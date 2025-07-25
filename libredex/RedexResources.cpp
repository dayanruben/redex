/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "RedexResources.h"

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/regex/pending/unicode_iterator.hpp>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ApkResources.h"
#include "BundleResources.h"
#include "CppUtil.h"
#include "Debug.h"
#include "DetectBundle.h"
#include "DexUtil.h"
#include "GlobalConfig.h"
#include "IOUtil.h"
#include "Macros.h"
#include "ReadMaybeMapped.h"
#include "StringUtil.h"
#include "Trace.h"
#include "WorkQueue.h"
#include "utils/Unicode.h"

// Workaround for inclusion order, when compiling on Windows (#defines NO_ERROR
// as 0).
#ifdef NO_ERROR
#undef NO_ERROR
#endif

namespace {

constexpr size_t MIN_CLASSNAME_LENGTH = 10;
constexpr size_t MAX_CLASSNAME_LENGTH = 500;

constexpr decltype(redex_parallel::default_num_threads()) kReadXMLThreads = 4u;
constexpr decltype(redex_parallel::default_num_threads()) kReadNativeThreads =
    2u;

using path_t = boost::filesystem::path;
using dir_iterator = boost::filesystem::directory_iterator;
using rdir_iterator = boost::filesystem::recursive_directory_iterator;
} // namespace

std::unique_ptr<AndroidResources> create_resource_reader(
    const std::string& directory) {
// TODO (T91001948): Integrate protobuf dependency in supported platforms for
// open source
#ifdef HAS_PROTOBUF
  if (has_bundle_config(directory)) {
    return std::make_unique<BundleResources>(directory);
  } else {
    return std::make_unique<ApkResources>(directory);
  }
#else
  return std::make_unique<ApkResources>(directory);
#endif // HAS_PROTOBUF
}

UnorderedSet<std::string> get_service_loader_classes_helper(
    const std::string& path_dir) {
  UnorderedSet<std::string> classes_set;

  if (boost::filesystem::exists(path_dir) &&
      boost::filesystem::is_directory(path_dir)) {
    for (auto it = dir_iterator(path_dir); it != dir_iterator(); ++it) {
      auto const& file = *it;
      const path_t& file_path = file.path();
      const auto& file_string = file_path.string();

      classes_set.insert(
          java_names::external_to_internal(file_path.filename().string()));

      std::fstream new_file;
      new_file.open(file_string, std::ios::in);
      if (new_file.is_open()) {
        std::string current_line;
        while (std::getline(new_file, current_line)) {
          classes_set.insert(java_names::external_to_internal(current_line));
        }
        new_file.close();
      }
    }
  }

  return classes_set;
}

namespace {
/*
 * Returns all strings that look like java class names from a native library.
 *
 * Return values will be formatted the way that the dex spec formats class
 * names:
 *
 *   "Ljava/lang/String;"
 *
 */
UnorderedSet<std::string> extract_classes_from_native_lib(const char* data,
                                                          size_t size) {
  UnorderedSet<std::string> classes;
  char buffer[MAX_CLASSNAME_LENGTH + 2]; // +2 for the trailing ";\0"
  const char* inptr = data;
  const char* end = inptr + size;

  while (inptr < end) {
    char* outptr = buffer;
    size_t length = 0;
    // All classnames start with a package, which starts with a lowercase
    // letter. Some of them are preceded by an 'L' and followed by a ';' in
    // native libraries while others are not.
    if ((*inptr >= 'a' && *inptr <= 'z') || *inptr == 'L') {

      if (*inptr != 'L') {
        *outptr++ = 'L';
        length++;
      }

      while (inptr < end &&
             ((*inptr >= 'a' && *inptr <= 'z') ||
              (*inptr >= 'A' && *inptr <= 'Z') ||
              (*inptr >= '0' && *inptr <= '9') || *inptr == '/' ||
              *inptr == '_' || *inptr == '$') &&
             length < MAX_CLASSNAME_LENGTH) {
        *outptr++ = *inptr++;
        length++;
      }
      if (length >= MIN_CLASSNAME_LENGTH) {
        *outptr++ = ';';
        *outptr = '\0';
        classes.insert(std::string(buffer));
      }
    }
    inptr++;
  }
  return classes;
}
} // namespace

void parse_authorities(const std::string& text,
                       UnorderedSet<std::string>* authority_classes) {
  size_t start = 0;
  size_t end = 0;
  while ((end = text.find(';', start)) != std::string::npos) {
    authority_classes->insert(
        java_names::external_to_internal(text.substr(start, end - start)));
    start = end + 1;
  }
  authority_classes->insert(
      java_names::external_to_internal(text.substr(start)));
}

// For external testing.
UnorderedSet<std::string> extract_classes_from_native_lib(
    const std::string& lib_contents) {
  return extract_classes_from_native_lib(lib_contents.data(),
                                         lib_contents.size());
}

UnorderedSet<std::string> get_files_by_suffix(const std::string& directory,
                                              const std::string& suffix) {
  UnorderedSet<std::string> files;
  path_t dir(directory);

  if (exists(dir) && is_directory(dir)) {
    for (auto it = dir_iterator(dir); it != dir_iterator(); ++it) {
      auto const& entry = *it;
      const path_t& entry_path = entry.path();

      if (is_regular_file(entry_path) &&
          boost::ends_with(entry_path.string(), suffix)) {
        files.emplace(entry_path.string());
      }

      if (is_directory(entry_path)) {
        UnorderedSet<std::string> sub_files =
            get_files_by_suffix(entry_path.string(), suffix);

        insert_unordered_iterable(files, sub_files);
      }
    }
  }
  return files;
}

UnorderedSet<std::string> get_xml_files(const std::string& directory) {
  return get_files_by_suffix(directory, ".xml");
}

bool is_raw_resource(const std::string& filename) {
  return filename.find("/res/raw/") != std::string::npos ||
         filename.find("/res/raw-") != std::string::npos;
}

std::string configs_to_string(
    const std::set<android::ResTable_config>& configs) {
  std::ostringstream s;
  bool empty = true;
  for (const auto& c : configs) {
    if (!empty) {
      s << ", ";
    }
    empty = false;
    auto desc = c.toString();
    s << (desc.length() > 0 ? desc.string() : "default");
  }
  return s.str();
}

namespace {
template <typename Fn>
void find_resource_xml_files(const std::string& dir,
                             const std::vector<std::string>& skip_dirs_prefixes,
                             Fn handler) {
  path_t res(dir);
  if (exists(res) && is_directory(res)) {
    for (auto it = dir_iterator(res); it != dir_iterator(); ++it) {
      auto const& entry = *it;
      const path_t& entry_path = entry.path();

      if (is_directory(entry_path)) {
        auto matches_prefix = [&skip_dirs_prefixes](const auto& p) {
          const auto& str = p.string();
          for (const auto& prefix : skip_dirs_prefixes) {
            if (str.find(prefix) == 0) {
              return true;
            }
          }
          return false;
        };
        if (matches_prefix(entry_path.filename())) {
          continue;
        }

        for (auto lit = dir_iterator(entry_path); lit != dir_iterator();
             ++lit) {
          const path_t& resource_path = lit->path();
          if (is_regular_file(resource_path) &&
              boost::ends_with(resource_path.string(), ".xml")) {
            handler(resource_path.string());
          }
        }
      } else {
        // In case input APK has resource file path changed and not in usual
        // format.
        // TODO(T126661220): this disabled performance improvement to read less
        // resource files, it would be better if we have mapping file to map
        // back resource file names.
        if (is_regular_file(entry_path) &&
            boost::ends_with(entry_path.string(), ".xml")) {
          handler(entry_path.string());
        }
      }
    }
  }
}
} // namespace

void AndroidResources::collect_layout_classes_and_attributes(
    const UnorderedSet<std::string>& attributes_to_read,
    UnorderedSet<std::string>* out_classes,
    std::unordered_multimap<std::string, std::string>* out_attributes) {
  auto res_table = load_res_table();
  auto collect_fn = [&](const std::vector<std::string>& skip_dirs_prefixes) {
    std::mutex out_mutex;
    resources::StringOrReferenceSet classes;
    std::unordered_multimap<std::string, resources::StringOrReference>
        attributes;
    workqueue_run<std::string>(
        [&](sparta::WorkerState<std::string>* worker_state,
            const std::string& input) {
          if (input.empty()) {
            // Dispatcher, find files and create tasks.
            auto directories = find_res_directories();
            for (const auto& dir : directories) {
              TRACE(RES, 9,
                    "Scanning %s for xml files for classes and attributes",
                    dir.c_str());
              find_resource_xml_files(dir, skip_dirs_prefixes,
                                      [&](const std::string& file) {
                                        worker_state->push_task(file);
                                      });
            }

            return;
          }

          resources::StringOrReferenceSet local_classes;
          std::unordered_multimap<std::string, resources::StringOrReference>
              local_attributes;
          collect_layout_classes_and_attributes_for_file(
              input, attributes_to_read, &local_classes, &local_attributes);
          if (!local_classes.empty() || !local_attributes.empty()) {
            std::unique_lock<std::mutex> lock(out_mutex);
            // C++17: use merge to avoid copies.
            insert_unordered_iterable(classes, local_classes);
            attributes.insert(local_attributes.begin(), local_attributes.end());
          }
        },
        std::vector<std::string>{""},
        std::min(redex_parallel::default_num_threads(), kReadXMLThreads),
        /*push_tasks_while_running=*/true);

    // Resolve references that were encountered while reading xml files
    for (const auto& val : UnorderedIterable(classes)) {
      if (val.is_reference()) {
        std::vector<std::string> all_values;
        res_table->resolve_string_values_for_resource_reference(val.ref,
                                                                &all_values);
        for (const auto& s : all_values) {
          out_classes->emplace(s);
        }
      } else {
        out_classes->emplace(val.str);
      }
    }
    for (auto it = attributes.begin(); it != attributes.end(); it++) {
      if (it->second.is_reference()) {
        std::vector<std::string> all_values;
        res_table->resolve_string_values_for_resource_reference(it->second.ref,
                                                                &all_values);
        for (const auto& s : all_values) {
          out_attributes->emplace(it->first, s);
        }
      } else {
        out_attributes->emplace(it->first, it->second.str);
      }
    }
  };

  collect_fn({
      // Animations do not have references (that we track).
      "anim",
      // Colors do not have references.
      "color",
      // Raw would not contain binary XML.
      "raw",
  });
}

void AndroidResources::collect_xml_attribute_string_values(
    UnorderedSet<std::string>* out) {
  std::mutex out_mutex;
  workqueue_run<std::string>(
      [&](sparta::WorkerState<std::string>* worker_state,
          const std::string& input) {
        if (input.empty()) {
          // Dispatcher, find files and create tasks.
          auto directories = find_res_directories();
          for (const auto& dir : directories) {
            TRACE(RES, 9, "Scanning %s for xml files for attribute values",
                  dir.c_str());
            find_resource_xml_files(dir, {}, [&](const std::string& file) {
              worker_state->push_task(file);
            });
          }

          return;
        }

        UnorderedSet<std::string> local_out_values;
        collect_xml_attribute_string_values_for_file(input, &local_out_values);
        if (!local_out_values.empty()) {
          std::unique_lock<std::mutex> lock(out_mutex);
          // C++17: use merge to avoid copies.
          insert_unordered_iterable(*out, local_out_values);
        }
      },
      std::vector<std::string>{""},
      std::min(redex_parallel::default_num_threads(), kReadXMLThreads),
      /*push_tasks_while_running=*/true);
}

void AndroidResources::rename_classes_in_layouts(
    const std::map<std::string, std::string>& rename_map) {
  workqueue_run<std::string>(
      [&](sparta::WorkerState<std::string>* worker_state,
          const std::string& input) {
        if (input.empty()) {
          // Dispatcher, find files and create tasks.
          auto directories = find_res_directories();
          for (const auto& dir : directories) {
            auto xml_files = get_xml_files(dir);
            for (const auto& path : UnorderedIterable(xml_files)) {
              if (!is_raw_resource(path)) {
                worker_state->push_task(path);
              }
            }
          }
          return;
        }
        size_t num_renamed = 0;
        TRACE(RES, 3, "Begin rename Views in layout %s", input.c_str());
        bool result = rename_classes_in_layout(input, rename_map, &num_renamed);
        TRACE(RES, 3, "%sRenamed %zu class names in file %s",
              (result ? "" : "FAILED: "), num_renamed, input.c_str());
      },
      std::vector<std::string>{""},
      std::min(redex_parallel::default_num_threads(), kReadXMLThreads),
      /*push_tasks_while_running=*/true);
}

namespace {

/**
 * Return a list of all the .so files in /lib
 */
template <typename Fn>
void find_native_library_files(const std::string& lib_root, Fn handler) {
  std::string library_extension(".so");

  path_t lib(lib_root);

  if (exists(lib) && is_directory(lib)) {
    for (auto it = rdir_iterator(lib); it != rdir_iterator(); ++it) {
      auto const& entry = *it;
      const path_t& entry_path = entry.path();
      if (is_regular_file(entry_path) &&
          boost::ends_with(entry_path.filename().string(), library_extension)) {
        TRACE(RES, 9, "Checking lib: %s", entry_path.string().c_str());
        handler(entry_path.string());
      }
    }
  }
}

} // namespace

/**
 * Return all potential java class names located in native libraries.
 */
UnorderedSet<std::string> AndroidResources::get_native_classes() {
  std::mutex out_mutex;
  UnorderedSet<std::string> all_classes;
  workqueue_run<std::string>(
      [&](sparta::WorkerState<std::string>* worker_state,
          const std::string& input) {
        if (input.empty()) {
          // Dispatcher, find files and create tasks.
          auto directories = find_lib_directories();
          for (const auto& dir : directories) {
            TRACE(RES, 9, "Scanning %s for so files for class names",
                  dir.c_str());
            find_native_library_files(dir, [&](const std::string& file) {
              worker_state->push_task(file);
            });
          }
          return;
        }

        redex::read_file_with_contents(
            input,
            [&](const char* data, size_t size) {
              UnorderedSet<std::string> classes_from_native =
                  extract_classes_from_native_lib(data, size);
              if (!classes_from_native.empty()) {
                std::unique_lock<std::mutex> lock(out_mutex);
                // C++17: use merge to avoid copies.
                insert_unordered_iterable(all_classes, classes_from_native);
              }
            },
            64 * 1024);
      },
      std::vector<std::string>{""},
      std::min(redex_parallel::default_num_threads(), kReadNativeThreads),
      /*push_tasks_while_running=*/true);
  return all_classes;
}

bool AndroidResources::can_obfuscate_xml_file(
    const UnorderedSet<std::string>& allowed_types,
    const std::string& dirname) {
  for (const auto& type : UnorderedIterable(allowed_types)) {
    auto path = RES_DIRECTORY + std::string("/") + type;
    if (dirname.find(path) != std::string::npos) {
      return true;
    }
  }
  return false;
}

void AndroidResources::finalize_bundle_config(const ResourceConfig& config) {
  // Do nothing in super implementation, sub class will override if relevant.
}

UnorderedSet<std::string> AndroidResources::get_all_keep_resources() {
  UnorderedSet<std::string> all_keep_resources;
  auto directories = find_res_directories();
  for (const auto& dir : directories) {
    auto xml_files = get_xml_files(dir);
    for (const auto& path : UnorderedIterable(xml_files)) {
      if (!is_raw_resource(path)) {
        continue;
      }

      auto resource_names = resources::parse_keep_xml_file(path);
      insert_unordered_iterable(all_keep_resources, resource_names);

      if (!resource_names.empty() && traceEnabled(RES, 1)) {
        auto iterable_resource_names = UnorderedIterable(resource_names);
        std::string resources_str = boost::algorithm::join(
            std::vector<std::string>(iterable_resource_names.begin(),
                                     iterable_resource_names.end()),
            ", ");
        TRACE(RES, 1, "Resources kept from file %s: %s", path.c_str(),
              resources_str.c_str());
      }
    }
  }
  return all_keep_resources;
}

void ResourceTableFile::finalize_resource_table(const ResourceConfig& config) {
  // Intentionally left empty, proto resource table will not contain a relevant
  // structure to clean up.
}

resources::StyleInfo ResourceTableFile::load_style_info() {
  resources::StyleInfo style_info;
  style_info.styles = get_style_map();
  TRACE(RES,
        3,
        "Building style graph; style count = %zu",
        style_info.styles.size());
  std::unordered_map<uint32_t, resources::StyleInfo::vertex_t> added_nodes;
  for (auto&& [id, _] : style_info.styles) {
    auto v =
        boost::add_vertex(resources::StyleInfo::Node{id}, style_info.graph);
    added_nodes.emplace(id, v);
  }
  // In the unusual situation where a style has many different versions in
  // different configurations, each with different parents, edges for each will
  // be emitted.
  for (auto&& [id, vec] : style_info.styles) {
    for (auto& style : vec) {
      if (style.parent != 0) {
        auto search = added_nodes.find(style.parent);
        if (search != added_nodes.end()) {
          boost::add_edge(search->second, added_nodes.at(id), style_info.graph);
        }
      }
    }
  }
  style_info.id_to_vertex = added_nodes;
  return style_info;
}

namespace resources {
bool valid_xml_element(const std::string& ident) {
  return java_names::is_identifier(ident) &&
         ident.find('.') != std::string::npos;
}

std::string convert_utf8_to_mutf8(const std::string& input) {
  std::ostringstream out;
  auto pack_to_3_byte_form = [&](char16_t c) {
    uint8_t one = 0xE0 | ((c >> 12) & 0xF);
    uint8_t two = 0x80 | ((c >> 6) & 0x3F);
    uint8_t three = 0x80 | (c & 0x3F);
    out << one << two << three;
  };

  for (boost::u8_to_u32_iterator<std::string::const_iterator> it(input.begin()),
       end(input.end());
       it != end;
       ++it) {
    auto code_point = (char32_t)*it;
    auto len = utf32_to_utf8_length(&code_point, 1);
    always_assert(len != -1);
    if (code_point == 0) {
      // Special null zero encoding for MUTF-8.
      out << '\xC0' << '\x80';
    } else if (code_point < 0x10000) {
      // Normal UTF-8 encoding.
      char dest[4] = {0};
      utf32_to_utf8(&code_point, 1, dest, sizeof(dest));
      for (size_t i = 0; i < (size_t)len; i++) {
        out << dest[i];
      }
    } else {
      // Convert to UTF-16 surrogate pair, then pack each as 3 byte encoding.
      code_point -= 0x10000;
      char16_t high = 0xD800 + ((code_point >> 10) & 0x3FF);
      char16_t low = 0xDC00 + (code_point & 0x3FF);
      pack_to_3_byte_form(high);
      pack_to_3_byte_form(low);
    }
  }
  return out.str();
}

void resources_inlining_find_refs(
    const UnorderedMap<uint32_t, uint32_t>& past_refs,
    UnorderedMap<uint32_t, resources::InlinableValue>* inlinable_resources) {
  for (auto& ref : UnorderedIterable(past_refs)) {
    uint32_t id = ref.first;
    uint32_t ref_id = ref.second;
    uint32_t current_ref_id = ref_id;
    UnorderedSet<uint32_t> visited_refs; // To detect cycles
    while (true) {
      if (!visited_refs.insert(current_ref_id).second) {
        break; // Cycle detected, break the loop
      }
      auto it = inlinable_resources->find(current_ref_id);
      if (it != inlinable_resources->end()) {
        inlinable_resources->insert({id, it->second});
        break;
      }
      auto ref_it = past_refs.find(current_ref_id);
      if (ref_it == past_refs.end()) {
        break;
      }
      current_ref_id = ref_it->second;
    }
  }
}

// TODO: Support pattern matching (T224930363)
UnorderedSet<std::string> parse_keep_xml_file(
    const std::string& xml_file_path) {
  UnorderedSet<std::string> resource_names;
  boost::property_tree::ptree tree;
  std::ifstream xml_file(xml_file_path);

  try {
    boost::property_tree::read_xml(
        xml_file, tree, boost::property_tree::xml_parser::trim_whitespace);
  } catch (const std::exception& e) {
    std::cerr << "Error parsing XML file at " << xml_file_path << ": "
              << e.what() << std::endl;
    return resource_names;
  } catch (...) {
    std::cerr << "Unknown error occurred while parsing XML file at "
              << xml_file_path << std::endl;
    return resource_names;
  }

  boost::optional<std::string> keep_value =
      tree.get_optional<std::string>("resources.<xmlattr>.tools:keep");

  if (!keep_value.has_value()) {
    return resource_names;
  }

  std::string keep_str = keep_value.value();
  for (const auto& token : split_string(keep_str, ",")) {
    std::string_view trimmed_token = trim_whitespaces(token);
    size_t pos = trimmed_token.find('/');
    if (pos != std::string::npos) {
      trimmed_token = trimmed_token.substr(pos + 1);
    }
    resource_names.insert(std::string(trimmed_token));
  }

  return resource_names;
}

std::string StyleInfo::print_as_dot(bool exclude_nodes_with_no_edges) {
  auto stringify = [](uint32_t id) {
    std::ostringstream oss;
    oss << "0x" << std::hex << id;
    return oss.str();
  };
  return print_as_dot(stringify, {}, exclude_nodes_with_no_edges);
}

std::string StyleInfo::print_as_dot(
    const std::function<std::string(uint32_t)>& stringify,
    const UnorderedMap<uint32_t, UnorderedMap<std::string, std::string>>&
        node_options,
    bool exclude_nodes_with_no_edges) {
  std::ostringstream oss;
  // Make the output dot text stable, use sorted intermediate collections.
  std::set<uint32_t> ordered_nodes;
  std::map<uint32_t, std::set<uint32_t>> ordered_parents;
  // Iterate through all nodes and their edges, optionally dropping some
  // uninteresting stuff.
  const auto& iters = boost::vertices(graph);
  const auto& begin = iters.first;
  const auto& end = iters.second;
  for (auto v_it = begin; v_it != end; ++v_it) {
    auto& node = graph[*v_it];
    auto adj_vertices = boost::adjacent_vertices(*v_it, graph);
    bool has_outbound_edges{false};
    for (auto e_it = adj_vertices.first; e_it != adj_vertices.second; ++e_it) {
      has_outbound_edges = true;
      auto parent = graph[*e_it];
      ordered_nodes.emplace(parent.id);
      ordered_parents[node.id].emplace(parent.id);
    }
    if (!exclude_nodes_with_no_edges || has_outbound_edges) {
      ordered_nodes.emplace(node.id);
    }
  }
  // NOTE: this should get converted over to use boost graph printing
  // functionality. Only reason for leaving as-is, for now, is to keep the
  // existing API for letting users customize the display of nodes.
  oss << "digraph {" << std::endl;
  for (auto id : ordered_nodes) {
    oss << "  " << "node" << id << " [";
    bool emitted_label{false};
    bool first{true};
    auto search = node_options.find(id);
    if (search != node_options.end()) {
      auto& dot_options = search->second;
      for (auto& k : unordered_to_ordered_keys(dot_options)) {
        if (k == "label") {
          emitted_label = true;
        }
        if (!first) {
          oss << " ";
        }
        oss << k << "=\"" << dot_options.at(k) << "\"";
        first = false;
      }
    }
    if (!emitted_label) {
      if (!first) {
        oss << " ";
      }
      auto str = stringify(id);
      oss << "label=\"" << str << "\"";
    }
    oss << "];" << std::endl;
  }
  oss << "  subgraph parents_edges {" << std::endl;
  for (auto&& [id, set] : ordered_parents) {
    for (auto parent : set) {
      oss << "    node" << id << " -> node" << parent << ";" << std::endl;
    }
  }
  oss << "  }" << std::endl;
  oss << "}" << std::endl;
  return oss.str();
}

UnorderedSet<StyleInfo::vertex_t> StyleInfo::get_roots() const {
  auto vertices = boost::vertices(graph);
  UnorderedSet<vertex_t> vertices_with_incoming;
  UnorderedSet<vertex_t> root_vertices;

  for (auto vertex_iter = vertices.first; vertex_iter != vertices.second;
       ++vertex_iter) {
    auto out_edges = boost::out_edges(*vertex_iter, graph);
    for (auto edge_iter = out_edges.first; edge_iter != out_edges.second;
         ++edge_iter) {
      vertices_with_incoming.insert(boost::target(*edge_iter, graph));
    }
  }

  // Vertices that don't have incoming edges are roots
  for (auto vertex_iter = vertices.first; vertex_iter != vertices.second;
       ++vertex_iter) {
    if (vertices_with_incoming.find(*vertex_iter) ==
        vertices_with_incoming.end()) {
      root_vertices.insert(*vertex_iter);
    }
  }

  return root_vertices;
}

std::vector<uint32_t> StyleInfo::get_children(uint32_t resource_id) const {
  auto vertex = id_to_vertex.at(resource_id);
  auto children = boost::adjacent_vertices(vertex, graph);
  std::vector<uint32_t> children_ids;
  for (auto child = children.first; child != children.second; ++child) {
    children_ids.push_back(graph[*child].id);
  }
  return children_ids;
}

std::optional<uint32_t> StyleInfo::get_unambiguous_parent(
    uint32_t resource_id) const {
  const auto& resource_styles_it = styles.find(resource_id);
  if (resource_styles_it == styles.end()) {
    return std::nullopt;
  }

  const auto& resource_styles = resource_styles_it->second;
  if (resource_styles.size() != 1) {
    return std::nullopt;
  }

  const auto& resource_style = resource_styles[0];
  return resource_style.parent;
}

}; // namespace resources
