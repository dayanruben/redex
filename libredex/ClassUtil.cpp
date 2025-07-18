/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "ClassUtil.h"
#include "DexAsm.h"
#include "IRCode.h"
#include "Show.h"
#include "TypeUtil.h"

namespace klass {

Serdes get_serdes(const DexClass* cls) {
  std::string name = cls->get_name()->str_copy();
  name.pop_back();
  std::string flatbuf_name = name;
  std::replace(flatbuf_name.begin(), flatbuf_name.end(), '$', '_');

  std::string desername = name + "$Deserializer;";
  DexType* deser = DexType::get_type(desername);

  std::string flatbuf_desername = flatbuf_name + "Deserializer;";
  DexType* flatbuf_deser = DexType::get_type(flatbuf_desername);

  std::string sername = name + "$Serializer;";
  DexType* ser = DexType::get_type(sername);

  std::string flatbuf_sername = flatbuf_name + "Serializer;";
  DexType* flatbuf_ser = DexType::get_type(flatbuf_sername);

  return Serdes(deser, flatbuf_deser, ser, flatbuf_ser);
}

DexMethod* get_or_create_clinit(DexClass* cls, bool need_cfg) {
  using namespace dex_asm;

  DexMethod* clinit = cls->get_clinit();

  if (clinit) {
    return clinit;
  }

  auto clinit_name = DexString::make_string("<clinit>");
  auto clinit_proto =
      DexProto::make_proto(type::_void(), DexTypeList::make_type_list({}));

  // clinit does not exist, create one
  clinit =
      DexMethod::make_method(cls->get_type(), clinit_name, clinit_proto)
          ->make_concrete(ACC_PUBLIC | ACC_STATIC | ACC_CONSTRUCTOR, false);

  clinit->set_deobfuscated_name(show_deobfuscated(clinit));

  auto ir_code = std::make_unique<IRCode>(clinit, 1);
  ir_code->push_back(dasm(OPCODE_RETURN_VOID));
  clinit->set_code(std::move(ir_code));
  if (need_cfg) {
    clinit->get_code()->build_cfg();
  }
  cls->add_method(clinit);
  return clinit;
}

bool has_hierarchy_in_scope(DexClass* cls) {
  DexType* super = nullptr;
  const DexClass* super_cls = cls;
  while (super_cls) {
    super = super_cls->get_super_class();
    super_cls = type_class_internal(super);
  }
  return super == type::java_lang_Object();
}

bool maybe_anonymous_class(const DexClass* cls) {
  static constexpr std::array<std::string_view, 2> patterns = {
      // https://r8.googlesource.com/r8/+/refs/tags/3.1.34/src/main/java/com/android/tools/r8/synthesis/SyntheticNaming.java#140
      "$$ExternalSyntheticLambda",
      // Desugared lambda classes from older versions of D8.
      "$$Lambda$",
  };
  const std::string_view name = cls->get_deobfuscated_name_or_empty();
  auto pos = name.rfind('$');
  if (pos == std::string::npos) {
    return false;
  }
  pos++;
  return (pos < name.size() && name[pos] >= '0' && name[pos] <= '9') ||
         std::any_of(patterns.begin(), patterns.end(),
                     [&name](const std::string_view& pattern) {
                       return name.find(pattern) != std::string::npos;
                     });
}

}; // namespace klass
