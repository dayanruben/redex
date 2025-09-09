/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "MaterializeResourceConstants.h"

#include "CFGMutation.h"
#include "ConfigFiles.h"
#include "FinalInlineV2.h"
#include "InitClassesWithSideEffects.h"
#include "PassManager.h"
#include "RClass.h"
#include "RedexResources.h"
#include "Resolver.h"
#include "ScopedCFG.h"
#include "Show.h"
#include "Walkers.h"

namespace {
size_t process_method(const UnorderedSet<DexType*>& r_classes,
                      DexMethod* method) {
  auto* code = method->get_code();
  if (code == nullptr) {
    return 0;
  }
  cfg::ScopedCFG cfg(code);
  cfg::CFGMutation mutation(*cfg);
  size_t changes{0};
  auto ii = InstructionIterable(*cfg);
  for (auto it = ii.begin(); it != ii.end(); ++it) {
    auto* insn = it->insn;
    if (opcode::is_an_sget(insn->opcode())) {
      DexField* field = resolve_field(insn->get_field(), FieldSearch::Static);
      if (field == nullptr) {
        continue;
      }
      if (r_classes.count(field->get_class()) > 0 &&
          type::is_primitive(field->get_type()) && field->is_concrete()) {
        auto* encoded_value = field->get_static_value();
        always_assert(encoded_value != nullptr);
        auto literal = encoded_value->value();
        if (literal >= PACKAGE_RESID_START) {
          auto move_result_it = cfg->move_result_of(it);
          always_assert(!move_result_it.is_end());
          auto* r_insn = new IRInstruction(IOPCODE_R_CONST);
          always_assert_log(literal <= std::numeric_limits<uint32_t>::max(),
                            "Resource id %llu must fit in uint32_t",
                            (long long unsigned)literal);
          r_insn->set_literal(static_cast<int64_t>(literal));
          r_insn->set_dest(move_result_it->insn->dest());
          mutation.replace(it, {r_insn});
          changes++;
        }
      }
    }
  }
  mutation.flush();
  if (changes > 0) {
    TRACE(OPTRES, 9, "After R_CONST insertion in %s %s", SHOW(method),
          SHOW(*cfg));
  }
  return changes;
}
} // namespace

void MaterializeResourceConstantsPass::run_pass(DexStoresVector& stores,
                                                ConfigFiles& conf,
                                                PassManager& mgr) {
  Scope scope = build_class_scope(stores);
  init_classes::InitClassesWithSideEffects init_classes_with_side_effects(
      scope, conf.create_init_class_insns());
  Scope apply_scope;
  UnorderedSet<DexType*> r_classes;
  resources::RClassReader r_class_reader(conf.get_global_config());
  for (auto* cls : scope) {
    if (r_class_reader.is_r_class(cls)) {
      apply_scope.emplace_back(cls);
      r_classes.emplace(cls->get_type());
    }
  }
  size_t clinit_cycles = 0;
  size_t deleted_clinits = 0;
  auto cp_state = constant_propagation::State();
  final_inline::analyze_and_simplify_clinits(
      apply_scope, init_classes_with_side_effects,
      /* xstores= */ nullptr,
      /* blocklist_types= */ {}, /* allowed_opaque_callee_names= */ {},
      cp_state, &clinit_cycles, &deleted_clinits);
  always_assert_log(clinit_cycles == 0,
                    "Should not have clinit cycles in R classes!");
  size_t instructions_created = walk::parallel::methods<size_t>(
      scope, [&](DexMethod* m) { return process_method(r_classes, m); });
  TRACE(OPTRES, 1, "Inserted %zu R_CONST instructions", instructions_created);
  mgr.incr_metric("instructions_created",
                  static_cast<int64_t>(instructions_created));
  TRACE(OPTRES, 1, "final_inline deleted %zu methods", deleted_clinits);
  mgr.incr_metric("deleted_clinits", static_cast<int64_t>(deleted_clinits));
}

static MaterializeResourceConstantsPass s_pass;
