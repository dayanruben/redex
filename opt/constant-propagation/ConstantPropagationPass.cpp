/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "ConstantPropagationPass.h"

#include "ConfigFiles.h"
#include "ConstantPropagation.h"
#include "DexUtil.h"
#include "PassManager.h"
#include "ScopedMetrics.h"
#include "Trace.h"

using namespace constant_propagation;

void ConstantPropagationPass::run_pass(DexStoresVector& stores,
                                       ConfigFiles& conf,
                                       PassManager& mgr) {
  auto scope = build_class_scope(stores);
  XStoreRefs xstores(stores, conf.normal_primary_dex());

  ConstantPropagation impl(m_config);
  auto state = constant_propagation::State();
  auto stats = impl.run(scope, &xstores, state);

  ScopedMetrics sm(mgr);
  stats.log_metrics(sm, /* with_scope= */ false);

  TRACE(CONSTP, 1, "num_branch_propagated: %zu", stats.branches_removed);
  TRACE(CONSTP,
        1,
        "num_moves_replaced_by_const_loads: %zu",
        stats.materialized_consts);
  TRACE(CONSTP, 1, "num_throws: %zu", stats.throws);
}

static ConstantPropagationPass s_pass;
