/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "DexClass.h"
#include "InterDex.h"
#include "InterDexReshuffleImpl.h"
#include "Pass.h"

/* This pass impls Local Search Algotithm to minize cross-dex refs by
reshuffling classes among dex files. The algorithm is descripted as follows:
Inputs: V = classes
        D = dexes
        num_batches

determine an initial allocation of classes v in V into dexes d in D;

for batch_idx in 1, ..., num_batches:
    # compute move gains
    for v in V:
        for d in D:
            gain[v, d] <- compute_move_gain(v, d)
    S <- sorted move pairs (v, d) in descending order of gains;

    # move classes
    for (v,d) in S:
        # compute new size of dex d after moving v to d
        new_size <- recompute_gains(d, v)
        if gain[v, d] > 0:
            if new_size is valid:
                move v to d;
                update dex size;
        else:
            break

    if converged or stopping condition is met:
        break
 */
class InterDexReshufflePass : public Pass {
 public:
  explicit InterDexReshufflePass() : Pass("InterDexReshufflePass") {}

  redex_properties::PropertyInteractions get_property_interactions()
      const override {
    using namespace redex_properties::interactions;
    using namespace redex_properties::names;
    return {
        {DexLimitsObeyed, Preserves},
        {NoResolvablePureRefs, Preserves},
        {InitialRenameClass, Preserves},
    };
  }

  void run_pass(DexStoresVector&, ConfigFiles&, PassManager&) override;

  void bind_config() override {
    bind("reserved_extra_frefs",
         m_config.reserved_extra_frefs,
         m_config.reserved_extra_frefs,
         "How many extra frefs to be reserved for the dexes this pass "
         "processes.");
    bind("reserved_extra_trefs",
         m_config.reserved_extra_trefs,
         m_config.reserved_extra_trefs,
         "How many extra trefs to be reserved for the dexes this pass "
         "processes.");
    bind("reserved_extra_mrefs",
         m_config.reserved_extra_mrefs,
         m_config.reserved_extra_mrefs,
         "How many extra mrefs to be reserved for the dexes this pass "
         "processes.");
    bind("extra_linear_alloc_limit",
         m_config.extra_linear_alloc_limit,
         m_config.extra_linear_alloc_limit,
         "How many extra linear_alloc_limit to be reserved for the dexes "
         "this pass rocesses.");
    bind("max_batches",
         m_config.max_batches,
         m_config.max_batches,
         "How many batches to execute. More might yield better results, but "
         "might take longer.");
    bind("max_batch_size",
         m_config.max_batch_size,
         m_config.max_batch_size,
         "How many class to move per batch. More might yield better results, "
         "but might take longer.");
    bind("exclude_below20pct_coldstart_classes",
         false,
         m_config.exclude_below20pct_coldstart_classes,
         "Whether to exclude coldstart classes in between 1pctColdStart and "
         "20pctColdStart marker"
         "from the reshuffle.");
    bind("interaction_frequency_threshold",
         m_config.interaction_frequency_threshold,
         m_config.interaction_frequency_threshold,
         "Threshold of class frequency to be considered perf sensitive."
         "A class has to have at least one interaction's frequency to be "
         "above this threshold to be considered as perf sensitive");
  }

 private:
  ReshuffleConfig m_config;
};
