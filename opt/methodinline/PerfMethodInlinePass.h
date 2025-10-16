/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "Pass.h"

class PerfMethodInlinePass : public Pass {
 public:
  PerfMethodInlinePass();

  redex_properties::PropertyInteractions get_property_interactions()
      const override {
    using namespace redex_properties::interactions;
    using namespace redex_properties::names;
    return {
        {DexLimitsObeyed, Preserves},
        {HasSourceBlocks, RequiresAndEstablishes},
        {NoResolvablePureRefs, Preserves},
        // This may be too conservative as the inliner can be configured not to
        // DCE in the shrinker.
        {SpuriousGetClassCallsInterned, RequiresAndPreserves},
        {InitialRenameClass, Preserves},
        {NoWriteBarrierInstructions, Destroys},
    };
  }

  ~PerfMethodInlinePass() override;

  void bind_config() override;

  void run_pass(DexStoresVector&, ConfigFiles&, PassManager&) override;

 private:
  struct Config;
  std::unique_ptr<Config> m_config{nullptr};
};
