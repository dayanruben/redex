/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.facebook.redex.test.instr.base;

class Base {
    public static String foo() {
        return "foo";
    }
}

public class ObfuscateTestPackages extends Base {
}
