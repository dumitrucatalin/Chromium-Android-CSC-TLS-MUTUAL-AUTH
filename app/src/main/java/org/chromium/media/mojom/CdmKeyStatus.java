
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is autogenerated by:
//     mojo/public/tools/bindings/mojom_bindings_generator.py
// For:
//     media/mojo/interfaces/content_decryption_module.mojom
//

package org.chromium.media.mojom;

import org.chromium.mojo.bindings.DeserializationException;

public final class CdmKeyStatus {



    private static final boolean IS_EXTENSIBLE = false;

    public static boolean isKnownValue(int value) {
        return false;
    }

    public static void validate(int value) {
        if (IS_EXTENSIBLE || isKnownValue(value))
            return;

        throw new DeserializationException("Invalid enum value.");
    }

    private CdmKeyStatus() {}

}