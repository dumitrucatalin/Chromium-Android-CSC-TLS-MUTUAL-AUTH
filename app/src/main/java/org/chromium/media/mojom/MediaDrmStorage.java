
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is autogenerated by:
//     mojo/public/tools/bindings/mojom_bindings_generator.py
// For:
//     media/mojo/interfaces/media_drm_storage.mojom
//

package org.chromium.media.mojom;

import org.chromium.mojo.bindings.DeserializationException;


public interface MediaDrmStorage extends org.chromium.mojo.bindings.Interface {



    public interface Proxy extends MediaDrmStorage, org.chromium.mojo.bindings.Interface.Proxy {
    }

    Manager<MediaDrmStorage, MediaDrmStorage.Proxy> MANAGER = MediaDrmStorage_Internal.MANAGER;


    void initialize(

InitializeResponse callback);

    interface InitializeResponse extends org.chromium.mojo.bindings.Callbacks.Callback1<org.chromium.mojo.common.mojom.UnguessableToken> { }



    void onProvisioned(

OnProvisionedResponse callback);

    interface OnProvisionedResponse extends org.chromium.mojo.bindings.Callbacks.Callback1<Boolean> { }



    void savePersistentSession(
String sessionId, SessionData sessionData, 
SavePersistentSessionResponse callback);

    interface SavePersistentSessionResponse extends org.chromium.mojo.bindings.Callbacks.Callback1<Boolean> { }



    void loadPersistentSession(
String sessionId, 
LoadPersistentSessionResponse callback);

    interface LoadPersistentSessionResponse extends org.chromium.mojo.bindings.Callbacks.Callback1<SessionData> { }



    void removePersistentSession(
String sessionId, 
RemovePersistentSessionResponse callback);

    interface RemovePersistentSessionResponse extends org.chromium.mojo.bindings.Callbacks.Callback1<Boolean> { }


}