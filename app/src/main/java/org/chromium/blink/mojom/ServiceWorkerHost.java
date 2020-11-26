
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is autogenerated by:
//     mojo/public/tools/bindings/mojom_bindings_generator.py
// For:
//     third_party/WebKit/common/service_worker/service_worker.mojom
//

package org.chromium.blink.mojom;

import org.chromium.mojo.bindings.DeserializationException;


public interface ServiceWorkerHost extends org.chromium.mojo.bindings.Interface {



    public interface Proxy extends ServiceWorkerHost, org.chromium.mojo.bindings.Interface.Proxy {
    }

    Manager<ServiceWorkerHost, ServiceWorkerHost.Proxy> MANAGER = ServiceWorkerHost_Internal.MANAGER;


    void setCachedMetadata(
org.chromium.url.mojom.Url url, byte[] data);



    void clearCachedMetadata(
org.chromium.url.mojom.Url url);



    void getClients(
ServiceWorkerClientQueryOptions options, 
GetClientsResponse callback);

    interface GetClientsResponse extends org.chromium.mojo.bindings.Callbacks.Callback1<ServiceWorkerClientInfo[]> { }



    void claimClients(

ClaimClientsResponse callback);

    interface ClaimClientsResponse extends org.chromium.mojo.bindings.Callbacks.Callback2<Integer, String> { }


}
