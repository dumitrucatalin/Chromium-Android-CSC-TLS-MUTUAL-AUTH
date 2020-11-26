
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is autogenerated by:
//     mojo/public/tools/bindings/mojom_bindings_generator.py
// For:
//     services/network/public/interfaces/url_loader_factory.mojom
//

package org.chromium.network.mojom;

import org.chromium.mojo.bindings.DeserializationException;


class UrlLoaderFactory_Internal {

    public static final org.chromium.mojo.bindings.Interface.Manager<UrlLoaderFactory, UrlLoaderFactory.Proxy> MANAGER =
            new org.chromium.mojo.bindings.Interface.Manager<UrlLoaderFactory, UrlLoaderFactory.Proxy>() {
    
        @Override
        public String getName() {
            return "network::mojom::URLLoaderFactory";
        }
    
        @Override
        public int getVersion() {
          return 0;
        }
    
        @Override
        public Proxy buildProxy(org.chromium.mojo.system.Core core,
                                org.chromium.mojo.bindings.MessageReceiverWithResponder messageReceiver) {
            return new Proxy(core, messageReceiver);
        }
    
        @Override
        public Stub buildStub(org.chromium.mojo.system.Core core, UrlLoaderFactory impl) {
            return new Stub(core, impl);
        }
    
        @Override
        public UrlLoaderFactory[] buildArray(int size) {
          return new UrlLoaderFactory[size];
        }
    };


    private static final int CREATE_LOADER_AND_START_ORDINAL = 0;

    private static final int CLONE_ORDINAL = 1;


    static final class Proxy extends org.chromium.mojo.bindings.Interface.AbstractProxy implements UrlLoaderFactory.Proxy {

        Proxy(org.chromium.mojo.system.Core core,
              org.chromium.mojo.bindings.MessageReceiverWithResponder messageReceiver) {
            super(core, messageReceiver);
        }


        @Override
        public void createLoaderAndStart(
org.chromium.mojo.bindings.InterfaceRequest<UrlLoader> loader, int routingId, int requestId, int options, UrlRequest request, UrlLoaderClient client, MutableNetworkTrafficAnnotationTag trafficAnnotation) {

            UrlLoaderFactoryCreateLoaderAndStartParams _message = new UrlLoaderFactoryCreateLoaderAndStartParams();

            _message.loader = loader;

            _message.routingId = routingId;

            _message.requestId = requestId;

            _message.options = options;

            _message.request = request;

            _message.client = client;

            _message.trafficAnnotation = trafficAnnotation;


            getProxyHandler().getMessageReceiver().accept(
                    _message.serializeWithHeader(
                            getProxyHandler().getCore(),
                            new org.chromium.mojo.bindings.MessageHeader(CREATE_LOADER_AND_START_ORDINAL)));

        }


        @Override
        public void clone(
org.chromium.mojo.bindings.InterfaceRequest<UrlLoaderFactory> factory) {

            UrlLoaderFactoryCloneParams _message = new UrlLoaderFactoryCloneParams();

            _message.factory = factory;


            getProxyHandler().getMessageReceiver().accept(
                    _message.serializeWithHeader(
                            getProxyHandler().getCore(),
                            new org.chromium.mojo.bindings.MessageHeader(CLONE_ORDINAL)));

        }


    }

    static final class Stub extends org.chromium.mojo.bindings.Interface.Stub<UrlLoaderFactory> {

        Stub(org.chromium.mojo.system.Core core, UrlLoaderFactory impl) {
            super(core, impl);
        }

        @Override
        public boolean accept(org.chromium.mojo.bindings.Message message) {
            try {
                org.chromium.mojo.bindings.ServiceMessage messageWithHeader =
                        message.asServiceMessage();
                org.chromium.mojo.bindings.MessageHeader header = messageWithHeader.getHeader();
                if (!header.validateHeader(org.chromium.mojo.bindings.MessageHeader.NO_FLAG)) {
                    return false;
                }
                switch(header.getType()) {
            
                    case org.chromium.mojo.bindings.interfacecontrol.InterfaceControlMessagesConstants.RUN_OR_CLOSE_PIPE_MESSAGE_ID:
                        return org.chromium.mojo.bindings.InterfaceControlMessagesHelper.handleRunOrClosePipe(
                                UrlLoaderFactory_Internal.MANAGER, messageWithHeader);
            
            
            
            
            
                    case CREATE_LOADER_AND_START_ORDINAL: {
            
                        UrlLoaderFactoryCreateLoaderAndStartParams data =
                                UrlLoaderFactoryCreateLoaderAndStartParams.deserialize(messageWithHeader.getPayload());
            
                        getImpl().createLoaderAndStart(data.loader, data.routingId, data.requestId, data.options, data.request, data.client, data.trafficAnnotation);
                        return true;
                    }
            
            
            
            
            
                    case CLONE_ORDINAL: {
            
                        UrlLoaderFactoryCloneParams data =
                                UrlLoaderFactoryCloneParams.deserialize(messageWithHeader.getPayload());
            
                        getImpl().clone(data.factory);
                        return true;
                    }
            
            
                    default:
                        return false;
                }
            } catch (org.chromium.mojo.bindings.DeserializationException e) {
                System.err.println(e.toString());
                return false;
            }
        }

        @Override
        public boolean acceptWithResponder(org.chromium.mojo.bindings.Message message, org.chromium.mojo.bindings.MessageReceiver receiver) {
            try {
                org.chromium.mojo.bindings.ServiceMessage messageWithHeader =
                        message.asServiceMessage();
                org.chromium.mojo.bindings.MessageHeader header = messageWithHeader.getHeader();
                if (!header.validateHeader(org.chromium.mojo.bindings.MessageHeader.MESSAGE_EXPECTS_RESPONSE_FLAG)) {
                    return false;
                }
                switch(header.getType()) {
            
                    case org.chromium.mojo.bindings.interfacecontrol.InterfaceControlMessagesConstants.RUN_MESSAGE_ID:
                        return org.chromium.mojo.bindings.InterfaceControlMessagesHelper.handleRun(
                                getCore(), UrlLoaderFactory_Internal.MANAGER, messageWithHeader, receiver);
            
            
            
            
            
            
                    default:
                        return false;
                }
            } catch (org.chromium.mojo.bindings.DeserializationException e) {
                System.err.println(e.toString());
                return false;
            }
        }
    }


    
    static final class UrlLoaderFactoryCreateLoaderAndStartParams extends org.chromium.mojo.bindings.Struct {
    
        private static final int STRUCT_SIZE = 48;
        private static final org.chromium.mojo.bindings.DataHeader[] VERSION_ARRAY = new org.chromium.mojo.bindings.DataHeader[] {new org.chromium.mojo.bindings.DataHeader(48, 0)};
        private static final org.chromium.mojo.bindings.DataHeader DEFAULT_STRUCT_INFO = VERSION_ARRAY[0];
        public org.chromium.mojo.bindings.InterfaceRequest<UrlLoader> loader;
        public int routingId;
        public int requestId;
        public int options;
        public UrlRequest request;
        public UrlLoaderClient client;
        public MutableNetworkTrafficAnnotationTag trafficAnnotation;
    
        private UrlLoaderFactoryCreateLoaderAndStartParams(int version) {
            super(STRUCT_SIZE, version);
        }
    
        public UrlLoaderFactoryCreateLoaderAndStartParams() {
            this(0);
        }
    
        public static UrlLoaderFactoryCreateLoaderAndStartParams deserialize(org.chromium.mojo.bindings.Message message) {
            return decode(new org.chromium.mojo.bindings.Decoder(message));
        }
    
        /**
         * Similar to the method above, but deserializes from a |ByteBuffer| instance.
         *
         * @throws org.chromium.mojo.bindings.DeserializationException on deserialization failure.
         */
        public static UrlLoaderFactoryCreateLoaderAndStartParams deserialize(java.nio.ByteBuffer data) {
            if (data == null)
                return null;
    
            return deserialize(new org.chromium.mojo.bindings.Message(
                    data, new java.util.ArrayList<org.chromium.mojo.system.Handle>()));
        }
    
        @SuppressWarnings("unchecked")
        public static UrlLoaderFactoryCreateLoaderAndStartParams decode(org.chromium.mojo.bindings.Decoder decoder0) {
            if (decoder0 == null) {
                return null;
            }
            decoder0.increaseStackDepth();
            UrlLoaderFactoryCreateLoaderAndStartParams result;
            try {
                org.chromium.mojo.bindings.DataHeader mainDataHeader = decoder0.readAndValidateDataHeader(VERSION_ARRAY);
                result = new UrlLoaderFactoryCreateLoaderAndStartParams(mainDataHeader.elementsOrVersion);
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    result.loader = decoder0.readInterfaceRequest(8, false);
                }
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    result.routingId = decoder0.readInt(12);
                }
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    result.requestId = decoder0.readInt(16);
                }
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    result.options = decoder0.readInt(20);
                }
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    org.chromium.mojo.bindings.Decoder decoder1 = decoder0.readPointer(24, false);
                    result.request = UrlRequest.decode(decoder1);
                }
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    result.client = decoder0.readServiceInterface(32, false, UrlLoaderClient.MANAGER);
                }
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    org.chromium.mojo.bindings.Decoder decoder1 = decoder0.readPointer(40, false);
                    result.trafficAnnotation = MutableNetworkTrafficAnnotationTag.decode(decoder1);
                }
            } finally {
                decoder0.decreaseStackDepth();
            }
            return result;
        }
    
        @SuppressWarnings("unchecked")
        @Override
        protected final void encode(org.chromium.mojo.bindings.Encoder encoder) {
            org.chromium.mojo.bindings.Encoder encoder0 = encoder.getEncoderAtDataOffset(DEFAULT_STRUCT_INFO);
            
            encoder0.encode(this.loader, 8, false);
            
            encoder0.encode(this.routingId, 12);
            
            encoder0.encode(this.requestId, 16);
            
            encoder0.encode(this.options, 20);
            
            encoder0.encode(this.request, 24, false);
            
            encoder0.encode(this.client, 32, false, UrlLoaderClient.MANAGER);
            
            encoder0.encode(this.trafficAnnotation, 40, false);
        }
    
        /**
         * @see Object#equals(Object)
         */
        @Override
        public boolean equals(Object object) {
            if (object == this)
                return true;
            if (object == null)
                return false;
            if (getClass() != object.getClass())
                return false;
            UrlLoaderFactoryCreateLoaderAndStartParams other = (UrlLoaderFactoryCreateLoaderAndStartParams) object;
            if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.loader, other.loader))
                return false;
            if (this.routingId!= other.routingId)
                return false;
            if (this.requestId!= other.requestId)
                return false;
            if (this.options!= other.options)
                return false;
            if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.request, other.request))
                return false;
            if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.client, other.client))
                return false;
            if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.trafficAnnotation, other.trafficAnnotation))
                return false;
            return true;
        }
    
        /**
         * @see Object#hashCode()
         */
        @Override
        public int hashCode() {
            final int prime = 31;
            int result = prime + getClass().hashCode();
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.loader);
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.routingId);
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.requestId);
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.options);
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.request);
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.client);
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.trafficAnnotation);
            return result;
        }
    }



    
    static final class UrlLoaderFactoryCloneParams extends org.chromium.mojo.bindings.Struct {
    
        private static final int STRUCT_SIZE = 16;
        private static final org.chromium.mojo.bindings.DataHeader[] VERSION_ARRAY = new org.chromium.mojo.bindings.DataHeader[] {new org.chromium.mojo.bindings.DataHeader(16, 0)};
        private static final org.chromium.mojo.bindings.DataHeader DEFAULT_STRUCT_INFO = VERSION_ARRAY[0];
        public org.chromium.mojo.bindings.InterfaceRequest<UrlLoaderFactory> factory;
    
        private UrlLoaderFactoryCloneParams(int version) {
            super(STRUCT_SIZE, version);
        }
    
        public UrlLoaderFactoryCloneParams() {
            this(0);
        }
    
        public static UrlLoaderFactoryCloneParams deserialize(org.chromium.mojo.bindings.Message message) {
            return decode(new org.chromium.mojo.bindings.Decoder(message));
        }
    
        /**
         * Similar to the method above, but deserializes from a |ByteBuffer| instance.
         *
         * @throws org.chromium.mojo.bindings.DeserializationException on deserialization failure.
         */
        public static UrlLoaderFactoryCloneParams deserialize(java.nio.ByteBuffer data) {
            if (data == null)
                return null;
    
            return deserialize(new org.chromium.mojo.bindings.Message(
                    data, new java.util.ArrayList<org.chromium.mojo.system.Handle>()));
        }
    
        @SuppressWarnings("unchecked")
        public static UrlLoaderFactoryCloneParams decode(org.chromium.mojo.bindings.Decoder decoder0) {
            if (decoder0 == null) {
                return null;
            }
            decoder0.increaseStackDepth();
            UrlLoaderFactoryCloneParams result;
            try {
                org.chromium.mojo.bindings.DataHeader mainDataHeader = decoder0.readAndValidateDataHeader(VERSION_ARRAY);
                result = new UrlLoaderFactoryCloneParams(mainDataHeader.elementsOrVersion);
                if (mainDataHeader.elementsOrVersion >= 0) {
                    
                    result.factory = decoder0.readInterfaceRequest(8, false);
                }
            } finally {
                decoder0.decreaseStackDepth();
            }
            return result;
        }
    
        @SuppressWarnings("unchecked")
        @Override
        protected final void encode(org.chromium.mojo.bindings.Encoder encoder) {
            org.chromium.mojo.bindings.Encoder encoder0 = encoder.getEncoderAtDataOffset(DEFAULT_STRUCT_INFO);
            
            encoder0.encode(this.factory, 8, false);
        }
    
        /**
         * @see Object#equals(Object)
         */
        @Override
        public boolean equals(Object object) {
            if (object == this)
                return true;
            if (object == null)
                return false;
            if (getClass() != object.getClass())
                return false;
            UrlLoaderFactoryCloneParams other = (UrlLoaderFactoryCloneParams) object;
            if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.factory, other.factory))
                return false;
            return true;
        }
    
        /**
         * @see Object#hashCode()
         */
        @Override
        public int hashCode() {
            final int prime = 31;
            int result = prime + getClass().hashCode();
            result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.factory);
            return result;
        }
    }



}
