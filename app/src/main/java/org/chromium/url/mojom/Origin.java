
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is autogenerated by:
//     mojo/public/tools/bindings/mojom_bindings_generator.py
// For:
//     url/mojo/origin.mojom
//

package org.chromium.url.mojom;

import org.chromium.mojo.bindings.DeserializationException;


public final class Origin extends org.chromium.mojo.bindings.Struct {

    private static final int STRUCT_SIZE = 40;
    private static final org.chromium.mojo.bindings.DataHeader[] VERSION_ARRAY = new org.chromium.mojo.bindings.DataHeader[] {new org.chromium.mojo.bindings.DataHeader(40, 0)};
    private static final org.chromium.mojo.bindings.DataHeader DEFAULT_STRUCT_INFO = VERSION_ARRAY[0];
    public String scheme;
    public String host;
    public short port;
    public String suborigin;
    public boolean unique;

    private Origin(int version) {
        super(STRUCT_SIZE, version);
    }

    public Origin() {
        this(0);
    }

    public static Origin deserialize(org.chromium.mojo.bindings.Message message) {
        return decode(new org.chromium.mojo.bindings.Decoder(message));
    }

    /**
     * Similar to the method above, but deserializes from a |ByteBuffer| instance.
     *
     * @throws org.chromium.mojo.bindings.DeserializationException on deserialization failure.
     */
    public static Origin deserialize(java.nio.ByteBuffer data) {
        if (data == null)
            return null;

        return deserialize(new org.chromium.mojo.bindings.Message(
                data, new java.util.ArrayList<org.chromium.mojo.system.Handle>()));
    }

    @SuppressWarnings("unchecked")
    public static Origin decode(org.chromium.mojo.bindings.Decoder decoder0) {
        if (decoder0 == null) {
            return null;
        }
        decoder0.increaseStackDepth();
        Origin result;
        try {
            org.chromium.mojo.bindings.DataHeader mainDataHeader = decoder0.readAndValidateDataHeader(VERSION_ARRAY);
            result = new Origin(mainDataHeader.elementsOrVersion);
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.scheme = decoder0.readString(8, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.host = decoder0.readString(16, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.port = decoder0.readShort(24);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.unique = decoder0.readBoolean(26, 0);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.suborigin = decoder0.readString(32, false);
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
        
        encoder0.encode(this.scheme, 8, false);
        
        encoder0.encode(this.host, 16, false);
        
        encoder0.encode(this.port, 24);
        
        encoder0.encode(this.unique, 26, 0);
        
        encoder0.encode(this.suborigin, 32, false);
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
        Origin other = (Origin) object;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.scheme, other.scheme))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.host, other.host))
            return false;
        if (this.port!= other.port)
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.suborigin, other.suborigin))
            return false;
        if (this.unique!= other.unique)
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
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.scheme);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.host);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.port);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.suborigin);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.unique);
        return result;
    }
}