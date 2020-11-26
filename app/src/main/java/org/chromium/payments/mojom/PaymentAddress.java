
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is autogenerated by:
//     mojo/public/tools/bindings/mojom_bindings_generator.py
// For:
//     components/payments/mojom/payment_request_data.mojom
//

package org.chromium.payments.mojom;

import org.chromium.mojo.bindings.DeserializationException;


public final class PaymentAddress extends org.chromium.mojo.bindings.Struct {

    private static final int STRUCT_SIZE = 104;
    private static final org.chromium.mojo.bindings.DataHeader[] VERSION_ARRAY = new org.chromium.mojo.bindings.DataHeader[] {new org.chromium.mojo.bindings.DataHeader(104, 0)};
    private static final org.chromium.mojo.bindings.DataHeader DEFAULT_STRUCT_INFO = VERSION_ARRAY[0];
    public String country;
    public String[] addressLine;
    public String region;
    public String city;
    public String dependentLocality;
    public String postalCode;
    public String sortingCode;
    public String languageCode;
    public String scriptCode;
    public String organization;
    public String recipient;
    public String phone;

    private PaymentAddress(int version) {
        super(STRUCT_SIZE, version);
    }

    public PaymentAddress() {
        this(0);
    }

    public static PaymentAddress deserialize(org.chromium.mojo.bindings.Message message) {
        return decode(new org.chromium.mojo.bindings.Decoder(message));
    }

    /**
     * Similar to the method above, but deserializes from a |ByteBuffer| instance.
     *
     * @throws org.chromium.mojo.bindings.DeserializationException on deserialization failure.
     */
    public static PaymentAddress deserialize(java.nio.ByteBuffer data) {
        if (data == null)
            return null;

        return deserialize(new org.chromium.mojo.bindings.Message(
                data, new java.util.ArrayList<org.chromium.mojo.system.Handle>()));
    }

    @SuppressWarnings("unchecked")
    public static PaymentAddress decode(org.chromium.mojo.bindings.Decoder decoder0) {
        if (decoder0 == null) {
            return null;
        }
        decoder0.increaseStackDepth();
        PaymentAddress result;
        try {
            org.chromium.mojo.bindings.DataHeader mainDataHeader = decoder0.readAndValidateDataHeader(VERSION_ARRAY);
            result = new PaymentAddress(mainDataHeader.elementsOrVersion);
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.country = decoder0.readString(8, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                org.chromium.mojo.bindings.Decoder decoder1 = decoder0.readPointer(16, false);
                {
                    org.chromium.mojo.bindings.DataHeader si1 = decoder1.readDataHeaderForPointerArray(org.chromium.mojo.bindings.BindingsHelper.UNSPECIFIED_ARRAY_LENGTH);
                    result.addressLine = new String[si1.elementsOrVersion];
                    for (int i1 = 0; i1 < si1.elementsOrVersion; ++i1) {
                        
                        result.addressLine[i1] = decoder1.readString(org.chromium.mojo.bindings.DataHeader.HEADER_SIZE + org.chromium.mojo.bindings.BindingsHelper.POINTER_SIZE * i1, false);
                    }
                }
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.region = decoder0.readString(24, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.city = decoder0.readString(32, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.dependentLocality = decoder0.readString(40, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.postalCode = decoder0.readString(48, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.sortingCode = decoder0.readString(56, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.languageCode = decoder0.readString(64, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.scriptCode = decoder0.readString(72, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.organization = decoder0.readString(80, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.recipient = decoder0.readString(88, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.phone = decoder0.readString(96, false);
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
        
        encoder0.encode(this.country, 8, false);
        
        if (this.addressLine == null) {
            encoder0.encodeNullPointer(16, false);
        } else {
            org.chromium.mojo.bindings.Encoder encoder1 = encoder0.encodePointerArray(this.addressLine.length, 16, org.chromium.mojo.bindings.BindingsHelper.UNSPECIFIED_ARRAY_LENGTH);
            for (int i0 = 0; i0 < this.addressLine.length; ++i0) {
                
                encoder1.encode(this.addressLine[i0], org.chromium.mojo.bindings.DataHeader.HEADER_SIZE + org.chromium.mojo.bindings.BindingsHelper.POINTER_SIZE * i0, false);
            }
        }
        
        encoder0.encode(this.region, 24, false);
        
        encoder0.encode(this.city, 32, false);
        
        encoder0.encode(this.dependentLocality, 40, false);
        
        encoder0.encode(this.postalCode, 48, false);
        
        encoder0.encode(this.sortingCode, 56, false);
        
        encoder0.encode(this.languageCode, 64, false);
        
        encoder0.encode(this.scriptCode, 72, false);
        
        encoder0.encode(this.organization, 80, false);
        
        encoder0.encode(this.recipient, 88, false);
        
        encoder0.encode(this.phone, 96, false);
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
        PaymentAddress other = (PaymentAddress) object;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.country, other.country))
            return false;
        if (!java.util.Arrays.deepEquals(this.addressLine, other.addressLine))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.region, other.region))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.city, other.city))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.dependentLocality, other.dependentLocality))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.postalCode, other.postalCode))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.sortingCode, other.sortingCode))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.languageCode, other.languageCode))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.scriptCode, other.scriptCode))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.organization, other.organization))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.recipient, other.recipient))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.phone, other.phone))
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
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.country);
        result = prime * result + java.util.Arrays.deepHashCode(this.addressLine);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.region);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.city);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.dependentLocality);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.postalCode);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.sortingCode);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.languageCode);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.scriptCode);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.organization);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.recipient);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.phone);
        return result;
    }
}