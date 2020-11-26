
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


public final class PaymentCurrencyAmount extends org.chromium.mojo.bindings.Struct {

    private static final int STRUCT_SIZE = 32;
    private static final org.chromium.mojo.bindings.DataHeader[] VERSION_ARRAY = new org.chromium.mojo.bindings.DataHeader[] {new org.chromium.mojo.bindings.DataHeader(32, 0)};
    private static final org.chromium.mojo.bindings.DataHeader DEFAULT_STRUCT_INFO = VERSION_ARRAY[0];
    public String currency;
    public String value;
    public String currencySystem;

    private PaymentCurrencyAmount(int version) {
        super(STRUCT_SIZE, version);
        this.currencySystem = (String) "urn:iso:std:iso:4217";
    }

    public PaymentCurrencyAmount() {
        this(0);
    }

    public static PaymentCurrencyAmount deserialize(org.chromium.mojo.bindings.Message message) {
        return decode(new org.chromium.mojo.bindings.Decoder(message));
    }

    /**
     * Similar to the method above, but deserializes from a |ByteBuffer| instance.
     *
     * @throws org.chromium.mojo.bindings.DeserializationException on deserialization failure.
     */
    public static PaymentCurrencyAmount deserialize(java.nio.ByteBuffer data) {
        if (data == null)
            return null;

        return deserialize(new org.chromium.mojo.bindings.Message(
                data, new java.util.ArrayList<org.chromium.mojo.system.Handle>()));
    }

    @SuppressWarnings("unchecked")
    public static PaymentCurrencyAmount decode(org.chromium.mojo.bindings.Decoder decoder0) {
        if (decoder0 == null) {
            return null;
        }
        decoder0.increaseStackDepth();
        PaymentCurrencyAmount result;
        try {
            org.chromium.mojo.bindings.DataHeader mainDataHeader = decoder0.readAndValidateDataHeader(VERSION_ARRAY);
            result = new PaymentCurrencyAmount(mainDataHeader.elementsOrVersion);
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.currency = decoder0.readString(8, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.value = decoder0.readString(16, false);
            }
            if (mainDataHeader.elementsOrVersion >= 0) {
                
                result.currencySystem = decoder0.readString(24, false);
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
        
        encoder0.encode(this.currency, 8, false);
        
        encoder0.encode(this.value, 16, false);
        
        encoder0.encode(this.currencySystem, 24, false);
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
        PaymentCurrencyAmount other = (PaymentCurrencyAmount) object;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.currency, other.currency))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.value, other.value))
            return false;
        if (!org.chromium.mojo.bindings.BindingsHelper.equals(this.currencySystem, other.currencySystem))
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
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.currency);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.value);
        result = prime * result + org.chromium.mojo.bindings.BindingsHelper.hashCode(this.currencySystem);
        return result;
    }
}