// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net;

import android.os.Build;
import android.support.annotation.RequiresApi;

import org.chromium.base.Log;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.chrome.R;
import org.conscrypt.OpenSSLProvider;

import java.io.DataInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import static org.chromium.build.BuildHooksAndroid.getResources;

import org.conscrypt.CloudSignatureSingleton;
/**
 * Specifies all the dependencies from the native OpenSSL engine on an Android KeyStore.
 */
@JNINamespace("net::android")
public class AndroidKeyStore {
    private static final String TAG = "AndroidKeyStore";

    /*
     * Adaugat pt teste
     * */

    private static String pemKey = "MIIEowIBAAKCAQEAzvE2cCa/Y2UwylljgVZIS8uc0c9GsFEp+vhd8ZZ9yo79n/SdI27MOgfKLAMZS3zTGZDvY8d/Yu4kLeEMrJKnHtPGXnBL/Rmyi9uMu/Z2mTsAM//KiCAp/QAIv0JETMIce5VtytXbc1MFpEa2R4iFsH8cZvTDZfYrXndXD/yaOGEVXCb67ffxnCcC9xsH+Y8U4BTyVLPw20VFdD4HiyidpPjiBG4CsJWew0y8GrAImWR8QKWv9AiIaoFSUOQsBwUkj8HDJI4MQo0HbdlhGS741cGhzbvcgup/dREm8I7WFF5lUWOhY91aJ8C6mnWVNCIi0unf1E7f9agFH7nBAlnEhwIDAQABAoIBAC4fpyGCEWBG+oPvPnViVMTIAhDlYP0FahTs7ItfHnRaQH85VxjBpjU87Tu4CRhBHw/wtNqJaYQUTe4H3fpMyYDedLUx1E36P0hay9hNC4wFkXsFhQ+oE5O3QTvXuj9deFm3KXxvA/WFSJmfxRrWe+2ltx/fZ/m+z1XDxZzjkUAFRESNjRB7TrPH7w435KRQEc1ouBf65LcEXDD5xBpiEKeBnk3QHVB1+CZb9GlESSBrjtcvu57E1S5KPUCJPD/PsQphME5OxkujS8pjtHDWDlq/KKzKmBo17k88Iadpc9po7eWt8r+LUTmd4GPfYRhq2k1zc03e8qPaDjYzCuRv1cECgYEA/10k3ioi2P3YAaMCYGECFuFv8U6aXsKMrYX3MW7HtxdctevU0fMRlVfLz2Jc3oOS9aHY+Frm+bkKQ2Hq2xdQlByfF5/lyq8BNaA/cy4iPyYoPMUWmnYnWT4BlrO1/4keXmuzl8dUiSeJUUcbqu6nDRTr76JxWVRfDHtVG5C9BGECgYEAz3UwLU8NGwSUCtelbLkVckUxx8EwQSVxikE1sdjmrLmzRk6kCWJ7R9vXqgNFS2gyCT6yB1l4Is1OaAnwB/4zQtyRH5VJsZOokmrsDvZhVjZzmf9sFy9gEQp8HtYA5cJAAQhtNDnGcPpX8HRJTRprs7/1jDRHjF1OwPDIqiZccecCgYEAoXxhqCy1RMuiIcbX5eLy001U4SB39pzJIaKqI5SOr3YSpuiv+OThpbOTq13kpMJH2RW0g7nYfutJVjtBrbMcvc0rvmDbjEUHWsYv2cK+3Xhf0a5BEQTO9VyE3Kxg12v6zHMHa2AeUW2zJLb3BC1PbrJgUXZEf90fDmGf/IKXRYECgYBBaKpq7qysIxJmJL20fNqFL8nVOFT1hU+6DntWepOoS9h5R1wy1UkXS/pAUU2sy8pS3eCVrqDRIDgjV1bFvmD9KLvc4F3ezjZtC6cnxIjF/N8P49d5q+c3GD4wHrsjtc4mRTjhKYImptfJKXDfDYB9qP1LWkRgvh6ReJlcBEJLawKBgAW4g1NhTLM3Pe915q2e7DikTKFLKvBHnCAalD7sshipbJlx9F8/XBLL0C9zwQRR7AhUoADB8JD7sHBoapowlIMlESG1yKwnG31TQ+wjY7E1JzeQEZUnQAdrs6cseFSf12X+1al2wyCgY6swEg7FuLTP58HwHp9tga5ko4MTqNP7";

    private static boolean isOurProvider(Provider p) {
        return p.getClass().getPackage().equals(OpenSSLProvider.class.getPackage());
    }

//    private static Provider getOpensslProvider(String algorithm) {
//        ArrayList<Provider> providers = new ArrayList<>(1);
//        for (Provider p : Security.getProviders()) {
//            if (!isOurProvider(p)) {
//                return p;
////                providers.add(p);
//            }
//        }
//        if (providers.isEmpty()) {
//            System.err.println("Could not find external provider for algorithm: " + algorithm);
//        }
////        return providers;
//        return  null;
//    }

    private static   PrivateKey generateRsaKeys ( ) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.genKeyPair().getPrivate();
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static PrivateKey getPrivateKeyFromStr(String keystr) throws Exception
    {
        // Remove the first and last lines
//        String pubKeyPEM = keystr.replace("-----BEGIN PUBLIC KEY-----\n", "");
//        pubKeyPEM = pubKeyPEM.replace("-----END PUBLIC KEY-----", "");

        // Base64 decode the data
        byte [] encoded = Base64.getDecoder().decode(keystr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pubkey = kf.generatePrivate(keySpec);

        return pubkey;
    }

    /**
     * Sign a given message with a given PrivateKey object.
     *
     * @param privateKey The PrivateKey handle.
     * @param algorithm The signature algorithm to use.
     * @param message The message to sign.
     * @return signature as a byte buffer.
     *
     * Note: NONEwithRSA is not implemented in Android < 4.2. See
     * getOpenSSLHandleForPrivateKey() below for a work-around.
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    @CalledByNative
    private static byte[] signWithPrivateKey(
            PrivateKey privateKey, String algorithm, byte[] message) {
        // Hint: Algorithm names come from:
        // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
        Signature signature = null;
        try {
            CloudSignatureSingleton.getInstance().mAuthorizationToken="token";
            CloudSignatureSingleton.getInstance().mTokenType="bearer";
            CloudSignatureSingleton.getInstance().mCredentialId="id123455";
//            signature = Signature.getInstance(algorithm);
            signature = Signature.getInstance(algorithm, "Conscrypt");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            Log.e(TAG, "Signature algorithm " + algorithm + " not supported: " + e);
            return null;
        }

        try {
            PrivateKey genPrivateKey = getPrivateKeyFromStr(pemKey);
//            signature.initSign(privateKey);
            signature.initSign(genPrivateKey);
            signature.update(message);

            byte [] signResult = signature.sign();
//            signResult[0] = signResult[1];
//            return signature.sign(); // aici returneaza semnatura, asadar aici pot sa modific. !!
            return signResult;
        } catch (Exception e) {
            Log.e(TAG,
                    "Exception while signing message with " + algorithm + " and "
                            + privateKey.getAlgorithm() + " private key ("
                            + privateKey.getClass().getName() + "): " + e);
            return null;
        }
    }

    private static Object getOpenSSLKeyForPrivateKey(PrivateKey privateKey) {
        // Sanity checks
        if (privateKey == null) {
            Log.e(TAG, "privateKey == null");
            return null;
        }
        if (!(privateKey instanceof RSAPrivateKey)) {
            Log.e(TAG, "does not implement RSAPrivateKey");
            return null;
        }
        // First, check that this is a proper instance of OpenSSLRSAPrivateKey
        // or one of its sub-classes.
        Class<?> superClass;
        try {
            superClass =
                    Class.forName("org.apache.harmony.xnet.provider.jsse.OpenSSLRSAPrivateKey");
        } catch (Exception e) {
            // This may happen if the target device has a completely different
            // implementation of the java.security APIs, compared to vanilla
            // Android. Highly unlikely, but still possible.
            Log.e(TAG, "Cannot find system OpenSSLRSAPrivateKey class: " + e);
            return null;
        }
        if (!superClass.isInstance(privateKey)) {
            // This may happen if the PrivateKey was not created by the "AndroidOpenSSL"
            // provider, which should be the default. That could happen if an OEM decided
            // to implement a different default provider. Also highly unlikely.
            Log.e(TAG, "Private key is not an OpenSSLRSAPrivateKey instance, its class name is:"
                    + privateKey.getClass().getCanonicalName());
            return null;
        }

        try {
            // Use reflection to invoke the 'getOpenSSLKey()' method on the
            // private key. This returns another Java object that wraps a native
            // EVP_PKEY and OpenSSLEngine. Note that the method is final in Android
            // 4.1, so calling the superclass implementation is ok.
            Method getKey = superClass.getDeclaredMethod("getOpenSSLKey");
            getKey.setAccessible(true);
            Object opensslKey = null;
            try {
                opensslKey = getKey.invoke(privateKey);
            } finally {
                getKey.setAccessible(false);
            }
            if (opensslKey == null) {
                // Bail when detecting OEM "enhancement".
                Log.e(TAG, "getOpenSSLKey() returned null");
                return null;
            }
            return opensslKey;
        } catch (Exception e) {
            Log.e(TAG, "Exception while trying to retrieve system EVP_PKEY handle: " + e);
            return null;
        }
    }

    /**
     * Return the system EVP_PKEY handle corresponding to a given PrivateKey
     * object.
     *
     * This shall only be used when the "NONEwithRSA" signature is not
     * available, as described in signWithPrivateKey(). I.e. never use this on
     * Android 4.2 or higher.
     *
     * This can only work in Android 4.0.4 and higher, for older versions
     * of the platform (e.g. 4.0.3), there is no system OpenSSL EVP_PKEY,
     * but the private key contents can be retrieved directly with
     * the getEncoded() method.
     *
     * This assumes that the target device uses a vanilla AOSP
     * implementation of its java.security classes, which is also
     * based on OpenSSL (fortunately, no OEM has apperently changed to
     * a different implementation, according to the Android team).
     *
     * Note that the object returned was created with the platform version of
     * OpenSSL, and _not_ the one that comes with Chromium. It may not be used
     * with the Chromium version of OpenSSL (BoringSSL). See AndroidEVP_PKEY in
     * net/android/legacy_openssl.h.
     *
     * To better understand what's going on below, please refer to the
     * following source files in the Android 4.0.4 and 4.1 source trees:
     * libcore/luni/src/main/java/org/apache/harmony/xnet/provider/jsse/OpenSSLRSAPrivateKey.java
     * libcore/luni/src/main/native/org_apache_harmony_xnet_provider_jsse_NativeCrypto.cpp
     *
     * @param privateKey The PrivateKey handle.
     * @return The EVP_PKEY handle, as a 32-bit integer (0 if not available)
     */
    @CalledByNative
    private static long getOpenSSLHandleForPrivateKey(PrivateKey privateKey) {
        Object opensslKey = getOpenSSLKeyForPrivateKey(privateKey);
        if (opensslKey == null) return 0;

        try {
            // Use reflection to invoke the 'getPkeyContext' method on the
            // result of the getOpenSSLKey(). This is an 32-bit integer
            // which is the address of an EVP_PKEY object. Note that this
            // method these days returns a 64-bit long, but since this code
            // path is used for older Android versions, it may still return
            // a 32-bit int here. To be on the safe side, we cast the return
            // value via Number rather than directly to Integer or Long.
            Method getPkeyContext;
            try {
                getPkeyContext = opensslKey.getClass().getDeclaredMethod("getPkeyContext");
            } catch (Exception e) {
                // Bail here too, something really not working as expected.
                Log.e(TAG, "No getPkeyContext() method on OpenSSLKey member:" + e);
                return 0;
            }
            getPkeyContext.setAccessible(true);
            long evp_pkey = 0;
            try {
                evp_pkey = ((Number) getPkeyContext.invoke(opensslKey)).longValue();
            } finally {
                getPkeyContext.setAccessible(false);
            }
            if (evp_pkey == 0) {
                // The PrivateKey is probably rotten for some reason.
                Log.e(TAG, "getPkeyContext() returned null");
            }
            return evp_pkey;

        } catch (Exception e) {
            Log.e(TAG, "Exception while trying to retrieve system EVP_PKEY handle: " + e);
            return 0;
        }
    }

    /**
     * Return the OpenSSLEngine object corresponding to a given PrivateKey
     * object.
     *
     * This shall only be used for Android 4.1 to work around a platform bug.
     * See https://crbug.com/381465.
     *
     * @param privateKey The PrivateKey handle.
     * @return The OpenSSLEngine object (or null if not available)
     */
    @CalledByNative
    private static Object getOpenSSLEngineForPrivateKey(PrivateKey privateKey) {
        // Find the system OpenSSLEngine class.
        Class<?> engineClass;
        try {
            engineClass = Class.forName("org.apache.harmony.xnet.provider.jsse.OpenSSLEngine");
        } catch (Exception e) {
            // This may happen if the target device has a completely different
            // implementation of the java.security APIs, compared to vanilla
            // Android. Highly unlikely, but still possible.
            Log.e(TAG, "Cannot find system OpenSSLEngine class: " + e);
            return null;
        }

        Object opensslKey = getOpenSSLKeyForPrivateKey(privateKey);
        if (opensslKey == null) return null;

        try {
            // Use reflection to invoke the 'getEngine' method on the
            // result of the getOpenSSLKey().
            Method getEngine;
            try {
                getEngine = opensslKey.getClass().getDeclaredMethod("getEngine");
            } catch (Exception e) {
                // Bail here too, something really not working as expected.
                Log.e(TAG, "No getEngine() method on OpenSSLKey member:" + e);
                return null;
            }
            getEngine.setAccessible(true);
            Object engine = null;
            try {
                engine = getEngine.invoke(opensslKey);
            } finally {
                getEngine.setAccessible(false);
            }
            if (engine == null) {
                // The PrivateKey is probably rotten for some reason.
                Log.e(TAG, "getEngine() returned null");
            }
            // Sanity-check the returned engine.
            if (!engineClass.isInstance(engine)) {
                Log.e(TAG, "Engine is not an OpenSSLEngine instance, its class name is:"
                        + engine.getClass().getCanonicalName());
                return null;
            }
            return engine;

        } catch (Exception e) {
            Log.e(TAG, "Exception while trying to retrieve OpenSSLEngine object: " + e);
            return null;
        }
    }
}
