// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.view.inputmethod.InputConnection;
import android.widget.EditText;
import android.widget.LinearLayout;

import org.chromium.base.ThreadUtils;
import org.chromium.base.VisibleForTesting;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.chrome.R;
import org.chromium.net.oath.OauthController;
import org.chromium.ui.base.WindowAndroid;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Enumeration;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;

import javax.security.auth.x500.X500Principal;

import org.conscrypt.csc.CloudSignatureSingleton;

/**
 * Handles selection of client certificate on the Java side. This class is responsible for selection
 * of the client certificate to be used for authentication and retrieval of the private key and full
 * certificate chain.
 * <p>
 * The entry point is selectClientCertificate() and it will be called on the UI thread. Then the
 * class will construct and run an appropriate CertAsyncTask, that will run in background, and
 * finally pass the results back to the UI thread, which will return to the native code.
 */
@JNINamespace("chrome::android")
public class SSLClientCertificateRequest {
    static final String TAG = "SSLClientCrtReq";
    private static Activity mActivity;
    private static Object mLock = new Object();


    private static String catalinCrt = "-----BEGIN CERTIFICATE-----\n" +
            "MIIF4jCCBMqgAwIBAgIMZ8rzcN9/6n5Qw3C5MA0GCSqGSIb3DQEBCwUAMHQxCzAJ\n" +
            "BgNVBAYTAlJPMRcwFQYDVQQKEw5UcmFucyBTcGVkIFNSTDEfMB0GA1UECxMWRk9S\n" +
            "IFRFU1QgUFVSUE9TRVMgT05MWTErMCkGA1UEAxMiVHJhbnMgU3BlZCBNb2JpbGUg\n" +
            "ZUlEQVMgUUNBIC0gVEVTVDAeFw0yMDExMTMxMjUzNTJaFw0yMzExMTQxMjUzNTJa\n" +
            "MIGWMQswCQYDVQQGEwJSTzEQMA4GA1UEBBMHRFVNSVRSVTEWMBQGA1UEKhMNSU9O\n" +
            "VVQtQ0FUQUxJTjE9MDsGA1UEBRM0MjAwNDEyMjM0REkwMjAxOEU3RDA2MDFEQTJF\n" +
            "OTRBRDBBM0VDMThDOTE1REM3Q0MzQzFFRDEeMBwGA1UEAxMVSU9OVVQtQ0FUQUxJ\n" +
            "TiBEVU1JVFJVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzr/zQjjy\n" +
            "S7ljqtOhfIRrXEjIDkDnICJx6Gk7cJwJX4Yj5CtCbjM6/HdTP9Fg0s02/q1spFOh\n" +
            "I1fmVzwBpZ99B6iDUu6mEEQzqJBEmb5/UTFuVcXmcu+7/qZ92m7l07L2HbcVeou9\n" +
            "RlCWsPuoPXdfzOn3kwePjjXXr7n8cpUSuNUQpVPDSouRpEjlnEH8uR3tFws5ikIt\n" +
            "1x2tRFslbxmEHSqM2ioA96qn+y9TBsnWf3Moy3xIRVlOmP+LK3801LslBWTPo32q\n" +
            "+Jc+sfSS1dLm7jSm3HoY/8+vveax8kBZMQq4hdpmhnueWugwhYZY6Cf38V808HIL\n" +
            "vYSPRfRbutaB6wIDAQABo4ICTzCCAkswgYQGCCsGAQUFBwEBBHgwdjBIBggrBgEF\n" +
            "BQcwAoY8aHR0cDovL3d3dy50cmFuc3NwZWQucm8vY2FjZXJ0cy90c19tb2JpbGVf\n" +
            "ZWlkYXNfcWNhX3Rlc3QucDdjMCoGCCsGAQUFBzABhh5odHRwOi8vb2NzcC10ZXN0\n" +
            "LnRyYW5zc3BlZC5yby8wHQYDVR0OBBYEFNiLbxI2WjtiBxJUE+ggZwrC0gTbMAwG\n" +
            "A1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUCvGAR+TEUYHUKozGlW3pi3O1BMwwewYI\n" +
            "KwYBBQUHAQMEbzBtMAgGBgQAjkYBATALBgYEAI5GAQMCAQswCAYGBACORgEEMBMG\n" +
            "BgQAjkYBBjAJBgcEAI5GAQYBMDUGBgQAjkYBBTArMCkWI2h0dHBzOi8vd3d3LnRy\n" +
            "YW5zc3BlZC5yby9yZXBvc2l0b3J5EwJlbjBVBgNVHSAETjBMMD8GCysGAQQBgrgd\n" +
            "BAEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly93d3cudHJhbnNzcGVkLnJvL3JlcG9z\n" +
            "aXRvcnkwCQYHBACL7EABAjBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vd3d3LnRy\n" +
            "YW5zc3BlZC5yby9jcmwvdHNfbW9iaWxlX2VpZGFzX3FjYV90ZXN0LmNybDAOBgNV\n" +
            "HQ8BAf8EBAMCBsAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMCYGA1Ud\n" +
            "EQQfMB2BG2R1bWl0cnUuY2F0YWxpbjk2QHlhaG9vLmNvbTANBgkqhkiG9w0BAQsF\n" +
            "AAOCAQEAYcja0dEG1deq6jv3wmidhcCWraIq6lB4e5MFcX1oRoFVKqAB38p3zcH/\n" +
            "Y8Qm3TNfGgS6ei36CKh8mLEMZ7RR08FUOV4QHOKIhud5N8Yu8g746pOabfHWqydN\n" +
            "ZiaY8Fweq8Dx77pKdl+QZSPxnZIY0KDEQM9yeftaAx3F48FbWUWikmE9lnw0kX88\n" +
            "t18MkTnZ3Dlgh8ox9sRdtp3vMINgLDRSNzFKCBfgTi+CNYskym83+QvEH0oH4e+a\n" +
            "Yr9LhVXwu/t4GdP8X5UaG9u7Ne5VGwrPoTtyDVEiRKIrcN0cIqD9+1+lPfCQWZ3a\n" +
            "nfYIj6bXB3AP0S83iBRMXWN59O2W/w==\n" +
            "-----END CERTIFICATE-----\n";

    private static String transspedMobileCaCrt = "-----BEGIN CERTIFICATE-----\n" +
            "MIIE5jCCA86gAwIBAgIKS7HdUQAAAAAACzANBgkqhkiG9w0BAQsFADBuMQswCQYD\n" +
            "VQQGEwJSTzEXMBUGA1UEChMOVHJhbnMgU3BlZCBTUkwxHzAdBgNVBAsTFkZPUiBU\n" +
            "RVNUIFBVUlBPU0VTIE9OTFkxJTAjBgNVBAMTHFRyYW5zIFNwZWQgUm9vdCBDQSBH\n" +
            "MiAtIFRFU1QwHhcNMTcwMTEyMTMzMTM2WhcNMjcwMTEyMTM0MTM2WjB0MQswCQYD\n" +
            "VQQGEwJSTzEXMBUGA1UEChMOVHJhbnMgU3BlZCBTUkwxHzAdBgNVBAsTFkZPUiBU\n" +
            "RVNUIFBVUlBPU0VTIE9OTFkxKzApBgNVBAMTIlRyYW5zIFNwZWQgTW9iaWxlIGVJ\n" +
            "REFTIFFDQSAtIFRFU1QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDf\n" +
            "DHu8uwd7qGWeC9UF2bS+tDCvQfsdO23HUikPVPbDIUClYgItXEv/t8SBjTCZUZPV\n" +
            "lnxIPFj3o/gXYwDq3ggpAOP1fREtWv7m83aOLT6xaFFzotzBRTEqKLSj5nFQWxq9\n" +
            "Emd4v8jce3IRuKi16U9MCwuH2FcoODrZ4WHlLuD25/6wE8oPBqIYt5llZqRaIur5\n" +
            "ZhU+Cq1Hd40k/bchWslVjzFxZQIhq9AIu63I0VlZtMjpQUIhxEfzbSBNBD5Cm6Ef\n" +
            "cmnnY9xN32/ikr5hUM86BXwEKXfMbgqLBc0cSkA/b12j8UTKUvYj1MTPdVom3YVQ\n" +
            "RlelrNzgbYeX60kRGJHlAgMBAAGjggF+MIIBejAdBgNVHQ4EFgQUCvGAR+TEUYHU\n" +
            "KozGlW3pi3O1BMwwHwYDVR0jBBgwFoAUmPw5ghFgEoJOtTkJGVsdtp0WGckwQAYD\n" +
            "VR0fBDkwNzA1oDOgMYYvaHR0cDovL3d3dy50cmFuc3NwZWQucm8vY3JsL3RzX3Jv\n" +
            "b3RfZzJfdGVzdC5jcmwwewYIKwYBBQUHAQEEbzBtMD8GCCsGAQUFBzAChjNodHRw\n" +
            "Oi8vd3d3LnRyYW5zc3BlZC5yby9jYWNlcnRzL3RzX3Jvb3RfZzJfdGVzdC5jcnQw\n" +
            "KgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLXRlc3QudHJhbnNzcGVkLnJvLzBVBgNV\n" +
            "HSAETjBMMAkGBwQAi+xAAQIwPwYLKwYBBAGCuB0EAQEwMDAuBggrBgEFBQcCARYi\n" +
            "aHR0cDovL3d3dy50cmFuc3NwZWQucm8vcmVwb3NpdG9yeTASBgNVHRMBAf8ECDAG\n" +
            "AQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAd4VtoRcG\n" +
            "Q5hTjQiDTlhpTFLvjMuQgSkfYk1hKwHXPlGhkitL6J94fZ7a5eKne32kBAI900ps\n" +
            "wAKWJu376rtxXxaMt2yCabJc+04eY4TphjDFfVFo5YJzlsBsFoFHMMapcBz9L5ii\n" +
            "mro/CHkTazv6qqupK46XwR3OUImiOpLEbxJv/ohCi5LnQPxZUjeMR74pLrQwESWn\n" +
            "mDj5qI3WF/jZQJySvxF/fD8Y+y5eBKMwZcPMO9F54RzsjkAePlAslXEDfyL/NTSW\n" +
            "UpPicMv3hyWtf622weH8PRnrRK4JqDaj4adEcKeThnXw5Ct2/uHpgF0kYZcTpeWy\n" +
            "McSbUFjhJlWEgw==\n" +
            "-----END CERTIFICATE-----\n";

    private static String rootCaCrt = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDqDCCApCgAwIBAgIQK2bbwnU3ML1CIz5RvN1ByjANBgkqhkiG9w0BAQsFADBu\n" +
            "MQswCQYDVQQGEwJSTzEXMBUGA1UEChMOVHJhbnMgU3BlZCBTUkwxHzAdBgNVBAsT\n" +
            "FkZPUiBURVNUIFBVUlBPU0VTIE9OTFkxJTAjBgNVBAMTHFRyYW5zIFNwZWQgUm9v\n" +
            "dCBDQSBHMiAtIFRFU1QwHhcNMTYxMjAyMTMxNjQ4WhcNMzExMjAyMTMyNjQ3WjBu\n" +
            "MQswCQYDVQQGEwJSTzEXMBUGA1UEChMOVHJhbnMgU3BlZCBTUkwxHzAdBgNVBAsT\n" +
            "FkZPUiBURVNUIFBVUlBPU0VTIE9OTFkxJTAjBgNVBAMTHFRyYW5zIFNwZWQgUm9v\n" +
            "dCBDQSBHMiAtIFRFU1QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7\n" +
            "z3iVoaZf3nuiX+cw9O86dkBPtHgkS/W2a09xKTd2WXx++tD4Ci2425IWuhUy1O5i\n" +
            "jQoVPfCVha8DCAbmT7ElBpPzY71HitYuMZMk2u12oJqHZmbrStlOwcTW/uKYb3/1\n" +
            "tK6E1cAh9Ux482sXEhkeSM6nhZKe5MBrSTx+jZOYcxWhXPenxI3oqwivWH2BBqrx\n" +
            "A3muct5ZeOh9UM3oJG4vhyst1tNbgT6cKfHpSVhMuNoiY4IrjkEJGcm/R5+oC7TA\n" +
            "KpTqoDaobkVakxJkcgHMn04vzv5ZUQuP+v7t2XuRjSJO7eBIue7+m4RMbYiVsUbi\n" +
            "tXGvBL22oQDrdFlmAHVlAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\n" +
            "Af8EBTADAQH/MB0GA1UdDgQWBBSY/DmCEWASgk61OQkZWx22nRYZyTANBgkqhkiG\n" +
            "9w0BAQsFAAOCAQEAqJBXU5l21vZbc8B2v2jMYiSsQFn2L/iLNw4dPEnlwUORHREq\n" +
            "vv4cVwlNyBJG4PQTWSqVzfbS4KaDOMfO2eiq2HI4QJ/v9VnKre5uwgCNhSj5fGIo\n" +
            "3SaTljKw7/gtjorRTOJfZPd6F0YLXkLKvah+ZScjMqjB9szWqIhcbiuBJBoi5vXB\n" +
            "XSalZk9ZbEpYkriyQ1iBJtvYs6WbZErGibMzwWAD+YXYrDKI2e95UC84bJloHPCW\n" +
            "du3LeH+LbqqVmssr3jTQfSUHIfiqGRjPTeP2rMnt2aaXTmx3G4iS7DaNxdrsQhCc\n" +
            "xM/c9DuEWrcQVuPrsrTRLeOV4gUPlw5wk/duJg==\n" +
            "-----END CERTIFICATE-----\n";


    static void importCertificateIntoAndroid(Certificate cert, PrivateKey privateKey) throws CertificateException, KeyStoreException {
        try {
            KeyStore pk12KeyStore = KeyStore.getInstance("PKCS12");
            pk12KeyStore.load(null, null);
//            ByteArrayInputStream is = new ByteArrayInputStream(certStr.getBytes());
//            CertificateFactory cf = CertificateFactory.getInstance("X.509");
//            Certificate cert = cf.generateCertificate(is);
            pk12KeyStore.setKeyEntry("CataDCertPfx", privateKey, "".toCharArray(), new Certificate[]{cert});
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            pk12KeyStore.store(os, "".toCharArray());
            Intent certInstallIntent = KeyChain.createInstallIntent();
            certInstallIntent.putExtra(KeyChain.EXTRA_PKCS12, String.valueOf(os));
            certInstallIntent.putExtra(KeyChain.EXTRA_KEY_ALIAS, "CataDCertPfx");
            certInstallIntent.putExtra(KeyChain.EXTRA_NAME,  "CataDCertPfx");
            mActivity.startActivity(certInstallIntent);
        } catch (Exception e) {
            Log.d(TAG, "help");
        }
    }


    static Certificate myGetCertificate() throws CertificateException, KeyStoreException {
        InputStream is = new ByteArrayInputStream(catalinCrt.getBytes());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(is);
           return certificate;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    static PrivateKey myGetKey() throws CertificateException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(

                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(
                "CataDCertPfx",
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                .build());

        KeyPair kp = kpg.generateKeyPair();

        return kp.getPrivate();
    }



    @RequiresApi(api = Build.VERSION_CODES.M)
    protected static void importPrivateKey() {
        try {
//            KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");
//            KeyStore keystore = KeyStore.getInstance("AndroidCAStore");
//            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(null);


            Enumeration<String> aliases = keystore.aliases();

            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            InputStream is = new ByteArrayInputStream(catalinCrt.getBytes());
            Certificate certificate = cf.generateCertificate(is);

            is = new ByteArrayInputStream(transspedMobileCaCrt.getBytes());

            Certificate caCert = cf.generateCertificate(is);

            is = new ByteArrayInputStream(transspedMobileCaCrt.getBytes());
            Certificate rootCaCrt =  cf.generateCertificate(is);

            Certificate[] chain = new Certificate[3];
            chain[0] = certificate;
            chain[1] = caCert;
            chain[2] = rootCaCrt;

//            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//            kpg.initialize(2048);
//            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);

//            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    "CataDCertPfx",
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA512)
                    .build());

            KeyPair kp = kpg.generateKeyPair();


//            kpg.initialize(spec);
//            KeyPair keyPair = kpg.genKeyPair();
//            PrivateKey prvKey = keyPair.getPrivate();

            PrivateKey prvKey = kp.getPrivate();

//            keystore.setKeyEntry("catalinCert3", prvKey, null, chain);
//            keystore.setCertificateEntry("catalinCert3", certificate );

            importCertificateIntoAndroid(certificate, prvKey);
            Enumeration<String> aliases2 = keystore.aliases();

            Log.d(TAG, aliases.toString());

        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }  catch (Exception e) {
            e.printStackTrace();
        }

    }




    /**
     * Implementation for anynchronous task of handling the certificate request. This
     * AsyncTask retrieves the authentication material from the system key store.
     * The key store is accessed in background, as the APIs being exercised
     * may be blocking. The results are posted back to native on the UI thread.
     */
    private static class CertAsyncTaskKeyChain extends AsyncTask<Void, Void, Void> {
        // These fields will store the results computed in doInBackground so that they can be posted
        // back in onPostExecute.
        private byte[][] mEncodedChain;
        private PrivateKey mPrivateKey;

        private WindowAndroid mWindow;  //my param

        // Pointer to the native certificate request needed to return the results.
        private final long mNativePtr;

        @SuppressLint("StaticFieldLeak") // TODO(crbug.com/799070): Fix.
        final Context mContext;
        final String mAlias;

        CertAsyncTaskKeyChain(Context context, long nativePtr, String alias) {
            mNativePtr = nativePtr;
            mContext = context;
            assert alias != null;
            mAlias = alias;
        }

        @RequiresApi(api = Build.VERSION_CODES.M)
        @Override
        protected Void doInBackground(Void... params) {
            String alias = getAlias();
            if (alias == null) return null;
//             modific aici si caut cheia si certificatul meu
            PrivateKey key = null;
            Certificate[] chain = null;
            try {
                key = myGetKey();
                chain =  new Certificate[]{myGetCertificate()};;
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }

//
//            PrivateKey key = getPrivateKey(alias);
//            X509Certificate[] chain = getCertificateChain(alias);

            if (key == null || chain == null || chain.length == 0) {
                Log.w(TAG, "Empty client certificate chain?");
                return null;
            }

            // Encode the certificate chain.
            byte[][] encodedChain = new byte[chain.length][];
            try {
                for (int i = 0; i < chain.length; ++i) {
                    encodedChain[i] = chain[i].getEncoded();
                }
            } catch (CertificateEncodingException e) {
                Log.w(TAG, "Could not retrieve encoded certificate chain: " + e);
                return null;
            }

            mEncodedChain = encodedChain;
            mPrivateKey = key;
            return null;
        }

        @Override
        protected void onPostExecute(Void result) {
            ThreadUtils.assertOnUiThread();
            nativeOnSystemRequestCompletion(mNativePtr, mEncodedChain, mPrivateKey);
        }

        private String getAlias() {
            return mAlias;
        }

        private PrivateKey getPrivateKey(String alias) {
            try {
                return KeyChain.getPrivateKey(mContext, alias);
            } catch (KeyChainException e) {
                Log.w(TAG, "KeyChainException when looking for '" + alias + "' certificate");
                return null;
            } catch (InterruptedException e) {
                Log.w(TAG, "InterruptedException when looking for '" + alias + "'certificate");
                return null;
            }
        }

        private X509Certificate[] getCertificateChain(String alias) {
            try {
                return KeyChain.getCertificateChain(mContext, alias);
            } catch (KeyChainException e) {
                Log.w(TAG, "KeyChainException when looking for '" + alias + "' certificate");
                return null;
            } catch (InterruptedException e) {
                Log.w(TAG, "InterruptedException when looking for '" + alias + "'certificate");
                return null;
            }
        }
    }

    /**
     * The system KeyChain API will call us back on the alias() method, passing the alias of the
     * certificate selected by the user.
     */
    private static class KeyChainCertSelectionCallback implements KeyChainAliasCallback {
        private final long mNativePtr;
        private final Context mContext;

        KeyChainCertSelectionCallback(Context context, long nativePtr) {
            mContext = context;
            mNativePtr = nativePtr;
        }

        @Override
        public void alias(final String alias) {
            // This is called by KeyChainActivity in a background thread. Post task to
            // handle the certificate selection on the UI thread.
            ThreadUtils.runOnUiThread(() -> {
                if (alias == null) {
                    // No certificate was selected.
                    ThreadUtils.runOnUiThread(
                            () -> nativeOnSystemRequestCompletion(mNativePtr, null, null));
                } else {
                    new CertAsyncTaskKeyChain(mContext, mNativePtr, alias).execute();
                }
            });
        }
    }

    /**
     * Wrapper class for the static KeyChain#choosePrivateKeyAlias method to facilitate testing.
     */
    @VisibleForTesting
    static class KeyChainCertSelectionWrapper {
        private final Activity mActivity;
        private final KeyChainAliasCallback mCallback;
        private final String[] mKeyTypes;
        private final Principal[] mPrincipalsForCallback;
        private final String mHostName;
        private final int mPort;
        private final String mAlias;

        public KeyChainCertSelectionWrapper(Activity activity, KeyChainAliasCallback callback,
                                            String[] keyTypes, Principal[] principalsForCallback, String hostName, int port,
                                            String alias) {
            mActivity = activity;
            mCallback = callback;
            mKeyTypes = keyTypes;
            mPrincipalsForCallback = principalsForCallback;
            mHostName = hostName;
            mPort = port;
            mAlias = alias;
        }

        /**
         * Calls KeyChain#choosePrivateKeyAlias with the provided arguments.
         */
        public void choosePrivateKeyAlias() throws ActivityNotFoundException {
            KeyChain.choosePrivateKeyAlias(mActivity, mCallback, mKeyTypes, mPrincipalsForCallback,
                    mHostName, mPort, mAlias);
        }
    }

    /**
     * Dialog that explains to the user that client certificates aren't supported on their operating
     * system. Separated out into its own class to allow Robolectric unit testing of
     * maybeShowCertSelection without depending on Chrome resources.
     */
    @VisibleForTesting
    static class CertSelectionFailureDialog {
        private final Activity mActivity;

        public CertSelectionFailureDialog(Activity activity) {
            mActivity = activity;
        }

        /**
         * Builds and shows the dialog.
         */
        public void show() {
            final AlertDialog.Builder builder =
                    new AlertDialog.Builder(mActivity, R.style.AlertDialogTheme);
            builder.setTitle(R.string.client_cert_unsupported_title)
                    .setMessage(R.string.client_cert_unsupported_message)
                    .setNegativeButton(R.string.close,
                            (OnClickListener) (dialog, which) -> {
                                // Do nothing
                            });
            builder.show();
        }
    }

    /**
     * Create a new asynchronous request to select a client certificate.
     *
     * @param nativePtr         The native object responsible for this request.
     * @param window            A WindowAndroid instance.
     * @param keyTypes          The list of supported key exchange types.
     * @param encodedPrincipals The list of CA DistinguishedNames.
     * @param hostName          The server host name is available (empty otherwise).
     * @param port              The server port if available (0 otherwise).
     * @return true on success.
     * Note that nativeOnSystemRequestComplete will be called iff this method returns true.
     */
    @CalledByNative
    private static boolean selectClientCertificate(final long nativePtr, final WindowAndroid window,
                                                   final String[] keyTypes, byte[][] encodedPrincipals, final String hostName,
                                                   final int port) {
        ThreadUtils.assertOnUiThread();

        final Activity activity = window.getActivity().get();
        if (activity == null) {
            Log.w(TAG, "Certificate request on GC'd activity.");
            return false;
        }
        mActivity = window.getActivity().get();


        // aici123 pot pune issuers din req OAUTH
        // Build the list of principals from encoded versions.
        Principal[] principals = null;
        if (encodedPrincipals.length > 0) {
            principals = new X500Principal[encodedPrincipals.length];
            try {
                for (int n = 0; n < encodedPrincipals.length; n++) {
                    principals[n] = new X500Principal(encodedPrincipals[n]);
                }
            } catch (Exception e) {
                Log.w(TAG, "Exception while decoding issuers list: " + e);
                return false;
            }
        }

//        importPrivateKey();

        String clientCertificates = OauthController.getClientCertificates();

        KeyChainCertSelectionCallback callback =
                new KeyChainCertSelectionCallback(activity.getApplicationContext(),
                        nativePtr);
//        KeyChainCertSelectionWrapper keyChain = new KeyChainCertSelectionWrapper(activity,
//                callback, keyTypes, principals, hostName, port, null);

        KeyChainCertSelectionWrapper keyChain = new KeyChainCertSelectionWrapper(activity,
                callback, keyTypes, principals, hostName, port, "catalinCert");

//        showMyCustomOauthPopup(new CertSelectionFailureDialog(activity), new OauthOtpDialog(activity));

        // comentat si accesat din myCustomOauthPopup
        // pot verifica keyChain si in cazul in care nu e certificat de pe server, sa il las sa isi ia cursul normal
        maybeShowCertSelection(keyChain, callback,
                new CertSelectionFailureDialog(activity));
        // We've taken ownership of the native ssl request object.
        return true;
    }


    public static void showMyOauthPopupDialog(Semaphore mutex) {
        ThreadUtils.assertOnUiThread();

        OauthController.initSignData();
        CloudSignatureSingleton.getInstance().setmAuthorizationToken(OauthController.getmAccessToken());
        CloudSignatureSingleton.getInstance().setmCredentialId(OauthController.getmCredentialId());

        mActivity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                showMyCustomOauthPopup(new CertSelectionFailureDialog(mActivity), new OauthOtpDialog(mActivity), mutex);
            }
        });
//        try {
//            mMutex.acquire();
//        } catch (InterruptedException e) {
//            Log.e(TAG, e.toString());
//            e.printStackTrace();
//        }

        // poate aici123 pun popup ul meu de test// incerc sa blockez Uithread
        // initiem proces semnare de unde primim si OTP
//            OauthController.initSignData();
//            CloudSignatureSingleton.getInstance().setmAuthorizationToken(OauthController.getmAccessToken());
//            CloudSignatureSingleton.getInstance().setmCredentialId(OauthController.getmCredentialId());
//            showMyCustomOauthPopup(new CertSelectionFailureDialog(mActivity), new OauthOtpDialog(mActivity));
//        }
    }

    /**
     * Attempt to show the certificate selection dialog and shows the provided
     * CertSelectionFailureDialog if the platform's cert selection activity can't be found.
     */
    @VisibleForTesting
    static void maybeShowCertSelection(KeyChainCertSelectionWrapper keyChain,
                                       KeyChainAliasCallback callback, CertSelectionFailureDialog failureDialog) {
        try { // poate aici123
            keyChain.choosePrivateKeyAlias();
        } catch (ActivityNotFoundException e) {
            // This exception can be hit when a platform is missing the activity to select
            // a client certificate. It gets handled here to avoid a crash.
            // Complete the callback without selecting a certificate.
            callback.alias(null);
            // Show a dialog letting the user know that the system does not support
            // client certificate selection.
            failureDialog.show();
        }
    }

    public static void notifyClientCertificatesChangedOnIOThread() {
        Log.d(TAG, "ClientCertificatesChanged!");
        nativeNotifyClientCertificatesChangedOnIOThread();
    }

    private static native void nativeNotifyClientCertificatesChangedOnIOThread();

    // Called to pass request results to native side.
    private static native void nativeOnSystemRequestCompletion(
            long requestPtr, byte[][] certChain, PrivateKey privateKey);


    /// my code

    @VisibleForTesting
    static void showMyCustomOauthPopup(CertSelectionFailureDialog failureDialog, OauthOtpDialog myDialog, Semaphore mutex) {
        try {
            myDialog.show(mutex);
//            keyChain.choosePrivateKeyAlias();
        } catch (ActivityNotFoundException e) {
            // This exception can be hit when a platform is missing the activity to select
            // a client certificate. It gets handled here to avoid a crash.
            // Complete the callback without selecting a certificate.
//            callback.alias(null);
            // Show a dialog letting the user know that the system does not support
            // client certificate selection.
            failureDialog.show();
            Log.e(TAG, e.toString());
        }
    }

    static class OauthOtpDialog {
        private final Activity mActivity;
        private boolean resultValue;

        public OauthOtpDialog(Activity activity) {
            mActivity = activity;
        }

        // Set up the input
//        final EditText input = new EditText(getApplication);
//        // Specify the type of input expected; this, for example, sets the input as a password, and will mask the text
//        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
//        builder.setView(input);

        /**
         * Builds and shows the dialog.
         */
        public boolean show(Semaphore mutex) {
            AlertDialog.Builder alertDialog = new AlertDialog.Builder(mActivity);
            alertDialog.setTitle("Oauth OTP");
            alertDialog.setMessage("Enter SMS OTP");

            final EditText input = new EditText(mActivity);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.MATCH_PARENT);
            input.setLayoutParams(lp);
            alertDialog.setView(input);

            try {


                alertDialog.setPositiveButton("YES",
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                String password = input.getText().toString();
//                            if (password.compareTo("") == 0) {
                                resultValue = true;
                                CloudSignatureSingleton.getInstance().setmSignOtp(password);
//                                maybeShowCertSelection(keyChain, callback, failureDialog);
                                mutex.release();
                            }
                        });

                alertDialog.setNegativeButton("NO",
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                resultValue = false;
                                dialog.cancel();
                                mutex.release();
                            }
                        });
                alertDialog.show();
            } catch (Exception e) {
                Log.e(TAG, e.toString());
            }

            return resultValue;
        }
    }
    /// end my Code

}
