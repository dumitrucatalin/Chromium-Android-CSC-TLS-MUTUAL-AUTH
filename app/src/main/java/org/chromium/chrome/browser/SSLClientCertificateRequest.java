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
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.widget.EditText;
import android.widget.LinearLayout;

import org.chromium.base.ThreadUtils;
import org.chromium.base.VisibleForTesting;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.bookmarks.BookmarkFolderRow;
import org.chromium.net.oauth.OauthController;
import org.chromium.ui.base.WindowAndroid;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.concurrent.Semaphore;

import javax.security.auth.x500.X500Principal;

import org.chromium.ui.widget.Toast;
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
//    private static Object mLock = new Object();

    //    private static String pemKey = "MIIEowIBAAKCAQEAzvE2cCa/Y2UwylljgVZIS8uc0c9GsFEp+vhd8ZZ9yo79n/SdI27MOgfKLAMZS3zTGZDvY8d/Yu4kLeEMrJKnHtPGXnBL/Rmyi9uMu/Z2mTsAM//KiCAp/QAIv0JETMIce5VtytXbc1MFpEa2R4iFsH8cZvTDZfYrXndXD/yaOGEVXCb67ffxnCcC9xsH+Y8U4BTyVLPw20VFdD4HiyidpPjiBG4CsJWew0y8GrAImWR8QKWv9AiIaoFSUOQsBwUkj8HDJI4MQo0HbdlhGS741cGhzbvcgup/dREm8I7WFF5lUWOhY91aJ8C6mnWVNCIi0unf1E7f9agFH7nBAlnEhwIDAQABAoIBAC4fpyGCEWBG+oPvPnViVMTIAhDlYP0FahTs7ItfHnRaQH85VxjBpjU87Tu4CRhBHw/wtNqJaYQUTe4H3fpMyYDedLUx1E36P0hay9hNC4wFkXsFhQ+oE5O3QTvXuj9deFm3KXxvA/WFSJmfxRrWe+2ltx/fZ/m+z1XDxZzjkUAFRESNjRB7TrPH7w435KRQEc1ouBf65LcEXDD5xBpiEKeBnk3QHVB1+CZb9GlESSBrjtcvu57E1S5KPUCJPD/PsQphME5OxkujS8pjtHDWDlq/KKzKmBo17k88Iadpc9po7eWt8r+LUTmd4GPfYRhq2k1zc03e8qPaDjYzCuRv1cECgYEA/10k3ioi2P3YAaMCYGECFuFv8U6aXsKMrYX3MW7HtxdctevU0fMRlVfLz2Jc3oOS9aHY+Frm+bkKQ2Hq2xdQlByfF5/lyq8BNaA/cy4iPyYoPMUWmnYnWT4BlrO1/4keXmuzl8dUiSeJUUcbqu6nDRTr76JxWVRfDHtVG5C9BGECgYEAz3UwLU8NGwSUCtelbLkVckUxx8EwQSVxikE1sdjmrLmzRk6kCWJ7R9vXqgNFS2gyCT6yB1l4Is1OaAnwB/4zQtyRH5VJsZOokmrsDvZhVjZzmf9sFy9gEQp8HtYA5cJAAQhtNDnGcPpX8HRJTRprs7/1jDRHjF1OwPDIqiZccecCgYEAoXxhqCy1RMuiIcbX5eLy001U4SB39pzJIaKqI5SOr3YSpuiv+OThpbOTq13kpMJH2RW0g7nYfutJVjtBrbMcvc0rvmDbjEUHWsYv2cK+3Xhf0a5BEQTO9VyE3Kxg12v6zHMHa2AeUW2zJLb3BC1PbrJgUXZEf90fDmGf/IKXRYECgYBBaKpq7qysIxJmJL20fNqFL8nVOFT1hU+6DntWepOoS9h5R1wy1UkXS/pAUU2sy8pS3eCVrqDRIDgjV1bFvmD9KLvc4F3ezjZtC6cnxIjF/N8P49d5q+c3GD4wHrsjtc4mRTjhKYImptfJKXDfDYB9qP1LWkRgvh6ReJlcBEJLawKBgAW4g1NhTLM3Pe915q2e7DikTKFLKvBHnCAalD7sshipbJlx9F8/XBLL0C9zwQRR7AhUoADB8JD7sHBoapowlIMlESG1yKwnG31TQ+wjY7E1JzeQEZUnQAdrs6cseFSf12X+1al2wyCgY6swEg7FuLTP58HwHp9tga5ko4MTqNP7";
    static String beginCertHeader = "-----BEGIN CERTIFICATE-----\n";
    static String endCertHeader = "-----END CERTIFICATE-----\n";

    private static String clientCertificate;


    @RequiresApi(api = Build.VERSION_CODES.O)
    public static PrivateKey getPrivateKeyFromStr(String keystr) throws Exception {
        // Remove the first and last lines
//        String pubKeyPEM = keystr.replace("-----BEGIN PUBLIC KEY-----\n", "");
//        pubKeyPEM = pubKeyPEM.replace("-----END PUBLIC KEY-----", "");

        // Base64 decode the data
        byte[] encoded = Base64.getDecoder().decode(keystr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pubkey = kf.generatePrivate(keySpec);
        return pubkey;
    }


    static Certificate myGetCertificate(String crtString) throws CertificateException, KeyStoreException {
        InputStream is = new ByteArrayInputStream(crtString.getBytes());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(is);
        return certificate;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    static PrivateKey myGetKey() throws  NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,"Conscrypt");

//        kpg.initialize(new KeyGenParameterSpec.Builder(
//                "UserKeyAlias",
//                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
//                .setDigests(KeyProperties.DIGEST_SHA256,
//                        KeyProperties.DIGEST_SHA512)
//                .build());

        KeyPair kp = kpg.generateKeyPair();
        return kp.getPrivate();
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

        @RequiresApi(api = Build.VERSION_CODES.O)
        @Override
        protected Void doInBackground(Void... params) {
            String alias = getAlias();
            if (alias == null) return null;
//             modific aici si caut cheia si certificatul meu
//            aici123
            PrivateKey key = null;
            Certificate[] chain = null;
            try {
                key = myGetKey();  // o cheie noua la fiecare request
                chain = new Certificate[]{myGetCertificate(clientCertificate)};
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (Exception e) {
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
                                                   final int port) throws CertificateException, KeyStoreException {
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

        clientCertificate = OauthController.getClientCertificates();

        if(clientCertificate == null) {
            Toast.makeText(mActivity, "Error on certificate. Certificate null", Toast.LENGTH_SHORT).show();
            return false;
        }
        Certificate clientCrt = myGetCertificate(clientCertificate);

        KeyChainCertSelectionCallback callback =
                new KeyChainCertSelectionCallback(activity.getApplicationContext(),
                        nativePtr);

        callback.alias("myAlias");

//        KeyChainCertSelectionWrapper keyChain = new KeyChainCertSelectionWrapper(activity,
//                callback, keyTypes, principals, hostName, port, null);

//        showMyCustomOauthPopup(new CertSelectionFailureDialog(activity), new OauthOtpDialog(activity));

        // comentat si accesat din myCustomOauthPopup
        // pot verifica keyChain si in cazul in care nu e certificat de pe server, sa il las sa isi ia cursul normal


//        maybeShowCertSelection(keyChain, callback,
//                new CertSelectionFailureDialog(activity));

        // We've taken ownership of the native ssl request object.
        return true;
    }


    public static void showMyOauthPopupDialog(Semaphore mutex) {
        ThreadUtils.assertOnUiThread();
        Boolean isInitSign = OauthController.initSignData();
        if (isInitSign == false) {
            Toast.makeText(mActivity, "Error req on server. Try to restart app and authorize to OAuth", Toast.LENGTH_LONG).show();
            return;
        }
        CloudSignatureSingleton.getInstance().setmAuthorizationToken(OauthController.getmAccessToken());
        CloudSignatureSingleton.getInstance().setmCredentialId(OauthController.getmCredentialId());

        mActivity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                showMyCustomOauthPopup(new CertSelectionFailureDialog(mActivity), new OauthOtpDialog(mActivity), mutex);
            }
        });
    }

    /**
     * Attempt to show the certificate selection dialog and shows the provided
     * CertSelectionFailureDialog if the platform's cert selection activity can't be found.
     */
    @VisibleForTesting
    static void maybeShowCertSelection(KeyChainCertSelectionWrapper keyChain,
                                       KeyChainAliasCallback callback, CertSelectionFailureDialog failureDialog) {
        try {
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


                alertDialog.setPositiveButton("OK",
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

                alertDialog.setNegativeButton("Cancel",
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
