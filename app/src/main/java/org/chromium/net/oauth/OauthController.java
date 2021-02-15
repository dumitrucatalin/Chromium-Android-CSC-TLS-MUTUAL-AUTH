package org.chromium.net.oauth;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.customtabs.CustomTabsIntent;
import android.util.Log;

import org.chromium.chrome.R;
import org.chromium.ui.widget.Toast;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.UUID;

import org.conscrypt.csc.CloudSignatureSingleton;

import static android.content.Intent.FLAG_ACTIVITY_NEW_TASK;

public class OauthController {
    // these needed to be configured  with user credentials and redirect uri from remote_signing_json_config file
    private static  String BASE_REDIRECT_URI;
    private static  String CSC_BASE_URI;
    private static  String CLIENT_OAUTH_PIN ;

    private static  String CREDENTIAL_ID_URI ;
    private static  String SEND_OTP_URI;
    private static  String CREDENTIALS_INFO_URI ;
    private static final String TAG = "OauthController";

    static String beginCertHeader = "-----BEGIN CERTIFICATE-----\n";
    static String endCertHeader = "\n-----END CERTIFICATE-----\n";

    private static String mClientId;
    private static String mClientSecret;
    private static String mAuthorizationEndpoint;
    private static String mRedirectUri;
    private static String mTokenEndpoint;
    private static Context mContext;


    private static String mAccessToken;
    private static String mTokenType;
    private static String mExpiresIn;
    private static String mCredentialId;
    private static String mClientCertificates;


    public static String getmAccessToken() {
        return mAccessToken;
    }

    public void setmAccessToken(String mAccessToken) {
        this.mAccessToken = mAccessToken;
    }

    public String getmTokenType() {
        return mTokenType;
    }

    public void setmTokenType(String mTokenType) {
        this.mTokenType = mTokenType;
    }

    public static String getmExpiresIn() {
        return mExpiresIn;
    }

    public void setmExpiresIn(String mExpiresIn) {
        this.mExpiresIn = mExpiresIn;
    }

    public static String getmCredentialId() {
        return mCredentialId;
    }

    public void setmCredentialId(String mCredentialId) {
        this.mCredentialId = mCredentialId;
    }

    public interface OAuthCallback {
        void auth(String accessToken, String expiresIn, String tokenType);
    }

    public OauthController(String clientId, String clientSecret, String authorizationEndpoint,
                           String redirectUri, String tokenUrl) {
        mClientId = clientId;
        mClientSecret = clientSecret;
        mAuthorizationEndpoint = authorizationEndpoint;
        mRedirectUri = redirectUri;
        mTokenEndpoint = tokenUrl;
        setParamsToConscyptProvider();
    }

    public OauthController()  {

    }

    public void authorize(Context context, String scope) throws IOException {
        this.mContext = context;
        getParamsFromConfigJson();
        // Generate a random state.
        String state = UUID.randomUUID().toString();

        // Save the state so we can verify later.
        SharedPreferences preferences =
                context.getSharedPreferences("OAUTH_STORAGE", Context.MODE_PRIVATE);
        preferences.edit()
                .putString("OAUTH_STATE", state)
                .apply();

        if(mAuthorizationEndpoint == null || mClientId==null || mRedirectUri==null) {
            Toast.makeText(context, "One or more client parameters null", android.widget.Toast.LENGTH_LONG).show();
            return;
        }

        // Create an authorization URI to the OAuth Endpoint.
        Uri uri = Uri.parse(mAuthorizationEndpoint)
                .buildUpon()
                .appendQueryParameter("response_type", "code")
                .appendQueryParameter("client_id", mClientId)
                .appendQueryParameter("redirect_uri", mRedirectUri)
                .appendQueryParameter("state", state)
                .appendQueryParameter("lang", "en-US")
                .build();

        // Open the Authorization URI in a Custom Tab.
        CustomTabsIntent customTabsIntent = new CustomTabsIntent.Builder().build();
        customTabsIntent.intent.setFlags(FLAG_ACTIVITY_NEW_TASK);
        customTabsIntent.launchUrl(context, uri);
    }

    // aici iau doar codul si urmeaza sa fac requesturi pt restul
    public void handleAuthCallback(
            @NonNull Context context, @NonNull Uri uri, @NonNull OAuthCallback callback) throws IOException, JSONException {
        String code = uri.getQueryParameter("code");
        String uriState = uri.getQueryParameter("state"); // de comparat cu state din shared preferences
        SharedPreferences preferences =
                context.getSharedPreferences("OAUTH_STORAGE", Context.MODE_PRIVATE);
        String state = preferences.getString("OAUTH_STATE", "");
        Uri tokenUri = Uri.parse(mTokenEndpoint);

        // Run the network request off the UI thread.
        new Thread(() -> {
            try {
                String response = OauthUtils.okhttpPostRequest(tokenUri, mClientId, mClientSecret, mRedirectUri, code);
                JSONObject jsonResponse = new JSONObject(response);
                mAccessToken = jsonResponse.getString("access_token");
                mTokenType = jsonResponse.getString("token_type");
                mExpiresIn = jsonResponse.getString("expires_in");

                OauthUtils.saveToSharedPreference(context, "access_token", mAccessToken);
                OauthUtils.saveToSharedPreference(context, "token_type", mTokenType);
                OauthUtils.saveToSharedPreference(context, "expires_in", mExpiresIn);

                // aici le pun in shared preferences sau fac o clasa token de unde sa iau pt requesturi de semnatura
                new Handler(Looper.getMainLooper()).post(
                        () -> callback.auth(mAccessToken, mExpiresIn, mTokenType));

            } catch (IOException | JSONException e) {
                Log.e(TAG, "Error requesting access token: " + e.getMessage());
            }
        }).start();
    }

    public static Boolean initSignData() {
        try {
            sendCredentialIDReq();
            sendOTPReq();
            if (mCredentialId == null) {
                return false;
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, e.toString());
        }
        return false;
    }


    public static String getClientCertificates() {
        try {
            loadDataFromSharedPreferences();
            sendCredentialIDReq();
            getClientCertificatesReq();
            if (mClientCertificates == null) {
                return null;
            }
            mClientCertificates = beginCertHeader + mClientCertificates + endCertHeader;
            return mClientCertificates;
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, e.toString());
        }
        return null;
    }


    private static void getClientCertificatesReq() throws InterruptedException {

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String reqBodyStr = "{\r\n\"credentialID\": \"" + mCredentialId + "\",\r\n\"certificates\": \"single\",\r\n\"certInfo\": true,\r\n\"authInfo\": true\r\n}";
                    String response = OauthUtils.okhttpSignRequestPost(CREDENTIALS_INFO_URI, reqBodyStr, mAccessToken);
                    if (response != null) {
                        JSONObject jsonResponse = null;
                        jsonResponse = new JSONObject(response);
                        JSONArray attributeArray = jsonResponse.getJSONObject("cert").getJSONArray("certificates");
                        mClientCertificates = attributeArray.get(0).toString().replaceAll("\\r", "");
                        ; // trebuie scos /r/n
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e(TAG, e.toString());
                }

            }
        });
        thread.start();
        thread.join();
    }


    private static void sendCredentialIDReq() throws InterruptedException {

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    String response = OauthUtils.okhttpSignRequestPost(CREDENTIAL_ID_URI, "", mAccessToken);
                    if (response != null) {
                        JSONObject jsonResponse = null;
                        jsonResponse = new JSONObject(response);
                        JSONArray attributeArray = jsonResponse.getJSONArray("credentialIDs");
                        mCredentialId = attributeArray.get(0).toString();
                        OauthUtils.saveToSharedPreference(mContext, "credentialId", mCredentialId);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e(TAG, e.toString());
                }

            }
        });
        thread.start();
        thread.join();
    }


    private static void sendOTPReq() throws InterruptedException {

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String reqBodyStr = "{\r\n\"credentialID\": \"" + mCredentialId + "\"\r\n}";
                    String response = OauthUtils.okhttpSignRequestPost(SEND_OTP_URI, reqBodyStr, mAccessToken);
                    if (response == null) {
                        Log.e(TAG, "Error on SendOTP req");
                        return;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e(TAG, e.toString());
                }

            }
        });
        thread.start();
        thread.join();
    }


    public static void loadDataFromSharedPreferences() {
        String access_token = OauthUtils.getFromSharedPreference(mContext, "access_token");
        String token_type = OauthUtils.getFromSharedPreference(mContext, "token_type");
        String expires_in = OauthUtils.getFromSharedPreference(mContext, "expires_in");
        mAccessToken = access_token;
        mExpiresIn = expires_in;
        mTokenType = token_type;
    }

    public static void setParamsToConscyptProvider() {
        CloudSignatureSingleton.getInstance().setmPIN(CLIENT_OAUTH_PIN);
        CloudSignatureSingleton.getInstance().setmCSC_BASE_URI(CSC_BASE_URI);
    }

    public static void getParamsFromConfigJson() throws IOException {
        InputStream is = mContext.getResources().openRawResource(R.raw.remote_signing_json_config);
        Writer writer = new StringWriter();
        char[] buffer = new char[1024];
        try {
            Reader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            int n;
            while ((n = reader.read(buffer)) != -1) {
                writer.write(buffer, 0, n);
            }
            String jsonString = writer.toString();

            JSONObject jsonResponse = new JSONObject(jsonString);
             mClientId = jsonResponse.getString("CLIENT_ID");
             mClientSecret = jsonResponse.getString("CLIENT_SECRET");
             CLIENT_OAUTH_PIN = jsonResponse.getString("CLIENT_OAUTH_PIN");
             BASE_REDIRECT_URI = jsonResponse.getString("BASE_REDIRECT_URI");
             CSC_BASE_URI = jsonResponse.getString("CSC_BASE_URI");

             if(mClientId == null || mClientSecret == null || CLIENT_OAUTH_PIN == null || BASE_REDIRECT_URI == null || CSC_BASE_URI == null) {
                 Toast.makeText(mContext, "Error on remote signing json config params!!", Toast.LENGTH_LONG).show();
             }

            mAuthorizationEndpoint = CSC_BASE_URI + "oauth2/authorize";
            mTokenEndpoint = CSC_BASE_URI + "oauth2/token";
            mRedirectUri = BASE_REDIRECT_URI + "://token";
            CREDENTIAL_ID_URI = CSC_BASE_URI + "credentials/list";
            SEND_OTP_URI = CSC_BASE_URI + "credentials/sendOTP";
            CREDENTIALS_INFO_URI = CSC_BASE_URI + "credentials/info";

            setParamsToConscyptProvider();

        } catch (IOException | JSONException e) {
            e.printStackTrace();
        } finally {
            is.close();
        }
    }

}
