package org.chromium.net.oath;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.customtabs.CustomTabsIntent;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.UUID;

import static android.content.Intent.FLAG_ACTIVITY_NEW_TASK;

public class OauthController {
    private static final String CSC_BASE_URI = "https://msign-test.transsped.ro/csc/v0/";
    private static final String AUTHORIZATION_ENDPOINT = CSC_BASE_URI + "oauth2/authorize";
    private static final String TOKEN_URL_ENDPOINT = CSC_BASE_URI + "oauth2/token";
    private static final String CLIENT_ID = "msdiverse";
    private static final String CLIENT_SECRET = "8KKhHnjKdYmAakc8";
    private static final String BASE_REDIRECT_URI = "com.csc.tls.auth";
    private static final String REDIRECT_URI = BASE_REDIRECT_URI +"://token";
    private static final String HASH_DATA_TO_SIGN = "o7WsDDAtnLKgrh77/2HGCZU9Y0ZtasYmCd0DBEioNgc=";
    private static final String TAG = "OauthController";
    private static final String CREDENTIAL_ID_URI = CSC_BASE_URI + "credentials/list";
    private static final String SEND_OTP_URI = CSC_BASE_URI + "credentials/sendOTP";


    private String mClientId;
    private String mClientSecret;
    private String mAuthorizationEndpoint;
    private String mRedirectUri;
    private String mTokenEndpoint;


    private static String mAccessToken;
    private static String mTokenType;
    private static String mExpiresIn;
    private static String mCredentialId;

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
    }

    public OauthController() {
        mClientId = CLIENT_ID;
        mClientSecret = CLIENT_SECRET;
        mAuthorizationEndpoint = AUTHORIZATION_ENDPOINT;
        mRedirectUri = REDIRECT_URI;
        mTokenEndpoint = TOKEN_URL_ENDPOINT;
    }

    public void authorize(Context context, String scope) {
        // Generate a random state.
        String state = UUID.randomUUID().toString();

        // Save the state so we can verify later.
        SharedPreferences preferences =
                context.getSharedPreferences("OAUTH_STORAGE", Context.MODE_PRIVATE);
        preferences.edit()
                .putString("OAUTH_STATE", state)
                .apply();

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

    // aici iau doar codul, numai pe asta il am... si urmeaza sa fac requesturi pt restul
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

                OauthUtils.saveToSharedPreference(context,"access_token", mAccessToken);
                OauthUtils.saveToSharedPreference(context,"token_type", mTokenType);
                OauthUtils.saveToSharedPreference(context,"expires_in", mExpiresIn);

                // aici le pun in shared preferences sau fac o clasa token de unde sa iau pt requesturi de semnatura
                new Handler(Looper.getMainLooper()).post(
                        () -> callback.auth(mAccessToken, mExpiresIn, mTokenType));

            } catch (IOException | JSONException e) {
                Log.e(TAG, "Error requesting access token: " + e.getMessage());
            }
        }).start();
    }

    public static void initSignData() {
        try {
            sendCredentialIDReq();
            sendOTPReq();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, e.toString());
        }

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

}
