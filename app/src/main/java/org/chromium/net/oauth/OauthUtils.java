package org.chromium.net.oauth;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class OauthUtils {
    private static final String TAG = "OauthUtils";
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static String fetch(@NonNull Uri uri, HashMap<String, String> bodyParams) throws IOException {
        HttpURLConnection connection = null;
        try {
            StringBuilder postData = new StringBuilder();
            for (Map.Entry<String,String> param : bodyParams.entrySet()) {
                if (postData.length() > 1) postData.append('&');
                postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                postData.append('=');
                postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
            }
            byte[] postDataBytes = postData.toString().getBytes(StandardCharsets.UTF_8);
            int postDataBytesLen = postDataBytes.length;
            URL url = new URL(uri.toString());
            connection = (HttpURLConnection)url.openConnection();
            connection.setDoOutput(true);
            connection.setInstanceFollowRedirects( false );
            connection.setRequestMethod( "POST" );
            connection.setRequestProperty( "Content-Type", "application/json");
            connection.setRequestProperty( "Content-Length", Integer.toString( postDataBytesLen ));
            connection.setUseCaches( false );
            connection.getOutputStream().write(postDataBytes);

            return inputStreamToString(connection.getInputStream());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    @NonNull
    public static String inputStreamToString(@NonNull InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            StringBuilder builder = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                builder.append(line).append('\n');
            }
            return builder.toString();
        }
    }


    public static String okhttpPostRequest(@NonNull Uri uri, String clientId,String clientSecret,String redirectUri, String code) throws IOException {
        try {
            OkHttpClient client = new OkHttpClient().newBuilder()
                    .build();
            MediaType mediaType = MediaType.parse("application/json");
            RequestBody body = RequestBody.create(mediaType, "{\r\n    \"grant_type\": \"authorization_code\",\r\n    \"client_id\": \""+ clientId +"\",\r\n    \"client_secret\": \"" + clientSecret +"\",\r\n    \"redirect_uri\": \""+ redirectUri +"\",\r\n    \"code\": \"" + code + "\"\r\n}");
            Request request = new Request.Builder()
                    .url(String.valueOf(uri))
                    .method("POST", body)
                    .addHeader("Content-Type", "application/json")
                    .build();
            Response response = client.newCall(request).execute();
            String responseString = response.body().string();
            return responseString;
        }catch (Exception e) {
            Log.e(TAG,e.toString());
        }
        return null;
    }

    public static void saveToSharedPreference(Context context, String key, String value ) {
        SharedPreferences preferences =
                context.getSharedPreferences("OAUTH_STORAGE", Context.MODE_PRIVATE);
        preferences.edit()
                .putString(key, value)
                .apply();
    }

    public static String getFromSharedPreference(Context context, String key ) {
        SharedPreferences preferences =
                context.getSharedPreferences("OAUTH_STORAGE", Context.MODE_PRIVATE);
        String value = preferences.getString(key, "");
        return value;
    }


    public static String okhttpSignRequestPost(@NonNull String uriStr, @Nullable String requestBodyStr, String authToken) throws Exception {
        try {
            OkHttpClient client = new OkHttpClient().newBuilder()
                    .build();
            MediaType mediaType = MediaType.parse("application/json");
            RequestBody body = RequestBody.create(mediaType, requestBodyStr);
            Request request = new Request.Builder()
                    .url(uriStr)
                    .method("POST", body)
                    .addHeader("Authorization", "Bearer " + authToken)
                    .build();
            Response response = client.newCall(request).execute();
            String responseString = response.body().string();

            if(response.code()!= 200) {
                throw new Exception(TAG+ " Error: " + responseString);
            }

            return responseString;
        }catch (Exception e) {
            throw new Exception(TAG+ " Error: " + e.toString());
        }

    }
}
