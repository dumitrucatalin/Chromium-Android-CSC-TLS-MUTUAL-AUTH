// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.document;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.StrictMode;
import android.widget.Toast;

import org.chromium.base.ApiCompatibilityUtils;
import org.chromium.base.TraceEvent;
import org.chromium.chrome.browser.LaunchIntentDispatcher;
import org.chromium.net.oath.OauthController;
import org.json.JSONException;

import java.io.IOException;

/**
 * Dispatches incoming intents to the appropriate activity based on the current configuration and
 * Intent fired.
 */
public class ChromeLauncherActivity extends Activity {

    private static final String BASE_REDIRECT_URI = "com.csc.tls.auth";
    private static String mAuthCode;
    private static final OauthController mOauthController = new OauthController();
    private static Boolean isFirstRun = true;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Third-party code adds disk access to Activity.onCreate. http://crbug.com/619824
        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
        TraceEvent.begin("ChromeLauncherActivity.onCreate");
        try {
            super.onCreate(savedInstanceState);

            // Begin MyCode
            Intent intent = getIntent();
            if (intent != null) {
                Uri data = intent.getData();
                boolean isRedirectTrue = (data != null && data.toString() != null && data.toString().startsWith(BASE_REDIRECT_URI));
                if (isRedirectTrue) {

                    try {
                        handleAuthCallback(data);
                        mAuthCode = data.toString();
                        Toast.makeText(this, "E OK", Toast.LENGTH_LONG).show();
                    } catch (Exception e) {
                        Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show();
                        e.printStackTrace();
                    }
                }
            }
            // end my code

            @LaunchIntentDispatcher.Action
            int dispatchAction = LaunchIntentDispatcher.dispatch(this, getIntent());
            switch (dispatchAction) {
                case LaunchIntentDispatcher.Action.FINISH_ACTIVITY:
                    finish();
                    break;
                case LaunchIntentDispatcher.Action.FINISH_ACTIVITY_REMOVE_TASK:
                    ApiCompatibilityUtils.finishAndRemoveTask(this);
                    break;
                default:
                    assert false : "Intent dispatcher finished with action " + dispatchAction
                            + ", finishing anyway";
                    finish();
                    break;
            }
        } finally {
            StrictMode.setThreadPolicy(oldPolicy);
            TraceEvent.end("ChromeLauncherActivity.onCreate");

            if (isFirstRun) {
                mOauthController.authorize(getApplicationContext(), "user");
                isFirstRun = false;
            }
        }
    }

    private void handleAuthCallback(Uri uri) throws IOException, JSONException {
        mOauthController.handleAuthCallback(this, uri, (accessToken, expiresIn, tokenType) -> {
            // aici le putem pune direct, fara a mai folosti shared preferences
//            mAccessTokenText.setText("access_token: " + Utils.getFromSharedPreference(this, "access_token"));
//            mTokenTypeText.setText("token_type: " + Utils.getFromSharedPreference(this, "token_type"));
//            mExipresInText.setText("expires_in: " + Utils.getFromSharedPreference(this, "expires_in"));
//            mProgressBar.setVisibility(View.INVISIBLE);
//            mLoginButton.setEnabled(true);
//            mLoggedIn = true;
//            mUserText.setText(R.string.logged_in);
//            mInitSignButton.setEnabled(true);
        });
    }
}
