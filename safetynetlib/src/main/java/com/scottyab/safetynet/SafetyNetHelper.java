package com.scottyab.safetynet;

import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 *
 * Simple wrapper to request google Play services - SafetyNet test
 * Based on the code samples from https://developer.android.com/google/play/safetynet/start.html
 *
 * Doesn't handle Google play services errors, just calls error on callback.
 *
 * Created by scottab on 26/05/2015.
 */
public class SafetyNetHelper implements GoogleApiClient.ConnectionCallbacks, GoogleApiClient.OnConnectionFailedListener {

    private static final String TAG = SafetyNetHelper.class.getSimpleName();
    public static final int SAFTYNET_API_UNSUCCESSFUL_ERROR_CODE = 999;
    public static final int SAFTYNET_VALIDATION_ERROR_CODE = 1000;
    public static final int SAFTYNET_VALIDATION_FAILED_ERROR_CODE = 1001;

    private final SecureRandom secureRandom;
    private GoogleApiClient googleApiClient;
    private byte[] requestNonce;
    private SafetyNetWrapperCallback callback;

    //used for local validation of payload
    private String packageName;
    private String googleDeviceVerificationApiKey;
    private SafetyNetResponse lastResponse;

    /**
     *
     * @param googleDeviceVerificationApiKey used to validate safety net response see https://developer.android.com/google/play/safetynet/start.html#verify-compat-check
     */
    public SafetyNetHelper(String googleDeviceVerificationApiKey) {
        secureRandom = new SecureRandom();
        if(TextUtils.isEmpty(googleDeviceVerificationApiKey)){
            Log.w(TAG, "Google Device Verification Api Key not defined, cannot properly validate safety net response without it. See https://developer.android.com/google/play/safetynet/start.html#verify-compat-check");
        }
        this.googleDeviceVerificationApiKey = googleDeviceVerificationApiKey;
    }

    public interface SafetyNetWrapperCallback{
        void error(int errorCode, String s);
        void success(boolean ctsProfileMatch);
    }

    private synchronized void buildGoogleApiClient(Context context) {
        googleApiClient = new GoogleApiClient.Builder(context)
                .addApi(SafetyNet.API)
                .addConnectionCallbacks(this)
                .addOnConnectionFailedListener(this)
                .build();
    }


    /**
     * Call the SafetyNet test to check if this device profile /ROM has passed the CTS test
     * @param context used to build and init the GoogleApiClient
     * @param safetyNetWrapperCallback results and error handling
     */
    public void requestTest(@NonNull final Context context, final SafetyNetWrapperCallback safetyNetWrapperCallback) {
        buildGoogleApiClient(context);
        googleApiClient.connect();
        packageName = context.getPackageName();
        callback = safetyNetWrapperCallback;
    }

    @Override
    public void onConnected(Bundle bundle) {
        Log.d(TAG, "connected");
        runSaftyNetTest();
    }

    private void runSaftyNetTest() {
        Log.d(TAG, "runSaftyNetTest");

        requestNonce = generateOneTimeRequestNonce();
        SafetyNet.SafetyNetApi.attest(googleApiClient, requestNonce)
                .setResultCallback(new ResultCallback<SafetyNetApi.AttestationResult>() {
                    @Override
                    public void onResult(final SafetyNetApi.AttestationResult result) {
                        Status status = result.getStatus();
                        //JSON Web Signature format
                        String jwsResult = result.getJwsResult();
                        if (status.isSuccess() && !TextUtils.isEmpty(jwsResult)) {
                            Log.d(TAG, result.toString());

                            final SafetyNetResponse response = parseJsonWebSignature(jwsResult);
                            lastResponse = response;

                            if (locallyValidateSafetyNetResponse(response)) {
                                if (!TextUtils.isEmpty(googleDeviceVerificationApiKey)) {
                                    //if the api key is set, run the AndroidDeviceVerifier
                                    AndroidDeviceVerifier androidDeviceVerifier = new AndroidDeviceVerifier(googleDeviceVerificationApiKey, jwsResult);
                                    androidDeviceVerifier.verify(new AndroidDeviceVerifier.AndroidDeviceVerifierCallback() {
                                        @Override
                                        public void error(String errorMsg) {
                                            callback.error(SAFTYNET_VALIDATION_ERROR_CODE, "Signature validation failed: " + errorMsg);
                                        }

                                        @Override
                                        public void success(boolean isValidSignature) {
                                            if (isValidSignature) {
                                                callback.success(response.isCtsProfileMatch());
                                            } else {
                                                callback.error(SAFTYNET_VALIDATION_FAILED_ERROR_CODE, "Signature invalid");

                                            }
                                        }
                                    });
                                }
                                callback.success(response.isCtsProfileMatch());
                            } else {
                                callback.error(SAFTYNET_VALIDATION_FAILED_ERROR_CODE, "Validation failed");
                            }
                            //callback.success(true);
                        } else {
                            // An error occurred while communicating with the service
                            callback.error(SAFTYNET_API_UNSUCCESSFUL_ERROR_CODE, "SafetyNetApi.AttestationResult success == false");
                        }
                    }
                });
    }

    /**
     * Gets the previous sucessful call to the safetynetAPI - this is mainly for debug purposes.
     *
     * @return
     */
    public SafetyNetResponse getLastResponse(){
        return lastResponse;
    }

    private boolean locallyValidateSafetyNetResponse(SafetyNetResponse response) {
        if (response==null)
            return false;

        //check the request nonce is matched in the response
        final String requestNonceBase64 = Base64.encodeToString(requestNonce, Base64.DEFAULT).trim();
        if (!requestNonceBase64.equals(response.getNonce())){
            Log.e(TAG, "invalid nonce, requested = \"" + requestNonceBase64 + "\"");
            Log.e(TAG, "invalid nonce, payload   = \"" + response.getNonce() + "\"");
            return false;
        }

        if (!packageName.equalsIgnoreCase(response.getApkPackageName())){
            Log.e(TAG, "invalid packageName, this package = \"" + packageName + "\"");
            Log.e(TAG, "invalid packageName, response = \"" + response.getApkPackageName() + "\"");
            return false;
        }

        //TODO scottab 27/05/2015 validate timestamp of the request is less that 5 mins
        Log.d(TAG, "TimestampMs:" + response.getTimestampMs());

        //TODO validate ApkDigest and certificate signature
        /*
        response.g.getApkDigestSha256()
        if (!requestNonce.equals(response.getNonce())){
            return false;
        }
        */

        return true;
    }

    private @Nullable SafetyNetResponse parseJsonWebSignature(@NonNull String jwsResult) {
        //the JWT (JSON WEB TOKEN) is just a 3 base64 encoded parts concatenated by a . character
        final String[] jwtParts = jwsResult.split("\\.");

        if(jwtParts.length==3) {
            //we're only really interested in the body/payload
            String decodedPayload = new String(Base64.decode(jwtParts[1], Base64.DEFAULT));

            return SafetyNetResponse.parse(decodedPayload);
        }else{
            return null;
        }
    }


    private byte[] generateOneTimeRequestNonce() {
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return nonce;
    }


    @Override
    public void onConnectionSuspended(int i) {

    }

    @Override
    public void onConnectionFailed(ConnectionResult connectionResult) {
        callback.error(connectionResult.getErrorCode(), "Google Play services onConnectionFailed");
    }

    private byte[] hash(String input){
    final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = input.getBytes("UTF-8");
            digest.update(hashedBytes, 0, hashedBytes.length);
            return hashedBytes;
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "problem hashing \"" + input + "\" " + e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "problem hashing \"" + input + "\" " + e.getMessage(), e);
        }
        return null;
    }



}
