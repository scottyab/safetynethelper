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

import java.security.SecureRandom;
import java.util.Arrays;


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
    public static final int SAFTYNET_API_REQUEST_UNSUCCESSFUL = 999;
    public static final int RESPONSE_ERROR_VALIDATING_SIGNATURE = 1000;
    public static final int RESPONSE_FAILED_SIGNATURE_VALIDATION = 1002;
    public static final int RESPONSE_VALIDATION_FAILED = 1001;


    /**
     * This is used to validate the payload response from the SafetyNet.API,
     * if it exceeds this duration, the response is considered invalid.
     */
    private static int MAX_TIMESTAMP_DURATION=2*60*1000;

    private final SecureRandom secureRandom;
    private GoogleApiClient googleApiClient;

    //used for local validation of API response payload
    private byte[] requestNonce;
    private long requestTimestamp;
    private String packageName;

    //not used currently
    private String[] apkCertificateDigests;
    private String apkDigest;


    private SafetyNetWrapperCallback callback;

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

    /**
     * Simple interface for handling SafetyNet API response
     */
    public interface SafetyNetWrapperCallback{
        void error(int errorCode, String errorMessage);
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

        //commented out for now as cannot recreate the values Google play services is using
        apkCertificateDigests = Utils.calcApkCertificateDigests(context);
        Log.d(TAG, "apkCertificateDigests:"+ Arrays.asList(apkCertificateDigests));
        apkDigest = Utils.calcApkDigest(context);
        Log.d(TAG, "apkDigest:"+apkDigest);
    }

    @Override
    public void onConnected(Bundle bundle) {
        Log.v(TAG, "Google play services connected");
        runSaftyNetTest();
    }

    private void runSaftyNetTest() {
        Log.v(TAG, "running SafetyNet.API Test");

        requestNonce = generateOneTimeRequestNonce();
        requestTimestamp = System.currentTimeMillis();
        SafetyNet.SafetyNetApi.attest(googleApiClient, requestNonce)
                .setResultCallback(new ResultCallback<SafetyNetApi.AttestationResult>() {
                    @Override
                    public void onResult(final SafetyNetApi.AttestationResult result) {
                        Status status = result.getStatus();
                        //JSON Web Signature format
                        final String jwsResult = result.getJwsResult();
                        if (status.isSuccess() && !TextUtils.isEmpty(jwsResult)) {
                            final SafetyNetResponse response = parseJsonWebSignature(jwsResult);
                            lastResponse = response;

                            //validate payload of the response
                            if (validateSafetyNetResponsePayload(response)) {
                                if (!TextUtils.isEmpty(googleDeviceVerificationApiKey)) {
                                    //if the api key is set, run the AndroidDeviceVerifier
                                    AndroidDeviceVerifier androidDeviceVerifier = new AndroidDeviceVerifier(googleDeviceVerificationApiKey, jwsResult);
                                    androidDeviceVerifier.verify(new AndroidDeviceVerifier.AndroidDeviceVerifierCallback() {
                                        @Override
                                        public void error(String errorMsg) {
                                            callback.error(RESPONSE_ERROR_VALIDATING_SIGNATURE, "Response signature validation error: " + errorMsg);
                                        }

                                        @Override
                                        public void success(boolean isValidSignature) {
                                            if (isValidSignature) {
                                                callback.success(response.isCtsProfileMatch());
                                            } else {
                                                callback.error(RESPONSE_FAILED_SIGNATURE_VALIDATION, "Response signature invalid");

                                            }
                                        }
                                    });
                                }else{
                                    Log.w(TAG, "No google Device Verification ApiKey defined, **skipping** response signature validation");
                                }
                                callback.success(response.isCtsProfileMatch());
                            } else {
                                callback.error(RESPONSE_VALIDATION_FAILED, "Response payload validation failed");
                            }
                        } else {
                            // An error occurred while communicating with the SafetyNet Api
                            callback.error(SAFTYNET_API_REQUEST_UNSUCCESSFUL, "SafetyNetApi.AttestationResult success == false or empty payload");
                        }
                    }
                });
    }

    /**
     * Gets the previous successful call to the safetynetAPI - this is mainly for debug purposes.
     *
     * @return
     */
    public SafetyNetResponse getLastResponse(){
        return lastResponse;
    }

    private boolean validateSafetyNetResponsePayload(SafetyNetResponse response) {
        if (response==null) {
            Log.e(TAG, "SafetyNetResponse is null.");
            return false;
        }

        //check the request nonce is matched in the response
        final String requestNonceBase64 = Base64.encodeToString(requestNonce, Base64.DEFAULT).trim();

        if (!requestNonceBase64.equals(response.getNonce())){
            Log.e(TAG, "invalid nonce, expected = \"" + requestNonceBase64 + "\"");
            Log.e(TAG, "invalid nonce, response   = \"" + response.getNonce() + "\"");
            return false;
        }

        if (!packageName.equalsIgnoreCase(response.getApkPackageName())){
            Log.e(TAG, "invalid packageName, expected = \"" + packageName + "\"");
            Log.e(TAG, "invalid packageName, response = \"" + response.getApkPackageName() + "\"");
            return false;
        }

        long durationOfReq = response.getTimestampMs()-requestTimestamp;
        if(durationOfReq>MAX_TIMESTAMP_DURATION){
            Log.e(TAG, "Duration calculated from the timestamp of response \""+durationOfReq +" \" exceeds permitted duration of \"" + MAX_TIMESTAMP_DURATION + "\"");
            return false;
        }

        //This is commented out as couldn't recreate the ApkCertificateDigest need more info on how these are constructed.
        if (!Arrays.equals(apkCertificateDigests,  response.getApkCertificateDigestSha256())){
            Log.e(TAG, "invalid apkCertificateDigest, local/expected = " + Arrays.asList(apkCertificateDigests));
            Log.e(TAG, "invalid apkCertificateDigest, response = " +  Arrays.asList(response.getApkCertificateDigestSha256()));
//            return false;
        }

        if (!apkDigest.equals(response.getApkDigestSha256())){
            Log.e(TAG, "invalid ApkDigest, local/expected = \"" + apkDigest + "\"");
            Log.e(TAG, "invalid ApkDigest, response = \"" + response.getApkDigestSha256() + "\"");
            return false;
        }

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
        callback.error(connectionResult.getErrorCode(), "Google Play services connection failed");
    }

}
