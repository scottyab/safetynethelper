package com.scottyab.safetynet;

import android.content.Context;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Simple wrapper to request google Play services - SafetyNet test
 * Based on the code samples from https://developer.android.com/google/play/safetynet/start.html
 * <p/>
 * Doesn't handle Google play services errors, just calls error on callback.
 * <p/>
 */
public class SafetyNetHelper {

    private static final String TAG = SafetyNetHelper.class.getSimpleName();
    public static final int SAFETY_NET_API_REQUEST_UNSUCCESSFUL = 999;
    public static final int RESPONSE_ERROR_VALIDATING_SIGNATURE = 1000;
    public static final int RESPONSE_FAILED_SIGNATURE_VALIDATION = 1002;
    public static final int RESPONSE_FAILED_SIGNATURE_VALIDATION_NO_API_KEY = 1003;
    public static final int RESPONSE_VALIDATION_FAILED = 1001;


    /**
     * This is used to validate the payload response from the SafetyNet.API,
     * if it exceeds this duration, the response is considered invalid.
     */
    private static int MAX_TIMESTAMP_DURATION = 2 * 60 * 1000;

    private final SecureRandom secureRandom;

    //used for local validation of API response payload
    private byte[] requestNonce;
    private long requestTimestamp;
    private String packageName;

    private List<String> apkCertificateDigests;

    private SafetyNetWrapperCallback callback;

    private String googleDeviceVerificationApiKey;
    private SafetyNetResponse lastResponse;

    /**
     * @param googleDeviceVerificationApiKey used to validate safety net response see https://developer.android.com/google/play/safetynet/start.html#verify-compat-check
     */
    public SafetyNetHelper(@Nullable String googleDeviceVerificationApiKey) {
        this.googleDeviceVerificationApiKey = googleDeviceVerificationApiKey;

        assureApiKeysDefined();

        secureRandom = new SecureRandom();
    }

    private void assureApiKeysDefined() {
        if (TextUtils.isEmpty(googleDeviceVerificationApiKey)) {
            Log.w(TAG, "Google Device Verification Api Key not defined, cannot properly validate safety net response without it. See https://developer.android.com/google/play/safetynet/start.html#verify-compat-check");
            throw new IllegalArgumentException("safetyNetApiKey must be defined!");
        }
    }

    /**
     * Simple interface for handling SafetyNet API response
     */
    public interface SafetyNetWrapperCallback {
        void error(int errorCode, String errorMessage);

        void success(boolean ctsProfileMatch, boolean basicIntegrity);
    }

    /**
     * Call the SafetyNet test to check if this device profile /ROM has passed the CTS test
     *
     * @param context                  used to build and init the GoogleApiClient
     * @param safetyNetWrapperCallback results and error handling
     */
    public void requestTest(@NonNull final Context context, final SafetyNetWrapperCallback safetyNetWrapperCallback) {
        packageName = context.getPackageName();
        callback = safetyNetWrapperCallback;
        apkCertificateDigests = Utils.calcApkCertificateDigests(context, packageName);
        Log.d(TAG, "apkCertificateDigests:" + apkCertificateDigests);
        runSafetyNetTest(context);
    }

    private void runSafetyNetTest(Context context) {
        Log.v(TAG, "running SafetyNet.API Test");
        requestNonce = generateOneTimeRequestNonce();
        requestTimestamp = System.currentTimeMillis();

        SafetyNet.getClient(context).attest(requestNonce, googleDeviceVerificationApiKey)
                .addOnSuccessListener(new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
                    @Override
                    public void onSuccess(SafetyNetApi.AttestationResponse attestationResponse) {
                        final String jwsResult = attestationResponse.getJwsResult();

                        final SafetyNetResponse response = parseJsonWebSignature(jwsResult);
                        lastResponse = response;

                        //only need to validate the response if it says we pass
                        if (!response.isCtsProfileMatch() || !response.isBasicIntegrity()) {
                            callback.success(response.isCtsProfileMatch(), response.isBasicIntegrity());
                            return;
                        } else {
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
                                                callback.success(response.isCtsProfileMatch(), response.isBasicIntegrity());
                                            } else {
                                                callback.error(RESPONSE_FAILED_SIGNATURE_VALIDATION, "Response signature invalid");

                                            }
                                        }
                                    });
                                } else {
                                    Log.w(TAG, "No google Device Verification ApiKey defined");
                                    callback.error(RESPONSE_FAILED_SIGNATURE_VALIDATION_NO_API_KEY, "No Google Device Verification ApiKey defined. Marking as failed. SafetyNet CtsProfileMatch: " + response.isCtsProfileMatch());
                                }
                            } else {
                                callback.error(RESPONSE_VALIDATION_FAILED, "Response payload validation failed");
                            }
                        }
                    }
                })
                .addOnFailureListener(new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception e) {
                        if (e instanceof ApiException) {
                            ApiException apiException = (ApiException) e;
                            callback.error(RESPONSE_VALIDATION_FAILED, "ApiException[" + apiException.getStatusCode() + "] " + apiException.getMessage());
                        } else {
                            Log.d(TAG, "Error: " + e.getMessage());
                            callback.error(RESPONSE_VALIDATION_FAILED, "Response payload validation failed");
                        }
                    }
                });
    }




    /**
     * Gets the previous successful call to the safetynetAPI - this is mainly for debug purposes.
     *
     * @return
     */
    public SafetyNetResponse getLastResponse() {
        return lastResponse;
    }

    private boolean validateSafetyNetResponsePayload(SafetyNetResponse response) {
        if (response == null) {
            Log.e(TAG, "SafetyNetResponse is null.");
            return false;
        }

        //check the request nonce is matched in the response
        final String requestNonceBase64 = Base64.encodeToString(requestNonce, Base64.DEFAULT).trim();

        if (!requestNonceBase64.equals(response.getNonce())) {
            Log.e(TAG, "invalid nonce, expected = \"" + requestNonceBase64 + "\"");
            Log.e(TAG, "invalid nonce, response   = \"" + response.getNonce() + "\"");
            return false;
        }

        if (!packageName.equalsIgnoreCase(response.getApkPackageName())) {
            Log.e(TAG, "invalid packageName, expected = \"" + packageName + "\"");
            Log.e(TAG, "invalid packageName, response = \"" + response.getApkPackageName() + "\"");
            return false;
        }

        long durationOfReq = response.getTimestampMs() - requestTimestamp;
        if (durationOfReq > MAX_TIMESTAMP_DURATION) {
            Log.e(TAG, "Duration calculated from the timestamp of response \"" + durationOfReq + " \" exceeds permitted duration of \"" + MAX_TIMESTAMP_DURATION + "\"");
            return false;
        }

        if (!Arrays.equals(apkCertificateDigests.toArray(), response.getApkCertificateDigestSha256())) {
            Log.e(TAG, "invalid apkCertificateDigest, local/expected = " + Arrays.asList(apkCertificateDigests));
            Log.e(TAG, "invalid apkCertificateDigest, response = " + Arrays.asList(response.getApkCertificateDigestSha256()));
            return false;
        }

        return true;
    }

    @Nullable
    private SafetyNetResponse parseJsonWebSignature(String jwsResult) {
        if (jwsResult == null) {
            return null;
        }
        //the JWT (JSON WEB TOKEN) is just a 3 base64 encoded parts concatenated by a . character
        final String[] jwtParts = jwsResult.split("\\.");

        if (jwtParts.length == 3) {
            //we're only really interested in the body/payload
            String decodedPayload = new String(Base64.decode(jwtParts[1], Base64.DEFAULT));

            return SafetyNetResponse.parse(decodedPayload);
        } else {
            return null;
        }
    }


    private byte[] generateOneTimeRequestNonce() {
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

}
