package com.scottyab.safetynet;

import android.util.Base64;
import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Custom TrustManager to use SSL public key Pinning to verify connections to www.googleapis.com
 */
public class GoogleApisTrustManager implements X509TrustManager {

    //good candidate for DexGuard string encryption. Generated with https://github.com/scottyab/ssl-pin-generator
    private final static String[] GOOGLEAPIS_COM_PINS = new String[]{
            "sha1/f2QjSla9GtnwpqhqreDLIkQNFu8=",
            "sha1/Q9rWMO5T+KmAym79hfRqo3mQ4Oo=",
            "sha1/wHqYaI2J+6sFZAwRfap9ZbjKzE4="};

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        //NOT IMP

    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // validate all the GOOGLEAPIS_COM_PINS
        for (X509Certificate cert : chain) {
            final boolean expected = validateCertificatePin(cert);
            if (!expected) {
                throw new CertificateException("could not find a valid SSL public key pin for www.googleapis.com");
            }
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    private boolean validateCertificatePin(X509Certificate certificate)
            throws CertificateException {

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }


        final byte[] pubKeyInfo = certificate.getPublicKey().getEncoded();
        final byte[] pin = digest.digest(pubKeyInfo);
        final String pinAsBase64 = "sha1/" + Base64.encodeToString(pin, Base64.DEFAULT);
        for (String validPin : GOOGLEAPIS_COM_PINS) {
            if (validPin.equalsIgnoreCase(pinAsBase64)) {
                return true;
            }
        }
        return false;
    }
}
