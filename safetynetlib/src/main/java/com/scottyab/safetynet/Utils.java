package com.scottyab.safetynet;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Useful but separate utils used by the safetynet helper
 */
public class Utils {
    private static final String TAG = Utils.class.getSimpleName();
    public static final String SHA_256 = "SHA-256";

    public static String getSigningKeyFingerprint(Context ctx) {
        String result = null;
        try {
            byte[] certEncoded = getSigningKeyCertificate(ctx);
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] publicKey = md.digest(certEncoded);
            result = byte2HexFormatted(publicKey);
        } catch (Exception e) {
            Log.w(TAG, e);
        }
        return result;
    }

    /**
     * Gets the encoded representation of the first signing certificate used to sign current APK
     *
     * @param ctx
     * @return
     */
    private static byte[] getSigningKeyCertificate(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String packageName = ctx.getPackageName();
            int flags = PackageManager.GET_SIGNATURES;
            PackageInfo packageInfo = pm.getPackageInfo(packageName, flags);
            Signature[] signatures = packageInfo.signatures;

            if (signatures != null && signatures.length >= 1) {
                //takes just the first signature, TODO: handle multi signed apks
                byte[] cert = signatures[0].toByteArray();
                InputStream input = new ByteArrayInputStream(cert);
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                X509Certificate c = (X509Certificate) cf.generateCertificate(input);
                return c.getEncoded();

            }
        } catch (Exception e) {
            Log.w(TAG, e);
        }
        return null;
    }

    private static String byte2HexFormatted(byte[] arr) {
        StringBuilder str = new StringBuilder(arr.length * 2);
        for (int i = 0; i < arr.length; i++) {
            String h = Integer.toHexString(arr[i]);
            int l = h.length();
            if (l == 1) h = "0" + h;
            if (l > 2) h = h.substring(l - 2, l);
            str.append(h.toUpperCase());
            if (i < (arr.length - 1)) str.append(':');
        }
        return str.toString();
    }

    public static List<String> calcApkCertificateDigests(Context context, String packageName) {
        List<String> encodedSignatures = new ArrayList<String>();

        // Get signatures from package manager
        PackageManager pm = context.getPackageManager();
        PackageInfo packageInfo;
        try {
            packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return encodedSignatures;
        }
        Signature[] signatures = packageInfo.signatures;

        // Calculate b64 encoded sha256 hash of signatures
        for (Signature signature : signatures) {
            try {
                MessageDigest md = MessageDigest.getInstance(SHA_256);
                md.update(signature.toByteArray());
                byte[] digest = md.digest();
                encodedSignatures.add(Base64.encodeToString(digest, Base64.NO_WRAP));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return encodedSignatures;
    }
}
