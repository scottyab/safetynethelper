package com.scottyab.safetynet;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;

/**
 * Useful but separate utils used by the safetynet helper
 */
public class Utils {


    private static final String TAG = Utils.class.getSimpleName();

    /**
     * Created SHA256 of input
     * @param input (assumes UTF-8 string)
     * @return
     */
    public static byte[] hash(String input){
        if(!TextUtils.isEmpty(input)) {
            try {
                byte[] inputBytes = input.getBytes("UTF-8");
                return hash(inputBytes);
            } catch (UnsupportedEncodingException e) {
                Log.e(TAG, "problem hashing \"" + input + "\" " + e.getMessage(), e);
            }
        }
        return null;
    }

    /**
     * Created SHA256 of input
     * @param input
     * @return
     */
    public static byte[] hash(byte[] input){
        if(input!=null) {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
                byte[] hashedBytes = input;
                digest.update(hashedBytes, 0, hashedBytes.length);
                return hashedBytes;
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "problem hashing \"" + input + "\" " + e.getMessage(), e);
            }
        }else{
            Log.w(TAG, "hash called with null input byte[]");
        }
        return null;
    }

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
     * Gets the encoded representation of the first signing cerificated used to sign current APK
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

            if(signatures!=null && signatures.length>=1) {
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
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signature.toByteArray());
                byte[] digest = md.digest();
                encodedSignatures.add(Base64.encodeToString(digest, Base64.NO_WRAP));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return encodedSignatures;
    }

    public static String calcApkDigest(final Context context) {
        byte[] hashed2 = getApkFileDigest(context);
        String encoded2 = Base64.encodeToString(hashed2, Base64.NO_WRAP);
        return encoded2;
    }

    private static long getApkFileChecksum(Context context) {
        String apkPath = context.getPackageCodePath();
        Long chksum = null;
        try {
            // Open the file and build a CRC32 checksum.
            FileInputStream fis = new FileInputStream(new File(apkPath));
            CRC32 chk = new CRC32();
            CheckedInputStream cis = new CheckedInputStream(fis, chk);
            byte[] buff = new byte[80];
            while (cis.read(buff) >= 0) ;
            chksum = chk.getValue();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return chksum;
    }


    private static byte[] getApkFileDigest(Context context) {
        String apkPath = context.getPackageCodePath();
        try {
            return getDigest(new FileInputStream(apkPath), "SHA-256");
        } catch (Throwable throwable) {
            throwable.printStackTrace();
        }
        return null;
    }

    public static final int BUFFER_SIZE = 2048;

    public static byte[] getDigest(InputStream in, String algorithm) throws Throwable {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        try {
            DigestInputStream dis = new DigestInputStream(in, md);
            byte[] buffer = new byte[BUFFER_SIZE];
            while (dis.read(buffer) != -1) {
                //
            }
            dis.close();
        } finally {
            in.close();
        }
        return md.digest();
    }


}
