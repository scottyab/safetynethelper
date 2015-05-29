package com.scottyab.sateynet.sample;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.scottyab.safetynet.SafetyNetHelper;
import com.scottyab.safetynet.sample.BuildConfig;
import com.scottyab.safetynet.sample.R;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class MainActivity extends ActionBarActivity {

    private static final String TAG = "SafetyNetHelperSAMPLE";
    private TextView resultsTV;


    //REPLACE with your own!!
    private static final String API_KEY = BuildConfig.GOOGLE_VERIFICATION_API_KEY;
    private View loading;
    private AlertDialog infoDialog;

    final SafetyNetHelper safetyNetHelper = new SafetyNetHelper(API_KEY);


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.d(TAG, "AndroidAPIKEY: " + getSigningKeyFingerprint(this) + ";" + getPackageName());

        resultsTV = (TextView)findViewById(R.id.results);
        loading = findViewById(R.id.loading);

        findViewById(R.id.runTestButton).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runTest();
            }
        });

        if(ConnectionResult.SUCCESS != GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)){
            resultsTV.setText("GooglePlayServices is not availible on this device.\n\nThis SafetyNet test will not work");
        }
    }

    private void runTest() {

        loading.setVisibility(View.VISIBLE);

        Log.d(TAG, "SafetyNet start request");
         safetyNetHelper.requestTest(this, new SafetyNetHelper.SafetyNetWrapperCallback() {
             @Override
             public void error(int errorCode, String s) {
                 Log.e(TAG, s);
                 resultsTV.setText(s);
                 loading.setVisibility(View.GONE);
             }

             @Override
             public void success(boolean ctsProfileMatch) {
                 Log.d(TAG, "SafetyNet req success: ctsProfileMatch:" + ctsProfileMatch);
                 resultsTV.setText("SafetyNet request and validation success: \n\n" + safetyNetHelper.getLastResponse().toString());
                 loading.setVisibility(View.GONE);
             }
         });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_info) {
            showInfoDialog();
            return true;
        }else if (id == R.id.action_sharee){
            shareTestResults();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private void shareTestResults() {
        if (safetyNetHelper.getLastResponse() != null){
            String body = "SafetyNet request and validation success: \n\n" + safetyNetHelper.getLastResponse().toString();
            Intent shareIntent = newEmailIntent(null, getString(R.string.app_name) + " " + getAppVersion(), body, false);
            startActivity(Intent.createChooser(shareIntent, "Share via..."));
        }else{
            Toast.makeText(this, "No tests results to share", Toast.LENGTH_SHORT).show();
        }
    }

    private void showInfoDialog() {
        if(infoDialog!=null && infoDialog.isShowing()){
            //do nothing if already showing
        }else {
            infoDialog = new AlertDialog.Builder(this)
                    .setTitle(R.string.app_name)
                    .setMessage(R.string.info_details)
                    .setCancelable(true)
                    .setPositiveButton("ok", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    })
                    .create();
            infoDialog.show();
        }
    }


    //util methods

    public static final String MIME_TYPE_EMAIL = "message/rfc822";

    public static Intent newEmailIntent(final String address, final String subject, final String body,
                                        boolean useEmailMime) {
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.putExtra(Intent.EXTRA_EMAIL, new String[] { address });
        intent.putExtra(Intent.EXTRA_TEXT, body);
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET);
        if (useEmailMime) {
            intent.setType(MIME_TYPE_EMAIL);
        }else{
            intent.setType("text/*");
        }


        return intent;
    }


    public static String getSigningKeyFingerprint(Context ctx) {
        String result = null;
        try {
            PackageManager pm = ctx.getPackageManager();
            String packageName = ctx.getPackageName();
            int flags = PackageManager.GET_SIGNATURES;
            PackageInfo packageInfo = pm.getPackageInfo(packageName, flags);
            Signature[] signatures = packageInfo.signatures;
            byte[] cert = signatures[0].toByteArray();
            InputStream input = new ByteArrayInputStream(cert);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate c = (X509Certificate) cf.generateCertificate(input);
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] publicKey = md.digest(c.getEncoded());
            result = byte2HexFormatted(publicKey);
        } catch (Exception e) {
            Log.w(TAG, e);
        }
        return result;
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

    private String getAppVersion() {
        String versionName = null;
        int versionCode = -1;
        try {
            PackageInfo pInfo = getPackageManager().getPackageInfo(
                    getPackageName(), 0);
            versionName = pInfo.versionName;
            versionCode = pInfo.versionCode;
        } catch (PackageManager.NameNotFoundException ex) {
            versionName = null;
        }
        return getString(R.string.about_version, versionName, versionCode);
    }

}
