package com.scottyab.sateynet.sample;

import android.animation.Animator;
import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.annotation.TargetApi;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewAnimationUtils;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.scottyab.safetynet.SafetyNetHelper;
import com.scottyab.safetynet.SafetyNetResponse;
import com.scottyab.safetynet.Utils;
import com.scottyab.safetynet.sample.BuildConfig;
import com.scottyab.safetynet.sample.R;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import android.content.pm.PackageManager;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SafetyNetHelperSAMPLE";

    //*** REPLACE with your own!! ***
    private static final String API_KEY = BuildConfig.GOOGLE_VERIFICATION_API_KEY;
    private View loading;
    private AlertDialog infoDialog;

    final SafetyNetHelper safetyNetHelper = new SafetyNetHelper(API_KEY);

    private TextView resultsTV;
    private TextView nonceTV;
    private TextView timestampTV;
    private View resultsContainer;
    private ImageView resultsIcon;
    private boolean hasAnimated =false;
    private View sucessResultsContainer;
    private TextView packagenameTV;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.d(TAG, "AndroidAPIKEY: " + Utils.getSigningKeyFingerprint(this) + ";" + getPackageName());

        initViews();

        if(ConnectionResult.SUCCESS != GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)){
            handleError(0, "GooglePlayServices is not availible on this device.\n\nThis SafetyNet test will not work");
        }
    }

    private void initViews() {
        resultsTV = (TextView)findViewById(R.id.results);
        nonceTV = (TextView)findViewById(R.id.nonce);
        timestampTV = (TextView)findViewById(R.id.timestamp);
        packagenameTV = (TextView)findViewById(R.id.packagename);
        resultsContainer = findViewById(R.id.resultsContainer);
        sucessResultsContainer = findViewById(R.id.sucessResultsContainer);
        loading = findViewById(R.id.loading);
        resultsIcon = (ImageView) findViewById(R.id.resultIcon);

        findViewById(R.id.runTestButton).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runTest();
            }
        });
    }

    private void runTest() {
        showLoading(true);

        Log.d(TAG, "SafetyNet start request");
         safetyNetHelper.requestTest(this, new SafetyNetHelper.SafetyNetWrapperCallback() {
             @Override
             public void error(int errorCode, String errorMessage) {
                 showLoading(false);
                 handleError(errorCode, errorMessage);
             }

             @Override
             public void success(boolean ctsProfileMatch) {
                 Log.d(TAG, "SafetyNet req success: ctsProfileMatch:" + ctsProfileMatch);
                 showLoading(false);
                 updateUIWithSucessfulResult(safetyNetHelper.getLastResponse());

             }
         });
    }

    private void handleError(int errorCode, String errorMsg) {
        Log.e(TAG, errorMsg);

        StringBuilder b=new StringBuilder();

        switch(errorCode){
            default:
            case SafetyNetHelper.SAFTYNET_API_REQUEST_UNSUCCESSFUL:
                b.append("SafetyNet request: fail\n");
                break;
            case SafetyNetHelper.RESPONSE_ERROR_VALIDATING_SIGNATURE:
                b.append("SafetyNet request: success\n");
                b.append("Response signature validation: error\n");
                break;
            case SafetyNetHelper.RESPONSE_FAILED_SIGNATURE_VALIDATION:
                b.append("SafetyNet request: success\n");
                b.append("Response signature validation: fail\n");
                break;
            case SafetyNetHelper.RESPONSE_VALIDATION_FAILED:
                b.append("SafetyNet request: success\n");
                b.append("Response validation: fail\n");
                break;
            case ConnectionResult.SERVICE_VERSION_UPDATE_REQUIRED:
                b.append("SafetyNet request: fail\n");
                b.append("\n*GooglePlayServices outdated*\n");
                try {
                    int v = getPackageManager().getPackageInfo("com.google.android.gms", 0).versionCode;
                    String vName = getPackageManager().getPackageInfo("com.google.android.gms", 0).versionName.split(" ")[0];
                    b.append("You are running version:\n" + vName + " " + v + "\nSafetyNet requires minimum:\n7.3.27 7327000\n");
                } catch (Exception NameNotFoundException) {
                    b.append("Could not find GooglePlayServices on this device.\nPackage com.google.android.gms missing.");
                }
                break;
        }
        resultsTV.setText(b.toString() + "\nError Msg:\n" + errorMsg);

        resultsIcon.setImageResource(R.drawable.problem);
        sucessResultsContainer.setVisibility(View.GONE);
        revealResults(getResources().getColor(R.color.problem));
    }

    private void showLoading(boolean show) {
        loading.setVisibility(show ? View.VISIBLE : View.GONE);
        if(show) {
            resultsContainer.setBackgroundColor(Color.TRANSPARENT);
            resultsContainer.setVisibility(View.GONE);
        }
    }

    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    private void revealResults(Integer colorTo){
        if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.HONEYCOMB) {
            doPropertyAnimatorReveal(colorTo);
            resultsContainer.setVisibility(View.VISIBLE);
        }else{
            resultsContainer.setVisibility(View.VISIBLE);
        }
    }

    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    private void doPropertyAnimatorReveal(Integer colorTo) {
        Integer colorFrom = Color.TRANSPARENT;
        Drawable background = resultsContainer.getBackground();
        if (background instanceof ColorDrawable){
            colorFrom = ((ColorDrawable) background).getColor();
        }

        ValueAnimator colorAnimation = ValueAnimator.ofObject(new ArgbEvaluator(), colorFrom, colorTo);
        colorAnimation.setDuration(500);
        colorAnimation.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator animator) {
                resultsContainer.setBackgroundColor((Integer) animator.getAnimatedValue());
            }

        });
        colorAnimation.start();
    }

    private void updateUIWithSucessfulResult(SafetyNetResponse safetyNetResponse) {
        resultsTV.setText("SafetyNet request: success \nResponse validation: success\nCTS profile match: "+ (safetyNetResponse.isCtsProfileMatch() ? "true" : "false"));

        sucessResultsContainer.setVisibility(View.VISIBLE);

        nonceTV.setText(safetyNetResponse.getNonce());

        SimpleDateFormat sim = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault());
        Date timeOfResponse = new Date(safetyNetResponse.getTimestampMs());
        timestampTV.setText(sim.format(timeOfResponse));
        packagenameTV.setText(safetyNetResponse.getApkPackageName());

        resultsIcon.setImageResource(safetyNetResponse.isCtsProfileMatch() ? R.drawable.pass : R.drawable.fail);

        revealResults(getResources().getColor(safetyNetResponse.isCtsProfileMatch() ? R.color.pass : R.color.fail));
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
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
        }else if (id == R.id.action_github){
            openGithubProjectPage();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private void shareTestResults() {
        if (safetyNetHelper.getLastResponse() != null){
            String body = safetyNetHelper.getLastResponse().toString();
            Intent shareIntent = newEmailIntent(null, getString(R.string.app_name) + " " + getAppVersion(), body, false);
            startActivity(Intent.createChooser(shareIntent, "Share via..."));
        }else{
            Toast.makeText(this, "No tests results to share", Toast.LENGTH_SHORT).show();
        }
    }

    private void openGithubProjectPage(){
        startActivity(new Intent(Intent.ACTION_VIEW,
                Uri.parse("https://github.com/scottyab/safetynethelper/")));
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
                    .setNegativeButton("More info", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                            startActivity(new Intent(Intent.ACTION_VIEW,
                                    Uri.parse("https://developer.android.com/training/safetynet")));
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
