package com.scottyab.sateynet.sample;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
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

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SafetyNetHelperSAMPLE";

    //*** TODO REPLACE with your own!! ***
    private static final String API_KEY = BuildConfig.GOOGLE_VERIFICATION_API_KEY;
    private View loading;

    private SafetyNetHelper safetyNetHelper;

    private TextView resultsTV;
    private TextView nonceTV;
    private TextView timestampTV;
    private View resultsContainer;
    private ImageView resultsIcon;
    private View successResultsContainer;
    private TextView packageNameTV;
    private TextView resultNoteTV;
    private TextView welcomeTV;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        safetyNetHelper = new SafetyNetHelper(API_KEY);

        Log.d(TAG, "AndroidAPIKEY: " + Utils.getSigningKeyFingerprint(this) + ";" + getPackageName());

        initViews();

        if (ConnectionResult.SUCCESS != GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)) {
            handleError(0, "GooglePlayServices is not available on this device.\n\nThis SafetyNet test will not work");
        }
    }

    private void initViews() {
        welcomeTV = findViewById(R.id.welcomeTV);
        resultsTV = findViewById(R.id.results);
        resultNoteTV = findViewById(R.id.resultsNote);
        nonceTV = findViewById(R.id.nonce);
        timestampTV = findViewById(R.id.timestamp);
        packageNameTV = findViewById(R.id.packagename);
        resultsContainer = findViewById(R.id.resultsContainer);
        successResultsContainer = findViewById(R.id.sucessResultsContainer);
        loading = findViewById(R.id.loading);
        resultsIcon = findViewById(R.id.resultIcon);

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
            public void success(boolean ctsProfileMatch, boolean basicIntegrity) {
                Log.d(TAG, "SafetyNet req success: ctsProfileMatch:" + ctsProfileMatch + " and basicIntegrity, " + basicIntegrity);
                showLoading(false);
                updateUIWithSuccessfulResult(safetyNetHelper.getLastResponse());
            }
        });


    }

    private void handleError(int errorCode, String errorMsg) {
        Log.e(TAG, errorMsg);

        StringBuilder b = new StringBuilder();

        switch (errorCode) {
            default:
            case SafetyNetHelper.SAFETY_NET_API_REQUEST_UNSUCCESSFUL:
                b.append("SafetyNet request failed\n");
                b.append("(This could be a networking issue.)\n");
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
        }
        resultsTV.setText(b.toString());
        resultNoteTV.setText("Error Msg:\n" + errorMsg);

        resultsIcon.setImageResource(R.drawable.problem);
        successResultsContainer.setVisibility(View.GONE);
        welcomeTV.setVisibility(View.GONE);
        revealResults(ContextCompat.getColor(this, R.color.problem));
    }

    private void showLoading(boolean show) {
        loading.setVisibility(show ? View.VISIBLE : View.GONE);
        if (show) {
            resultsContainer.setBackgroundColor(Color.TRANSPARENT);
            resultsContainer.setVisibility(View.GONE);
            welcomeTV.setVisibility(View.GONE);
        }
    }

    private void revealResults(Integer colorTo) {
        doPropertyAnimatorReveal(colorTo);
        resultsContainer.setVisibility(View.VISIBLE);
    }

    private void doPropertyAnimatorReveal(Integer colorTo) {
        Integer colorFrom = Color.TRANSPARENT;
        Drawable background = resultsContainer.getBackground();
        if (background instanceof ColorDrawable) {
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

    private void updateUIWithSuccessfulResult(SafetyNetResponse safetyNetResponse) {
        String advice = safetyNetResponse.getAdvice() == null ? "None availible" : safetyNetResponse.getAdvice();

        resultsTV.setText(getString(R.string.safety_results,
                safetyNetResponse.isCtsProfileMatch(),
                safetyNetResponse.isBasicIntegrity(),
                safetyNetResponse.getEvaluationType(),
                advice));
        resultNoteTV.setText(R.string.safety_results_note);

        successResultsContainer.setVisibility(View.VISIBLE);

        nonceTV.setText(safetyNetResponse.getNonce());

        SimpleDateFormat sim = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault());
        Date timeOfResponse = new Date(safetyNetResponse.getTimestampMs());
        timestampTV.setText(sim.format(timeOfResponse));
        packageNameTV.setText(safetyNetResponse.getApkPackageName());

        resultsIcon.setImageResource(safetyNetResponse.isCtsProfileMatch() ? R.drawable.pass : R.drawable.fail);

        revealResults(ContextCompat.getColor(this, safetyNetResponse.isCtsProfileMatch() ? R.color.pass : R.color.fail));
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
            SampleAppUtils.showInfoDialog(this);
            return true;
        } else if (id == R.id.action_sharee) {
            SampleAppUtils.shareTestResults(this, safetyNetHelper.getLastResponse());
            return true;
        } else if (id == R.id.action_github) {
            SampleAppUtils.openGitHubProjectPage(this);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }


}
