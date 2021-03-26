package com.scottyab.sateynet.sample;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.widget.Toast;
import androidx.appcompat.app.AlertDialog;
import com.scottyab.safetynet.SafetyNetResponse;
import com.scottyab.safetynet.sample.R;

/**
 * extracting some of the boilerplate sample app code from the mainActivity.
 */
public class SampleAppUtils {

    private static final String MIME_TYPE_EMAIL = "message/rfc822";


    static void openGitHubProjectPage(Activity activity) {
        activity.startActivity(new Intent(Intent.ACTION_VIEW,
                Uri.parse("https://github.com/scottyab/safetynethelper/")));
    }

    static void showInfoDialog(final Activity activity) {
        new AlertDialog.Builder(activity)
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
                        activity.startActivity(new Intent(Intent.ACTION_VIEW,
                                Uri.parse("https://developer.android.com/training/safetynet")));
                    }
                })
                .create().show();
    }


    static void shareTestResults(Activity activity, SafetyNetResponse lastResponse) {
        if (lastResponse != null) {
            String body = lastResponse.toString();
            Intent shareIntent = newEmailIntent(null, activity.getString(R.string.app_name) + " " + getAppVersion(activity), body, false);
            activity.startActivity(Intent.createChooser(shareIntent, "Share via..."));
        } else {
            Toast.makeText(activity, "No tests results to share", Toast.LENGTH_SHORT).show();
        }
    }


    private static Intent newEmailIntent(final String address, final String subject, final String body,
                                         boolean useEmailMime) {
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.putExtra(Intent.EXTRA_EMAIL, new String[]{address});
        intent.putExtra(Intent.EXTRA_TEXT, body);
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        if (useEmailMime) {
            intent.setType(MIME_TYPE_EMAIL);
        } else {
            intent.setType("text/*");
        }


        return intent;
    }

    private static String getAppVersion(Context context) {
        String versionName = null;
        int versionCode = -1;
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0);
            versionName = pInfo.versionName;
            versionCode = pInfo.versionCode;
        } catch (PackageManager.NameNotFoundException ex) {
            versionName = null;
        }
        return context.getString(R.string.about_version, versionName, versionCode);
    }


}
