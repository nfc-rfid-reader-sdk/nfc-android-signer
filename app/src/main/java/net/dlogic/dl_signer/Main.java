package net.dlogic.dl_signer;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import net.dlogic.dialogs.FileOperation;
import net.dlogic.dialogs.FileSelector;
import net.dlogic.dialogs.OnHandleFileListener;
import net.dlogic.dl_signer_nfc.DLSignerListener;
import net.dlogic.dl_signer_nfc.DLSignerNfc;
import net.dlogic.util.StringUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import java.nio.charset.Charset;
import java.security.MessageDigest;

/**
 * Created by d-logic on 12.02.2019.
 */

public class Main extends Activity {
    Context context;
    Button btnChooseFile;
    Button btnGetSignature;
    Button btnSaveSignature;
    TextView txtSiteUrl;
    EditText ebUserPin;
    EditText ebFile;
    EditText ebDigest;
    EditText ebSignature;
    Spinner spnDigestAlgorithm;
    Spinner spnCipherAlgorithm;
    Spinner spnKeyIndexes;

    private String[] mStrDigestAlgorithms;
    private byte mCipherAlg = 0; // 0 => RSA; 1 => ECDSA
    private byte mDigestAlg = 2; // 0 => SHA1; 1 => SHA-224; 2 => SHA-256; 3 => SHA-384; 4 => SHA-512
    private byte mKeyIdx = 0; // default key index in card

    ProgressDialog mProgressDialog;
    ProgressDialog mSpinnerDialog;

    DLSignerNfc mDLSignerNfc;
    byte[] mDigest;
    byte[] mSignature;

    static Resources res;
    static int[] authModes;
    private static final int FILE_SELECT_CODE = 0;
    final private static int REQUEST_CODE_ASK_PERMISSIONS = 301;
    private static final int DIALOG_HASH_PROGRESS = 0xAA55AA50;
    private static final int DIALOG_WAITING_FOR_SIGNATURE = 0xAA55AA51;
    private static final int DIGEST_CHUNK_SIZE = 1024 * 16; // 16 KB
    private static final int PROGRESS_SCALE = 100;
    public static final String LOG_TAG = "DL Signer Log";

    private Uri mInputFileUri = null;

    @Override
    protected void onPause() {
        DLSignerNfc.callOnPause(this);
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        DLSignerNfc.callOnResume(this);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        context = this;
        DLSignerNfc.getInstance(this);

        // Get arrays from resources:
        res = getResources();
        authModes = res.getIntArray(R.array.authentication_mode_values);

        // Get references to UI widgets:
        txtSiteUrl = findViewById(R.id.siteLogo);

        txtSiteUrl.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Uri siteUri = Uri.parse("http://" + getResources().getString(R.string.site_url));
                Intent browserIntent = new Intent(Intent.ACTION_VIEW, siteUri);

                startActivity(browserIntent);
            }
        });

        ebUserPin = findViewById(R.id.ebUserPin);
        ebFile = findViewById(R.id.ebFile);
        ebFile.setInputType(0);
        ebDigest = findViewById(R.id.ebDigest);
        ebDigest.setInputType(0);
        ebSignature = findViewById(R.id.ebSignature);
        ebSignature.setInputType(0);

        spnCipherAlgorithm = findViewById(R.id.spnCipherAlgorithm);
        ArrayAdapter<CharSequence> spnAuthenticationAdapter = ArrayAdapter.createFromResource(context,
                R.array.cipher_algorithms,
                R.layout.dl_spinner_textview);
        spnAuthenticationAdapter.setDropDownViewResource(R.layout.dl_spinner_textview);
        spnCipherAlgorithm.setAdapter(spnAuthenticationAdapter);
        spnCipherAlgorithm.setSelection(mCipherAlg);

        spnCipherAlgorithm.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                mCipherAlg = (byte) (pos & 0xFF);
            }

            public void onNothingSelected(AdapterView<?> parent) { }
        });

        spnDigestAlgorithm = findViewById(R.id.spnDigestAlgorithm);
        ArrayAdapter<CharSequence> spnLightAdapter = ArrayAdapter.createFromResource(context,
                R.array.digest_algorithms,
                R.layout.dl_spinner_textview);
        spnLightAdapter.setDropDownViewResource(R.layout.dl_spinner_textview);
        spnDigestAlgorithm.setAdapter(spnLightAdapter);
        spnDigestAlgorithm.setSelection(mDigestAlg);
        spnDigestAlgorithm.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                mDigestAlg = (byte) (pos & 0xFF);
            }

            public void onNothingSelected(AdapterView<?> parent) { }
        });

        spnKeyIndexes = findViewById(R.id.spnKeyIndexes);
        ArrayAdapter<CharSequence> spnBeepAdapter = ArrayAdapter.createFromResource(context,
                R.array.key_indexes,
                R.layout.dl_spinner_textview);
        spnBeepAdapter.setDropDownViewResource(R.layout.dl_spinner_textview);
        spnKeyIndexes.setAdapter(spnBeepAdapter);
        spnKeyIndexes.setSelection(mKeyIdx);
        spnKeyIndexes.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                mKeyIdx = (byte) (pos & 0xFF);
            }

            public void onNothingSelected(AdapterView<?> parent) { }
        });

        mStrDigestAlgorithms = res.getStringArray(R.array.digest_algorithms);

        btnChooseFile = findViewById(R.id.btnChooseFile);
        btnGetSignature = findViewById(R.id.btnGetSignature);
        btnSaveSignature = findViewById(R.id.btnSaveSignature);

        btnChooseFile.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                if (Build.VERSION.SDK_INT >= 23) {
                    int hasWriteContactsPermission = checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE);

                    if (hasWriteContactsPermission != PackageManager.PERMISSION_GRANTED) {

                        if (!shouldShowRequestPermissionRationale(Manifest.permission.WRITE_CONTACTS)) {
                            showMessageOKCancel("You need to allow access to external storage",
                                    new DialogInterface.OnClickListener() {
                                        @Override
                                        public void onClick(DialogInterface dialog, int which) {
                                            requestPermissions(new String[] {Manifest.permission.READ_EXTERNAL_STORAGE},
                                                    REQUEST_CODE_ASK_PERMISSIONS);
                                        }
                                    });
                            return;
                        }

                        requestPermissions(new String[] {Manifest.permission.READ_EXTERNAL_STORAGE}, REQUEST_CODE_ASK_PERMISSIONS);
                        return;
                    }
                }

                showFileChooser();
            }
        });

        btnGetSignature.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                signFile();
            }
        });

        btnSaveSignature.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                if (mSignature == null) {
                    Toast.makeText(Main.this, "First sign the file", Toast.LENGTH_LONG).show();
                    return;
                }

                final String[] mFileFilter = { "*.*", ".bin", ".sgn"};

                new FileSelector(Main.this, FileOperation.SAVE, new OnHandleFileListener() {
                    @Override
                    public void handleFile(final String filePath) {

                        FileOutputStream f;
                        try {
                            f = new FileOutputStream(filePath);
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                            Toast.makeText(Main.this, "Failed to save: " + filePath, Toast.LENGTH_LONG).show();
                            return;
                        }

                        try {
                            f.write(mSignature);
                        } catch (IOException e) {
                            e.printStackTrace();
                            Toast.makeText(Main.this, "Failed to save: " + filePath, Toast.LENGTH_LONG).show();
                            return;
                        } finally {
                            try {
                                f.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }

                        Toast.makeText(Main.this, "Successfully saved: " + filePath, Toast.LENGTH_LONG).show();
                    }
                }

                , mFileFilter).show();

            }
        });

        mDLSignerNfc.addListener(new DLSignerListener() {
            @Override
            public void signatureFinished(Boolean success, byte[] result, String... messages) {
                if (success) {

                    mSignature = result.clone();
                    ebSignature.setText(Base64.encodeToString(mSignature, Base64.DEFAULT));
                    Audio.Notify();
                    Toast.makeText(context, "Operation was successful", Toast.LENGTH_SHORT).show();

                } else {
                    Toast.makeText(context, messages[0], Toast.LENGTH_LONG).show();
                }
                dismissDialog(DIALOG_WAITING_FOR_SIGNATURE);
            }
            @Override
            public void certReadFinished(Boolean success, byte[] result, String... messages) {
                if (success) {

                } else {
                    Toast.makeText(context, messages[0], Toast.LENGTH_LONG).show();
                }
            }
        });
    }

    private void showMessageOKCancel(String message, DialogInterface.OnClickListener okListener) {
        new AlertDialog.Builder(this)
                .setMessage(message)
                .setPositiveButton("OK", okListener)
                .setNegativeButton("Cancel", null)
                .create()
                .show();
    }

    // Progress bar settings:
    @Override
    protected Dialog onCreateDialog(int id) {
        switch (id) {
            case DIALOG_HASH_PROGRESS:
                mProgressDialog = new ProgressDialog(this);
                mProgressDialog.setMessage("Hashing file...");
                mProgressDialog.setIndeterminate(false);
                mProgressDialog.setMax(PROGRESS_SCALE);
                mProgressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
                mProgressDialog.setCancelable(false);
                mProgressDialog.setProgressNumberFormat(null);
                mProgressDialog.show();
                return mProgressDialog;
            case DIALOG_WAITING_FOR_SIGNATURE:
                mSpinnerDialog = new ProgressDialog(this);
                mSpinnerDialog.setMessage("Tap an DL Signer card to sign...");
                mSpinnerDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
                mSpinnerDialog.setCancelable(false);
                mSpinnerDialog.show();
                return mSpinnerDialog;
            default:
                return null;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        String str;

        if (resultCode == Activity.RESULT_OK) {
            if (data != null) {
                Uri tempUri = data.getData();
//            str = mInputFileUri.toString().replace("%2F", "/").replace("%3A", ":").replace("%20", " ");
                str = StringUtil.getFileName(this, tempUri);
                if (!str.equals("")) {
                    mInputFileUri = tempUri;
                    ebFile.setText(str);
                    mDigest = null;
                    ebDigest.setText("");
                    mSignature = null;
                    ebSignature.setText("");
                } else {
                    mInputFileUri = null;
                    ebFile.setText("");
                    mDigest = null;
                    ebDigest.setText("");
                    mSignature = null;
                    ebSignature.setText("");
                }
            }
        }

        super.onActivityResult(requestCode, resultCode, data);
    }

    private void showFileChooser() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);

        try {
            startActivityForResult(Intent.createChooser(intent, "Select a File to Sign"), FILE_SELECT_CODE);

        } catch (android.content.ActivityNotFoundException ex) {
            // Potentially direct the user to the Market with a Dialog
            Toast.makeText(this, "Please install a File Manager.", Toast.LENGTH_SHORT).show();
        }
    }

    private void signFile() {

        if (mInputFileUri == null) {
            Toast.makeText(this, "Please choose a file to sign", Toast.LENGTH_LONG).show();
            return;
        }

        FileInputStream fis;

        try {
            fis = (FileInputStream) getContentResolver().openInputStream(mInputFileUri);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            Toast.makeText(this, "File not found", Toast.LENGTH_LONG).show();
            return;
        }

        new HashFile().execute(fis);
    }

    class HashFile extends AsyncTask<FileInputStream, Integer, Boolean> {

        @Override
        protected void onPreExecute() {
            showDialog(DIALOG_HASH_PROGRESS);
        }

        @Override
        protected Boolean doInBackground(FileInputStream... files) {

            if (mDigest == null) {
                try {

                    MessageDigest md = MessageDigest.getInstance(mStrDigestAlgorithms[mDigestAlg]);
                    FileInputStream in = files[0]; // new FileInputStream(files[0]);
                    float flen = (float) files[0].getChannel().size(); //.length();
                    float fprogress = (float) 0;
                    Integer progress;

                    byte[] buff = new byte[DIGEST_CHUNK_SIZE];
                    int len;
                    while ((len = in.read(buff, 0, DIGEST_CHUNK_SIZE)) != -1) {
                        md.update(buff, 0 , len);
                        fprogress += DIGEST_CHUNK_SIZE;
                        progress = (int) (fprogress * PROGRESS_SCALE / flen);
                        publishProgress(progress);
                    }

                    mDigest = md.digest();

                } catch (Exception e) {
                    Log.d(LOG_TAG, e.getMessage());
                    return false;
                }
            }

            return true;
        }

        @Override
        protected void onProgressUpdate(Integer... progress) {
            mProgressDialog.setProgress(progress[0]);
        }

        @Override
        protected void onPostExecute(Boolean success) {
            //findViewById(R.id.waitingPanel).setVisibility(View.GONE);
            dismissDialog(DIALOG_HASH_PROGRESS);

            if (!success)
                mDigest = null;
            else {

                ebDigest.setText(Base64.encodeToString(mDigest, Base64.DEFAULT));
                byte[] pin = ebUserPin.getText().toString().getBytes(Charset.forName("US-ASCII"));

                showDialog(DIALOG_WAITING_FOR_SIGNATURE);
                DLSignerNfc.signInitiate(pin, mCipherAlg, mDigestAlg, mKeyIdx, mDigest);
            }
        }
    }
}
