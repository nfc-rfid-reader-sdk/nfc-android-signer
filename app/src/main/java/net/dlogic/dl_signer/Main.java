package net.dlogic.dl_signer;

import android.app.Activity;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import android.os.AsyncTask;
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

import net.dlogic.dl_signer_nfc.DLSignerListener;
import net.dlogic.dl_signer_nfc.DLSignerNfc;
import net.dlogic.ufr.block_read.R;
import net.dlogic.util.StringUtil;

import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.DigestInfo;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.*;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.w3c.dom.*;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;

/**
 * Created by d-logic on 15.5.2015..
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
    private byte mPaddingAlg = 0; // 0 => None; 1 => PKCS1
    private byte mDigestAlg = 2; // 0 => SHA1; 1 => SHA-224; 2 => SHA-256; 3 => SHA-384; 4 => SHA-512
    private byte mKeyIdx = 0; // default key index in card

    static ProgressDialog mProgressDialog;
    DLSignerNfc mDLSignerNfc;
    byte[] mDigest;
    byte[] mSign;

    static Resources res;
    static int[] authModes;
    private static final int FILE_SELECT_CODE = 0;
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
                Toast.makeText(context, "Not implemented yet", Toast.LENGTH_SHORT).show();
            }
        });

        mDLSignerNfc.addListener(new DLSignerListener() {
            @Override
            public void finished(Boolean success, byte[] result, String... messages) {
                if (success) {
                    Audio.Notify();
                    Toast.makeText(context, "Operation was successful", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(context, messages[0], Toast.LENGTH_LONG).show();
                }
                dismissDialog(DIALOG_WAITING_FOR_SIGNATURE);
            }
        });
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
                mProgressDialog = new ProgressDialog(this);
                mProgressDialog.setMessage("Tap an DL Signer card to sign...");
                mProgressDialog.setProgressStyle(ProgressDialog.STYLE_SPINNER);
                mProgressDialog.setCancelable(false);
                mProgressDialog.show();
                return mProgressDialog;
            default:
                return null;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        String str;

        if (data != null) {
            Uri tempUri = data.getData();
//            str = mInputFileUri.toString().replace("%2F", "/").replace("%3A", ":").replace("%20", " ");
            str = StringUtil.getFileName(this, tempUri);
            if (!str.equals("")) {
                mInputFileUri = tempUri;
                ebFile.setText(str);
            }
        }

        super.onActivityResult(requestCode, resultCode, data);
    }

    private void showFileChooser() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);

        try {
            startActivityForResult(
                    Intent.createChooser(intent, "Select a File to Sign"), FILE_SELECT_CODE);
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

        new HashFile().execute(new File(mInputFileUri.getPath()));

        /*
        InputStream is = null;

        ContentResolver cr = getContentResolver();


        byte[] plain = {1,2,3,4,5,6,7,8,9,10};


        try {
                is = cr.openInputStream(mInputFileUri);
//                XMLVerify.verifySignature(is);
                int av = is.available();
                int x = av + 1;


        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (is != null)
                try {
                    is.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
        */
    }

    class HashFile extends AsyncTask<File, Integer, Boolean> {

        @Override
        protected void onPreExecute() {
            showDialog(DIALOG_HASH_PROGRESS);
        }

        @Override
        protected Boolean doInBackground(File... files) {

            try {

                MessageDigest md = MessageDigest.getInstance(mStrDigestAlgorithms[mDigestAlg]);
                FileInputStream in = new FileInputStream(files[0]);
                float flen = (float) files[0].length();
                float fprogress = (float) 0;
                Integer progress;

                byte [] buff = new byte[DIGEST_CHUNK_SIZE];
                while (in.read(buff, 0, DIGEST_CHUNK_SIZE) != -1)
                {
                    md.update(buff);
                    fprogress += DIGEST_CHUNK_SIZE;
                    progress = (int) (fprogress * PROGRESS_SCALE / flen);
                    publishProgress(progress);
                }


                mDigest = md.digest();
                publishProgress(1);

            } catch (Exception e) {
                Log.d(LOG_TAG, e.getMessage());
                return false;
            }

            return true;
        }

        @Override
        protected void onProgressUpdate(Integer... progress) {
            mProgressDialog.setProgress(progress[0]);
        }

        @Override
        protected void onPostExecute(Boolean success) {
            ASN1ObjectIdentifier mOid = null;
            byte jc_signer_digest;

            //findViewById(R.id.waitingPanel).setVisibility(View.GONE);
            dismissDialog(DIALOG_HASH_PROGRESS);

            if (!success)
                mDigest = null;
            else {
                try {

                    ebDigest.setText(Base64.encodeToString(mDigest, Base64.DEFAULT));

                    switch (mDigestAlg) {
                        case 0: // "None":
                            jc_signer_digest = DLSignerNfc.JCDLSignerDigests.ALG_NULL;
                            mOid = null;
                            break;
                        case 1: // "SHA-1":
                            jc_signer_digest = DLSignerNfc.JCDLSignerDigests.ALG_SHA;
                            mOid = OIWObjectIdentifiers.idSHA1;
                            break;
                        case 2: // "SHA-224":
                            jc_signer_digest = DLSignerNfc.JCDLSignerDigests.ALG_SHA_224;
                            mOid = NISTObjectIdentifiers.id_sha224;
                            break;
                        case 3: // "SHA-256":
                            jc_signer_digest = DLSignerNfc.JCDLSignerDigests.ALG_SHA_256;
                            mOid = NISTObjectIdentifiers.id_sha256;
                            break;
                        case 4: // "SHA-384":
                            jc_signer_digest = DLSignerNfc.JCDLSignerDigests.ALG_SHA_384;
                            mOid = NISTObjectIdentifiers.id_sha384;
                            break;
                        case 5: // "SHA-512":
                            jc_signer_digest = DLSignerNfc.JCDLSignerDigests.ALG_SHA_512;
                            mOid = NISTObjectIdentifiers.id_sha512;
                    }

                    DigestInfo dInfo = new DigestInfo(new AlgorithmIdentifier(mOid, DERNull.INSTANCE), mDigest);
                    mDigest = dInfo.getEncoded();



                    byte[] pin = ebUserPin.getText().toString().getBytes(Charset.forName("US-ASCII"));
                    if (mCipherAlg == 0)
                        mPaddingAlg = 1; // PKCS1 padding is only supported for RSA
                    else
                        mPaddingAlg = 0; // PaddingNone otherwise

                    showDialog(DIALOG_WAITING_FOR_SIGNATURE);
                    DLSignerNfc.signInitiate(pin, mCipherAlg, mPaddingAlg, mKeyIdx, mDigest);

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static class XMLVerify {
        void XMLVerify() {}

        static {
            org.apache.xml.security.Init.init();
        }

        static boolean verifySignature(InputStream in) {
            boolean valid = false;
            try {
                // parse the XML
                DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
                f.setNamespaceAware(true);
                Document doc = f.newDocumentBuilder().parse(in);
                in.close();

                // verify signature
                NodeList nodes = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
                if (nodes.getLength() == 0) {
                    throw new Exception("Signature NOT found!");
                }

                Element sigElement = (Element) nodes.item(0);
                XMLSignature signature = new XMLSignature(sigElement, "");

                KeyInfo ki = signature.getKeyInfo();
                if (ki == null) {
                    throw new Exception("Did not find KeyInfo");
                }

                X509Certificate cert = signature.getKeyInfo().getX509Certificate();
                if (cert == null) {
                    PublicKey pk = signature.getKeyInfo().getPublicKey();
                    if (pk == null) {
                        throw new Exception("Did not find Certificate or Public Key");
                    }
                    org.apache.xml.security.signature.SignedInfo var2 = signature.getSignedInfo();
                    valid = signature.checkSignatureValue(pk);
                }
                else {
                    valid = signature.checkSignatureValue(cert);
                }
            }
            catch (Exception e) {
                e.printStackTrace();
            }

            return valid;
        }
    }
}