package net.dlogic.dl_signer_nfc;

/**
 * Created by dlogic on 12.2.2019.
 *
 * 12.2.2019. class DLSignerNfc v1.0
 *            - Initial support for DLSigner Card Applet version 2.0
 *            - Supported signature generator, off-card hashing method
 */

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.widget.Toast;

import java.io.IOException;
import java.lang.System;
import java.util.ArrayList;
import java.util.List;

import net.dlogic.dl_signer.Audio;
import net.dlogic.util.ArrayUtil;
import net.dlogic.util.Bitwise;
import static android.os.SystemClock.uptimeMillis;

public class DLSignerNfc {
    private static DLSignerNfc instance = null;
    private static List<DLSignerListener> mListeners = new ArrayList<>(); // <DLSignerListener>
    private static NfcAdapter mAdapter;
    private static IsoDep mTag = null;
    private static byte[] mSignature;

    public static DLSignerNfc getInstance(Context context) {

        if (instance == null) {

            mAdapter = NfcAdapter.getDefaultAdapter(context);
            if (mAdapter == null)
                return null;

            instance = new DLSignerNfc();

        }
        return instance;
    }

    public static void callOnResume(Activity context) {

        if (instance != null) {

            if (!mAdapter.isEnabled()) {
                Toast.makeText(context, "Please enable NFC", Toast.LENGTH_LONG).show();
                return;
            }

            /*
            Bundle options = new Bundle();
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 5000);
            //*/

            mAdapter.enableReaderMode(context, new ReaderCallback() {
                        @Override
                        public void onTagDiscovered(Tag tag) {
                            Intent i = new Intent().putExtra(NfcAdapter.EXTRA_TAG, tag);
                            instance.resolveIntent(i);
                        }
                    }, NfcAdapter.FLAG_READER_NFC_A
                            | NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, // | NfcAdapter.FLAG_READER_NFC_B
                    null); // options
        }
    }

    public static void callOnPause(Activity context) {
        mAdapter.disableReaderMode(context);
    }

    public static void addListener(DLSignerListener toAdd) {
        mListeners.add(toAdd);
    }

    private static void callListeners(Boolean success, byte[] result, String... messages) {
        for (DLSignerListener l : mListeners)
            l.finished(success, result, messages);
    }

    private void resolveIntent(Intent intent) {

        if (null != mAdapter) {
            if (intent.hasExtra(NfcAdapter.EXTRA_TAG)) {
                Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                if (tagFromIntent != null) {
                    mTag = IsoDep.get(tagFromIntent);
                    try {

                        mTag.connect();
                        mTag.setTimeout(3000);
                        Audio.Notify();

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    static class AsyncSign extends AsyncTask<Byte[], Void, Boolean> {
        private String Message;
//        private TimeGuard tg = null;

        @Override
        protected void onPreExecute() {
            mSignature = null;
        }

        @Override
        protected Boolean doInBackground(Byte[]... params) {

            try {

                long TimeMarker = uptimeMillis();
                while ((mTag == null) || !mTag.isConnected()) {
                    if (TimeMarker < (uptimeMillis() - Consts.WAIT_CARD_TIMEOUT))
                        throw new DLSignerNfcException("Waiting for card timeout");
                }

//                tg = new TimeGuard(3000);
//                tg.start();

                mSignature = innerSign(ArrayUtil.bytesFromObjects(params[0]),
                        ArrayUtil.bytesFromObjects(params[1])[0],
                        ArrayUtil.bytesFromObjects(params[1])[1],
                        ArrayUtil.bytesFromObjects(params[1])[2], ArrayUtil.bytesFromObjects(params[2]));

//                tg.cancel();
//                tg.join();
//                tg = null;

            } catch (Exception e) { // DLSignerNfcException
                Message = e.getMessage();
                return false;
            } finally {
//                if (tg != null) {
//                    try {
//                        tg.join();
//                    } catch (InterruptedException e) {
//                        e.printStackTrace();
//                    }
//                }
            }

            Message = "Signed successfully";
            return true;
        }

        @Override
        protected void onPostExecute(Boolean success) {
            callListeners(success, mSignature, Message);
        }
    }

    /*/
    private static class TimeGuard extends Thread {
        boolean terminateIt = true;
        int mTimeout;

        TimeGuard(int timeout) {
            mTimeout = timeout;
        }

        public synchronized void cancel() {
            terminateIt = false;
        }

        private synchronized void terminate() {
            if (terminateIt) {
                try {
                    mTag.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        public void run() {

            long TimeMarker = uptimeMillis();
            while (terminateIt && (TimeMarker > (uptimeMillis() - mTimeout)))
                ;
            terminate();
        }
    }
    //*/

    public static void signInitiate(byte[] pin, byte cipherAlg, byte paddingAlg, byte key_index, byte[] plain) {

        Byte[] params = {cipherAlg, paddingAlg, key_index};
        new AsyncSign().execute(ArrayUtil.bytesToObjects(pin), params, ArrayUtil.bytesToObjects(plain));
    }

    private static byte[] innerSign(byte[] pin, byte cipherAlg, byte paddingAlg, byte key_index, byte[] plainText) throws DLSignerNfcException, InterruptedException {

        //byte[] selectResponse =
        apduSelectByAid(Consts.AID);
        //byte DLSignerType = selectResponse[0];
        apduLogin(false, pin);
        return apduGenerateSignature(cipherAlg, paddingAlg, key_index, plainText);
    }

    public static byte[] apduSelectByAid(byte[] aid) throws DLSignerNfcException {
        byte[] sw = new byte[2];

        byte[] rapdu = transceiveAPDU(Consts.CLA_ISO, (byte) 0xA4, (byte) 4, (byte) 0, aid, (short) 16, true, sw);

        if (Bitwise.bytesToShortBE(sw) != (short) 0x9000)
            throw new DLSignerNfcException("APDU Error: " + getApduError(sw));

        if (rapdu.length != 16)
            throw new DLSignerNfcException("Unsupported card");

        return rapdu;
    }

    public static void apduLogin(boolean itIsSO, byte[] pin) throws DLSignerNfcException {
        byte p1 = itIsSO ? (byte) 1 : (byte) 0;
        byte p2 = 0;
        byte[] sw = new byte[2];

        //byte[] rapdu =
        transceiveAPDU(Consts.CLA_DEFAULT, Consts.INS_LOGIN, p1, p2, pin, (short) 0, false, sw);

        short StatusWordBE = Bitwise.bytesToShortBE(sw);
        if (StatusWordBE != (short) 0x9000) {
            String err_msg;
            if ((StatusWordBE & Consts.SW_WRONG_PIN_MASK) == Consts.SW_WRONG_PIN_MASK) {
                // Wrong PIN => in lower nibble of the sw[1] is the count of the remaining tries
                err_msg = "wrong User PIN, " + (sw[1] & 0x0F) + " tries remaining";
            } else {
                err_msg = "APDU Error: " + getApduError(sw);
            }
            throw new DLSignerNfcException(err_msg);
        }
    }

    public static byte[] apduGenerateSignature(byte cipherAlg, byte paddingAlg, byte key_index,
                                               byte[] plainText) throws DLSignerNfcException {
        byte p1 = 0, p2 = 0;
        byte[] sw = new byte[2];

        p1 |= 0x80; // last chunk flag
        p1 |= (cipherAlg << 4) & 0x70;
        p1 |= key_index & 0x0F;

        p2 |= paddingAlg << 4;
        // p2 |= digest & 0x0F; // We now using only "digest on card"=None

        byte[] rapdu = transceiveAPDU(Consts.CLA_DEFAULT, Consts.INS_GET_SIGNATURE, p1, p2, plainText, (short) 256, true, sw);

        if (Bitwise.bytesToShortBE(sw) != (short) 0x9000)
            throw new DLSignerNfcException("APDU Error: " + getApduError(sw));

        return rapdu;
    }

    public static String getApduError(byte[] sw) throws DLSignerNfcException {

        if (sw == null)
            throw new DLSignerNfcException("SW not instantiated");
        if (sw.length < 2)
            throw new DLSignerNfcException("Invalid SW length");

        switch (Bitwise.bytesToShortBE(sw)) {
            case Consts.SW_SECURITY_STATUS_NOT_SATISFIED:
                return "security condition not satisfied";
            case Consts.SW_CONDITIONS_NOT_SATISFIED:
                return "conditions of use not satisfied";
            case Consts.SW_WRONG_DATA:
                return "wrong data";
            case Consts.SW_RECORD_NOT_FOUND:
                return "record not found";
            case Consts.SW_ENTITY_ALREADY_EXISTS:
                return "entity already exists";
            case Consts.SW_INS_NOT_SUPPORTED:
                return "instruction not supported";
            case Consts.SW_NO_PRECISE_DIAGNOSTIC:
                return "no precise diagnostic in Java card (probably index out of range)";
            default:
                return "unspecified";
        }
    }

    private static byte[] transceiveAPDU(byte cls, byte ins, byte p1, byte p2, byte[] data,
                                         short Ne, boolean SendLe, byte[] sw) throws DLSignerNfcException {
        byte[] ret;
        int capdu_size = 4;
        int max_transceive_len = mTag.getMaxTransceiveLength();

        if (sw == null)
            throw new DLSignerNfcException("SW not instantiated");
        if (sw.length < 2)
            throw new DLSignerNfcException("Invalid SW length");

        if (data != null)
            capdu_size += data.length + 1; // +1 for Lc

        if (SendLe) {
            if (Ne > 256)
                throw new DLSignerNfcException("APDU extended length not supported");
            else if ((Ne + 2) > max_transceive_len)
                throw new DLSignerNfcException("Invalid expected R-APDU length");
        }

        if (capdu_size > max_transceive_len)
            throw new DLSignerNfcException("Invalid C-APDU length");


        if (SendLe) {
            ++capdu_size;
            if (Ne > 255)
                Ne = 0;
        }

        byte[] capdu = new byte[capdu_size];
        capdu[0] = cls;
        capdu[1] = ins;
        capdu[2] = p1;
        capdu[3] = p2;
        if (data != null) {
            capdu[4] = (byte) (data.length & 0xFF); // Lc
            System.arraycopy(data, 0, capdu, 5, data.length);
        }
        if (SendLe)
            capdu[capdu_size - 1] = (byte) Ne;

        byte[] rapdu;
        try {
            rapdu = mTag.transceive(capdu);
        } catch (IOException e) {
            e.printStackTrace();
            throw new DLSignerNfcException("Communication error");
        }

        if (rapdu.length < 2)
            throw new DLSignerNfcException("Invalid APDU response");
        else if (rapdu.length > 2) {
            ret = new byte[rapdu.length - 2];
            System.arraycopy(rapdu, 0, ret, 0, rapdu.length - 2);
        } else
            ret = new byte[0]; // After call to this method you can always check ret.length without risk to get Exception

        System.arraycopy(rapdu, rapdu.length - 2, sw, 0, 2);

        return ret;
    }

    public static class JCDLSignerDigests {
        public static final byte ALG_NULL = 0;
        public static final byte ALG_SHA = 1; // SHA1
        public static final byte ALG_SHA_256 = 2; // SHA2-256
        public static final byte ALG_SHA_384 = 3; // SHA2-384
        public static final byte ALG_SHA_512 = 4; // SHA2-512
        public static final byte ALG_SHA_224 = 5; // SHA2-224
    }

    public static class Consts {

        static final long WAIT_CARD_TIMEOUT = 10000; // [ms] => 10 s
        static final byte CLA_ISO = 0;
        static final byte CLA_DEFAULT = (byte) 0x80;

        static final byte[] AID = new byte[]{(byte) 0xF0, 0x44, 0x4C, 0x6F, 0x67, 0x69, 0x63, 0x00, 0x01};

        // DLSigner Card instructions:
        static final byte INS_SET_RSA_PRIKEY = 0x51;
        static final byte INS_GEN_RSA_KEY_PAIR = 0x52;
        static final byte INS_GET_RSA_PUBKEY_MODULUS = 0x53;
        static final byte INS_GET_RSA_PUBKEY_EXPONENT = 0x54;
        static final byte INS_DEL_RSA_KEY_PAIR = 0x5F;
        static final byte INS_SET_EC_PRIKEY = 0x61;
        static final byte INS_GEN_EC_KEY_PAIR = 0x62;
        static final byte INS_GET_EC_PUBKEY = 0x63;
        static final byte INS_GET_EC_FIELD = 0x64;
        static final byte INS_GET_EC_AB = 0x65;
        static final byte INS_GET_EC_G = 0x66;
        static final byte INS_GET_EC_RK_SIZE = 0x67;
        static final byte INS_DEL_EC_KEY_PAIR = 0x6F;
        static final byte INS_GET_SIGNATURE = 0x71;
        static final byte INS_PUT_OBJ = 0x31;
        static final byte INS_PUT_OBJ_SUBJECT = 0x32;
        static final byte INS_INVALIDATE_CERT = 0x33;
        static final byte INS_GET_OBJ = 0x41;
        static final byte INS_GET_OBJ_ID = 0x42;
        static final byte INS_GET_OBJ_SUBJECT = 0x43;
        static final byte INS_LOGIN = 0x20;
        static final byte INS_GET_PIN_TRIES_REMAINING = 0x21;
        static final byte INS_PIN_CHANGE = 0x22;
        static final byte INS_PIN_UNBLOCK = 0x23;

        // APDU Error codes:
        static final short SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
        static final short SW_CONDITIONS_NOT_SATISFIED = 0x6985;
        static final short SW_WRONG_DATA = 0x6A80;
        static final short SW_RECORD_NOT_FOUND = 0x6A83;
        static final short SW_ENTITY_ALREADY_EXISTS = 0x6A89;
        static final short SW_INS_NOT_SUPPORTED = 0x6D00;
        static final short SW_NO_PRECISE_DIAGNOSTIC = 0x6F00;

        static final short SW_WRONG_PIN_MASK = 0x63C0;
    }

    public static class DLSignerNfcException extends Exception {

        public DLSignerNfcException(String message) {
            super(message);
        }
    }
}
