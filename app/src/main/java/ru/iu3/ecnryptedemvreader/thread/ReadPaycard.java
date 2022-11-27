package ru.iu3.ecnryptedemvreader.thread;

import android.content.Context;
import android.content.Intent;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.support.annotation.NonNull;
import android.support.v4.content.LocalBroadcastManager;

import ru.iu3.ecnryptedemvreader.R;
import ru.iu3.ecnryptedemvreader.activity.ReadPaycardActivity;
import ru.iu3.ecnryptedemvreader.envr.MainEnvr;
import ru.iu3.ecnryptedemvreader.helper.ReadPaycardConstsHelper;
import ru.iu3.ecnryptedemvreader.object.AflObject;
import ru.iu3.ecnryptedemvreader.util.AflUtil;
import ru.iu3.ecnryptedemvreader.util.AidUtil;
import ru.iu3.ecnryptedemvreader.util.DolUtil;
import ru.iu3.ecnryptedemvreader.util.EmvUtil;
import ru.iu3.ecnryptedemvreader.util.GacUtil;
import ru.iu3.ecnryptedemvreader.util.GpoUtil;
import ru.iu3.ecnryptedemvreader.util.HexUtil;
import ru.iu3.ecnryptedemvreader.util.LogUtil;
import ru.iu3.ecnryptedemvreader.util.PseUtil;
import ru.iu3.ecnryptedemvreader.util.TlvUtil;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import io.realm.RealmList;

public class ReadPaycard implements Runnable {
    private static final String TAG = ReadPaycardThread.class.getSimpleName();

    private Context mContext;

    private IsoDep mIsoDep = null;

    public ReadPaycard(@NonNull Context context, @NonNull Tag tag) {
        mContext = context;

        try {
            mIsoDep = IsoDep.get(tag);
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());

            e.printStackTrace();
        }

        Vibrator vibrator = null;
        try {
            vibrator = (Vibrator) mContext.getSystemService(Context.VIBRATOR_SERVICE);
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());

            e.printStackTrace();
        }

        if (vibrator != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                try {
                    vibrator.vibrate(VibrationEffect.createOneShot(MainEnvr.READ_PAYCARD_VIBE_TIME, VibrationEffect.DEFAULT_AMPLITUDE));
                } catch (Exception e) {
                    LogUtil.e(TAG, e.getMessage());
                    LogUtil.e(TAG, e.toString());

                    e.printStackTrace();
                }
            } else {
                try {
                    vibrator.vibrate(MainEnvr.READ_PAYCARD_VIBE_TIME);
                } catch (Exception e) {
                    LogUtil.e(TAG, e.getMessage());
                    LogUtil.e(TAG, e.toString());

                    e.printStackTrace();
                }
            }
        }
    }

    boolean isPayPass = false, isPayWave = false;
    // NfcA (ISO 14443-3A)
    byte[] historicalBytes = null;
    // NfcB (ISO 14443-3B)
    byte[] hiLayerResponse = null;

    // PPSE (Proximity Payment System Environment)
    byte[] cPpse = null, rPpse = null;
    boolean ppseSucceed = false;

    // TLV Extractable Data
    byte[] aid = null; // AID (Application Identifier)
    String aidHexadecimal = null; // AID (Application Identifier)

    byte[] applicationLabel = null; // Application Label
    String applicationLabelAscii = null; // Application Label ASCII

    byte[] dfName = null; // Dedicated file Name
    String dfNameHexadecimal = null; // Dedicated file Name Hex

    byte[] fciTemplate = null;
    String fciTemplateHexadecimal = null;

    byte[] signedAppTags = null;
    String signedAppTagsHexadecimal = null;

    byte[] unsignedAppTags = null;
    String unsignedAppTagsHexadecimal = null;

    byte[] applicationPan = null; // Application PAN (Primary Account Number)
    byte[] cardholderName = null; // Cardholder Name
    String cardholderNameAscii = null; // Cardholder Name ASCII
    byte[] applicationExpirationDate = null; // Application Expiration Date
    byte[] applicationStartDate = null; // Application Expiration Date
    byte[] auc = null; // AUC
    byte[] appInfo = null; // AUC

    // FCI (File Control Information)
    byte[] cFci = null, rFci = null;

    byte[] pdol = null;
    byte[] pdolConstructed = null;

    byte[] cGpo = null;
    byte[] rGpo = null;

    byte[] aflData = null;

    byte[] cdol_1 = null, cdol_2 = null;
    @Override
    public void run() {
        LogUtil.d(TAG, "\"" + TAG + "\": Thread run");
        if (mIsoDep == null) {
            return;
        }
        if (mIsoDep.getTag() == null) {
            return;
        }

        LogUtil.d(TAG, "ISO-DEP - Compatible NFC tag discovered: " + mIsoDep.getTag());
        // ISO-DEP - Connect
        connect();
        // - ISO-DEP - Connect

        // Thread relative
        // ATS (Answer To Select)
        // NfcA (ISO 14443-3A)
        getAndLogHistoricalBytes();
        // - NfcA (ISO 14443-3A)

        // NfcB (ISO 14443-3B)
        getAndLogHiLayer();
        // - NfcB (ISO 14443-3B)
        // - ATS (Answer To Select)

        // PPSE (Proximity Payment System Environment)
        performPpse();
        // - PPSE (Proximity Payment System Environment)
        if (!ppseSucceed) {
            cannotReadPaycard();
            return;
        }
        // AID (Application Identifier)
        getAid();
        if (aid != null) {
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.aid) + " [4F]\": " + Arrays.toString(aid));

            aidHexadecimal = HexUtil.bytesToHexadecimal(aid);
            if (aidHexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.aid) + " [4F]\" Hexadecimal: " + aidHexadecimal);
            }
        } else {
            cannotReadPaycard();
            return;
        }
        // - AID (Application Identifier)

        // FCI (File Control Information)
        getFci();
        if (rFci != null) {
            LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.fci) + "\": " + Arrays.toString(rFci));
            String rFciHexadecimal = HexUtil.bytesToHexadecimal(rFci);
            if (rFciHexadecimal != null) {
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.fci) + "\" Hexadecimal: " + rFciHexadecimal);
            }
            if (EmvUtil.isOk(rFci)) {
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.fci) + "\": Succeed");
            } else {
                LogUtil.w(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.fci) + "\": Not succeed");
                // TODO: Get response SW1 & SW2, check response SW1 & SW2, log the result
                cannotReadPaycard();
                return;
            }
        } else {
            cannotReadPaycard();
            return;
        }

        // df name check
        if (dfName == null) {
            dfName = new TlvUtil().getTlvValue(rFci, ReadPaycardConstsHelper.DEDICATED_FILE_NAME);
            if (dfName != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.df_name) + " [84]\": " + Arrays.toString(dfName));
                dfNameHexadecimal = HexUtil.bytesToHexadecimal(dfName);
                if (dfNameHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.df_name) + " [84]\" Hexadecimal: " + dfNameHexadecimal);
                }
            }
        }
        if (!aidHexadecimal.equals(dfNameHexadecimal)) {
            cannotReadPaycard();
            return;
        }
        // fci template check
        if (fciTemplate == null) {
            fciTemplate = new TlvUtil().getTlvValue(rFci, ReadPaycardConstsHelper.FCI_TEMPLATE);
            if (fciTemplate != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.fci_template) + " [A5]\": " + Arrays.toString(fciTemplate));
                fciTemplateHexadecimal = HexUtil.bytesToHexadecimal(fciTemplate);
                if (fciTemplateHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.fci_template) + " [A5]\" Hexadecimal: " + fciTemplateHexadecimal);
                }
            }
        }

        getApplicationLabel();
        getSignedAppTags();
        getUnsignedAppTags();
        // todo опциональный проверки на стр 40
        constructPdolData();
        performGpo();
        if (EmvUtil.isOk(rGpo)) {
            LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\": Succeed");
        } else {
            LogUtil.w(TAG, "EMV (R-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\": Not succeed");
            cannotReadPaycard();
            return;
        }

        // AFL (Application File Locator) [GPO] Data
        byte[] aip = new TlvUtil().getTlvValue(rGpo, ReadPaycardConstsHelper.AIP_TLV_TAG);
        if (aip != null && !BigInteger.valueOf(aip[1]).testBit(7)) {
            //todo обработка emv запрещена
            cannotReadPaycard();
            return;
        }
        getAfl();
        // AFL (Application File Locator) Record(s)
        readAflRecords();
        //todo проверка срока дейсвтия

        // CDOL1
        if (cdol_1 != null) {
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_1) + " [8C]\": " + Arrays.toString(cdol_1));

            String cdol1Hexadecimal = HexUtil.bytesToHexadecimal(cdol_1);
            if (cdol1Hexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_1) + " [8C]\" Hexadecimal: " + cdol1Hexadecimal);
            }

            // CDOL1 Constructed
            byte[] cdol1Constructed = new GacUtil().fillCdol_1(cdol_1);

            if (cdol1Constructed != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_1) + " Constructed\": " + Arrays.toString(cdol1Constructed));

                String cdol1ConstructedHexadecimal = HexUtil.bytesToHexadecimal(cdol1Constructed);
                if (cdol1ConstructedHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_1) + " Constructed\" Hexadecimal: " + cdol1ConstructedHexadecimal);
                }
            }
            // - CDOL1 Constructed
        }
    }

    private void getAndLogHistoricalBytes() {
        try {
            historicalBytes = mIsoDep.getHistoricalBytes();
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }
        if (historicalBytes != null && historicalBytes.length > 0) {
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + ": Supported");

            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + ": " + Arrays.toString(historicalBytes));
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + " Hexadecimal: " + HexUtil.bytesToHexadecimal(historicalBytes));
        } else {
            LogUtil.w(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + ": Not supported");
        }
    }

    private void getAndLogHiLayer() {
        try {
            hiLayerResponse = mIsoDep.getHiLayerResponse();
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());

            e.printStackTrace();
        }

        if (hiLayerResponse != null && hiLayerResponse.length > 0) {
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + ": Supported");

            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + ": " + Arrays.toString(hiLayerResponse));
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + " Hexadecimal: " + HexUtil.bytesToHexadecimal(hiLayerResponse));
        } else {
            LogUtil.w(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + ": Not supported");
        }
    }

    private void performPpse() {
        cPpse = PseUtil.selectPpse(null);

        if (cPpse != null) {
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\": " + Arrays.toString(cPpse));
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cPpse));

            try {
                rPpse = mIsoDep.transceive(PseUtil.selectPpse(null));
            } catch (Exception e) {
                LogUtil.e(TAG, e.getMessage());
                LogUtil.e(TAG, e.toString());

                e.printStackTrace();
            }

            if (rPpse != null) {
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\": " + Arrays.toString(rPpse));

                String rPpseHexadecimal = HexUtil.bytesToHexadecimal(rPpse);
                if (rPpseHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\" Hexadecimal: " + rPpseHexadecimal);
                }

                // ----

                if (EmvUtil.isOk(rPpse)) {
                    ppseSucceed = true;

                    LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\": Succeed");
                } else {
                    LogUtil.w(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\": Not succeed");

                    // TODO: Get response SW1 & SW2, check response SW1 & SW2, log the result
                }
            }
        }
    }

    private void getAid() {
        if (aid == null && ppseSucceed) {
            ByteArrayInputStream byteArrayInputStream = null;
            // todo with resources
            try {
                byteArrayInputStream = new ByteArrayInputStream(rPpse);
            } catch (Exception e) {
                LogUtil.e(TAG, e.getMessage());
                LogUtil.e(TAG, e.toString());

                e.printStackTrace();
            }
            if (byteArrayInputStream != null) {
                if (byteArrayInputStream.available() < 2) {
                    try {
                        throw new Exception("Cannot preform TLV byte array stream actions, available bytes < 2; Length is " + byteArrayInputStream.available());
                    } catch (Exception e) {
                        LogUtil.e(TAG, e.getMessage());
                        LogUtil.e(TAG, e.toString());
                        e.printStackTrace();
                    }
                } else {
                    int i = 0, resultSize;
                    byte[] aidTlvTagLength = new byte[ReadPaycardConstsHelper.AID_TLV_TAG.length];
                    while (byteArrayInputStream.read() != -1) {
                        i += 1;
                        if (i >= ReadPaycardConstsHelper.AID_TLV_TAG.length) {
                            aidTlvTagLength = Arrays.copyOfRange(rPpse, i - ReadPaycardConstsHelper.AID_TLV_TAG.length, i);
                        }
                        if (Arrays.equals(ReadPaycardConstsHelper.AID_TLV_TAG, aidTlvTagLength)) {
                            resultSize = byteArrayInputStream.read();
                            if (resultSize > byteArrayInputStream.available()) {
                                continue;
                            }
                            if (resultSize != -1) {
                                byte[] resultRes = new byte[resultSize];
                                if (byteArrayInputStream.read(resultRes, 0, resultSize) != 0) {
                                    if (Arrays.equals(resultRes, AidUtil.A0000006581010)) {
                                        isPayPass = true;
                                        aid = resultRes;
                                        //todo а че если не нашли
                                        LogUtil.d(TAG, mContext.getString(R.string.aid) + " Found: " + Arrays.toString(resultRes));
                                    }
                                }
                            }
                        }
                    }
                }
                try {
                    byteArrayInputStream.close();
                } catch (Exception e) {
                    LogUtil.e(TAG, e.getMessage());
                    LogUtil.e(TAG, e.toString());
                    e.printStackTrace();
                }
            }
        }

    }

    private void getFci() {
        cFci = AidUtil.selectAid(AidUtil.A0000006581010); // Mir

        if (cFci != null) {
            try {
                rFci = mIsoDep.transceive(AidUtil.selectAid(AidUtil.A0000006581010));
            } catch (Exception e) {
                LogUtil.e(TAG, e.getMessage());
                LogUtil.e(TAG, e.toString());

                e.printStackTrace();
            }
        }
        if (cFci != null) {
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.fci) + "\": " + Arrays.toString(cFci));
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.fci) + "\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cFci));
        }
    }

    private void getApplicationLabel() {
        if (applicationLabel == null) {
            applicationLabel = new TlvUtil().getTlvValue(rFci, ReadPaycardConstsHelper.APPLICATION_LABEL_TLV_TAG);

            if (applicationLabel != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_label) + " [50]\": " + Arrays.toString(applicationLabel));
                String applicationLabelHexadecimal = HexUtil.bytesToHexadecimal(applicationLabel);
                if (applicationLabelHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_label) + " [50]\" Hexadecimal: " + applicationLabelHexadecimal);
                    // ----
                    String tempApplicationLabelAscii = HexUtil.hexadecimalToAscii(applicationLabelHexadecimal);
                    if (tempApplicationLabelAscii != null) {
                        applicationLabelAscii = tempApplicationLabelAscii;
                        LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_label) + " [50]\" ASCII: " + applicationLabelAscii);
                    }
                }
            }
        }
    }

    private void getSignedAppTags() {
        if (signedAppTags == null) {
            signedAppTags = new TlvUtil().getTlvValue(rFci, ReadPaycardConstsHelper.SIGN_APP_TAGS);

            if (signedAppTags != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.sign_app_tags) + " [BF61]\": " + Arrays.toString(signedAppTags));
                signedAppTagsHexadecimal = HexUtil.bytesToHexadecimal(signedAppTags);
                if (signedAppTagsHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.sign_app_tags) + " [BF61]\" Hexadecimal: " + signedAppTagsHexadecimal);
                }
            } else {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.sign_app_tags) + " [BF61]\": " + "Not found");
            }
        }
    }

    private void getUnsignedAppTags() {
        if (unsignedAppTags == null) {
            unsignedAppTags = new TlvUtil().getTlvValue(rFci, ReadPaycardConstsHelper.SIGN_APP_TAGS);

            if (unsignedAppTags != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.unsign_app_tags) + " [BF62]\": " + Arrays.toString(unsignedAppTags));
                unsignedAppTagsHexadecimal = HexUtil.bytesToHexadecimal(unsignedAppTags);
                if (unsignedAppTagsHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.unsign_app_tags) + " [BF62]\" Hexadecimal: " + unsignedAppTagsHexadecimal);
                }
            } else {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.unsign_app_tags) + " [BF62]\": " + "Not found");
            }
        }
    }

    private void constructPdolData() {
        byte[] tempPdol = new TlvUtil().getTlvValue(rFci, ReadPaycardConstsHelper.PDOL_TLV_TAG);
        if (tempPdol != null && DolUtil.isValidDol(tempPdol, ReadPaycardConstsHelper.PDOL_TLV_TAG)) {
            pdol = tempPdol;
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.pdol) + " [9F38]\": " + Arrays.toString(pdol));
            String pdolHexadecimal = HexUtil.bytesToHexadecimal(pdol);
            if (pdolHexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.pdol) + " [9F38]\" Hexadecimal: " + pdolHexadecimal);
            }
        }
        // - PDOL (Processing Options Data Object List)
        // PDOL Constructed
        pdolConstructed = new GpoUtil().fillPdol(pdol);
        if (pdolConstructed != null) {
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.pdol) + " Constructed\": " + Arrays.toString(pdolConstructed));
            String pdolConstructedHexadecimal = HexUtil.bytesToHexadecimal(pdolConstructed);
            if (pdolConstructedHexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.pdol) + " Constructed\" Hexadecimal: " + pdolConstructedHexadecimal);
            }
        } else {
            cannotReadPaycard();
            return;
        }
    }

    private void performGpo() {
        cGpo = new GpoUtil().cGpo(pdolConstructed); // C-APDU & R-APDU
        if (cGpo != null) {
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\": " + Arrays.toString(cGpo));
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cGpo));

            try {
                rGpo = mIsoDep.transceive(cGpo);
            } catch (Exception e) {
                LogUtil.e(TAG, e.getMessage());
                LogUtil.e(TAG, e.toString());
                e.printStackTrace();
            }
        }

        if (rGpo != null) {
            LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\": " + Arrays.toString(rGpo));
            String rGpoHexadecimal = HexUtil.bytesToHexadecimal(rGpo);
            if (rGpoHexadecimal != null) {
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\" Hexadecimal: " + rGpoHexadecimal);
            }
        } else {
            cannotReadPaycard();
            return;
        }
    }

    private void getAfl(){
        // Response message template 2 (with tags and lengths)
        if (rGpo[0] == ReadPaycardConstsHelper.GPO_RMT2_TLV_TAG[0]) {
            LogUtil.d(TAG, mContext.getString(R.string.gpo) + " Response message template 2");
            byte[] gpoData77 ;
            gpoData77 = new TlvUtil().getTlvValue(rGpo, ReadPaycardConstsHelper.GPO_RMT2_TLV_TAG);
            if (gpoData77 != null) {
                // AFL (Application File Locator)
                byte[] afl; // TLV (Type-length-value) tag specified for AFL (Application File Locator) and result variable
                afl = new TlvUtil().getTlvValue(rGpo, ReadPaycardConstsHelper.AFL_TLV_TAG);
                if (afl != null && afl.length % 4 ==0) {
                    aflData = afl;
                } else {
                    // todo длина не кратна 4
                    cannotReadPaycard();
                    return;
                }
                // - AFL (Application File Locator)
            }
        }
        // - Response message template 2 (with tags and lengths)
    }

    private void readAflRecords(){
        RealmList<byte[]> cAflRecordsList = new RealmList<>(), rAflRecordsList = new RealmList<>();
        ArrayList<AflObject> aflObjectArrayList = new AflUtil().getAflDataRecords(aflData);
        if (aflObjectArrayList != null && !aflObjectArrayList.isEmpty()) {
            for (AflObject aflObject : aflObjectArrayList) {
                byte[] cReadRecord = aflObject.getReadCommand(), rReadRecord = null; // C-APDU & R-APDU
                if (cReadRecord != null) {
                    cAflRecordsList.add(cReadRecord);
                    LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Read Record\"; Data: \"Read Record\": " + Arrays.toString(cReadRecord));
                    LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Read Record\"; Data: \"Read Record\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cReadRecord));
                    try {
                        rReadRecord = mIsoDep.transceive(cReadRecord);
                    } catch (Exception e) {
                        LogUtil.e(TAG, e.getMessage());
                        LogUtil.e(TAG, e.toString());
                        e.printStackTrace();
                    }
                }
                if (rReadRecord != null) {
                    rAflRecordsList.add(rReadRecord);
                    boolean succeedLe = false;
                    LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\": " + Arrays.toString(rReadRecord));
                    String rReadRecordHexadecimal = HexUtil.bytesToHexadecimal(rReadRecord);
                    if (rReadRecordHexadecimal != null) {
                        LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\" Hexadecimal: " + rReadRecordHexadecimal);
                    }
                    if (EmvUtil.isOk(rReadRecord)) {
                        succeedLe = true;
                    } else if (EmvUtil.getSwBytes(rReadRecord)[0] == (byte) 0x6C) {
                        cReadRecord[cReadRecord.length - 1] = (byte) (rReadRecord.length - 1); // Custom Le
                        if (cReadRecord != null) {
                            cAflRecordsList.add(cReadRecord);
                            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Read Record\"; Data: \"Read Record\": " + Arrays.toString(cReadRecord));
                            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Read Record\"; Data: \"Read Record\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cReadRecord));
                            try {
                                rReadRecord = mIsoDep.transceive(cReadRecord);
                            } catch (Exception e) {
                                LogUtil.e(TAG, e.getMessage());
                                LogUtil.e(TAG, e.toString());
                                e.printStackTrace();
                            }
                        }

                        if (rReadRecord != null) {
                            rAflRecordsList.add(rReadRecord);
                            LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\": " + Arrays.toString(rReadRecord));
                            String rReadRecordCustomLeHexadecimal = HexUtil.bytesToHexadecimal(rReadRecord);
                            if (rReadRecordCustomLeHexadecimal != null) {
                                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\" Hexadecimal: " + rReadRecordCustomLeHexadecimal);
                            }

                            if (EmvUtil.isOk(rReadRecord)) {
                                succeedLe = true;
                            }
                        }
                    }

                    if (succeedLe) {
                        LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\": Succeed");
                        // CDOL1 (Card Risk Management Data Object List 1)
                        if (cdol_1 == null) {
                            byte[] tempCdol1 = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.CDOL_1_TLV_TAG);

                            if (tempCdol1 != null && DolUtil.isValidDol(tempCdol1, ReadPaycardConstsHelper.CDOL_1_TLV_TAG)) {
                                cdol_1 = tempCdol1;
                            }
                        }
                        // - CDOL1 (Card Risk Management Data Object List 1)

                        // CDOL2 (Card Risk Management Data Object List 2)
                        if (cdol_2 == null) {
                            byte[] tempCdol2 = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.CDOL_2_TLV_TAG);
                            if (tempCdol2 != null && DolUtil.isValidDol(tempCdol2, ReadPaycardConstsHelper.CDOL_2_TLV_TAG)) {
                                cdol_2 = tempCdol2;
                            }
                        }
                        // - CDOL2 (Card Risk Management Data Object List 2)

                        // Application PAN (Primary Account Number)
                        if (applicationPan == null) {
                            applicationPan = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_PAN_TLV_TAG);
                            if (applicationPan != null) {
                                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_pan) + " [5A]\": " + Arrays.toString(applicationPan));
                                String applicationPanHexadecimal = HexUtil.bytesToHexadecimal(applicationPan);
                                if (applicationPanHexadecimal != null) {
                                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_pan) + " [5A]\" Hexadecimal: " + applicationPanHexadecimal);
                                }
                            }
                        }
                        //Auc (Application Usage Control)
                        if (auc == null) {
                            auc = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.AUC_TLV_TAG);
                            if (auc != null) {
                                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.auc) + " [9F07]\": " + Arrays.toString(auc));
                                String aucHexadecimal = HexUtil.bytesToHexadecimal(auc);
                                if (aucHexadecimal != null) {
                                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.auc) + " [9F07]\" Hexadecimal: " + aucHexadecimal);
                                }
                            }
                        }
                        // - Auc (Application Usage Control)
                        //AI (Application info)
                        if (appInfo == null) {
                            appInfo = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_INFO_TLV_TAG);
                            if (appInfo != null) {
                                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_info) + " [DF70]\": " + Arrays.toString(appInfo));
                                String appInfoHexadecimal = HexUtil.bytesToHexadecimal(appInfo);
                                if (appInfoHexadecimal != null) {
                                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_info) + " [DF70]\" Hexadecimal: " + appInfoHexadecimal);
                                }
                            }
                        }
                        // - Auc (Application Usage Control)
                        //Auc (Application Usage Control)
                        if (applicationStartDate == null) {
                            applicationStartDate = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_START_DATE_TLV_TAG);
                            if (applicationStartDate != null) {
                                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.app_start_date) + " [5F25]\": " + Arrays.toString(applicationStartDate));
                                String applicationStartDateHexadecimal = HexUtil.bytesToHexadecimal(applicationStartDate);
                                if (applicationStartDateHexadecimal != null) {
                                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.app_start_date) + " [5F25]\" Hexadecimal: " + applicationStartDateHexadecimal);
                                }
                            } else {
                                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.app_start_date) + " [5F25] not specified");
                            }
                        }
                        // - Auc (Application Usage Control)
                        // Cardholder Name (May be ASCII convertible)
                        if (cardholderName == null) {
                            cardholderName = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.CARDHOLDER_NAME_TLV_TAG);
                            if (cardholderName != null) {
                                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cardholder_name) + " [5F20]\": " + Arrays.toString(cardholderName));
                                String cardholderNameHexadecimal = HexUtil.bytesToHexadecimal(cardholderName);
                                if (cardholderNameHexadecimal != null) {
                                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cardholder_name) + " [5F20]\" Hexadecimal: " + cardholderNameHexadecimal);
                                    // ----
                                    String tempCardholderNameAscii = HexUtil.hexadecimalToAscii(cardholderNameHexadecimal);
                                    if (tempCardholderNameAscii != null) {
                                        cardholderNameAscii = tempCardholderNameAscii;
                                        LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cardholder_name) + " [5F20]\" ASCII: " + cardholderNameAscii);
                                    }
                                }
                            }
                        }
                        // - Cardholder Name (May be ASCII convertible)
                        // Application Expiration Date
                        if (applicationExpirationDate == null) {
                            applicationExpirationDate = new TlvUtil().getTlvValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_EXPIRATION_DATE_TLV_TAG);
                            if (applicationExpirationDate != null) {
                                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_expiration_date) + "[5F24]\": " + Arrays.toString(applicationExpirationDate));
                                String applicationExpirationDateHexadecimal = HexUtil.bytesToHexadecimal(applicationExpirationDate);
                                if (applicationExpirationDateHexadecimal != null) {
                                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_expiration_date) + " [5F24]\" Hexadecimal: " + applicationExpirationDateHexadecimal);
                                }
                            }
                        }
                        // - Application Expiration Date
                    } else {
                        LogUtil.w(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\": Not succeed");
                        // TODO: Get response SW1 & SW2, check response SW1 & SW2, log the result
                    }
                }
            }
        } else {
            LogUtil.w(TAG, "Will not read \"" + mContext.getString(R.string.afl) + "\" Record(s) (List is not available or empty)");
            cannotReadPaycard();
            return;
        }
    }

    private void successReadPaycard() {
        LocalBroadcastManager.getInstance(mContext).sendBroadcast(new Intent(ReadPaycardActivity.ACTION_SUCCESS_READ_PAYCARD_BROADCAST));
    }

    private void cannotReadPaycard() {
        LocalBroadcastManager.getInstance(mContext).sendBroadcast(new Intent(ReadPaycardActivity.ACTION_CANNOT_READ_PAYCARD_BROADCAST));
    }


    private void connect() {
        if (mIsoDep == null) {
            LogUtil.w(TAG, "ISO-DEP - Connect failed, no actionable instance found");
            return;
        }
        if (mIsoDep.getTag() == null) {
            LogUtil.w(TAG, "ISO-DEP - Connect failed, tag not found");
            return;
        }
        // Try to enable I/O operations to the tag
        LogUtil.d(TAG, "ISO-DEP - Trying to enable I/O operations to the tag...");
        try {
            mIsoDep.connect();
        } catch (Exception e) {
            LogUtil.e(TAG, "ISO-DEP - Exception while trying to enable I/O operations to the tag");

            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());

            e.printStackTrace();
        } finally {
            if (mIsoDep.isConnected()) {
                LogUtil.d(TAG, "ISO-DEP - Enabled I/O operations to the tag");
            } else {
                LogUtil.w(TAG, "ISO-DEP - Not enabled I/O operations to the tag");
            }
        }
        // - Try to enable I/O operations to the tag
    }

    private void close() {
        if (mIsoDep == null) {
            LogUtil.w(TAG, "ISO-DEP - Close failed, no actionable instance found");

            return;
        }

        if (mIsoDep.getTag() == null) {
            LogUtil.w(TAG, "ISO-DEP - Close failed, tag not found");

            return;
        }

        // Try to disable I/O operations to the tag
        LogUtil.d(TAG, "ISO-DEP - Trying to disable I/O operations to the tag...");
        try {
            mIsoDep.close();
        } catch (Exception e) {
            LogUtil.e(TAG, "ISO-DEP - Exception while trying to disable I/O operations to the tag");

            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());

            e.printStackTrace();
        } finally {
            if (mIsoDep.isConnected()) {
                LogUtil.w(TAG, "ISO-DEP - Not disabled I/O operations to the tag");
            } else {
                LogUtil.d(TAG, "ISO-DEP - Disabled I/O operations to the tag");
            }
        }
        // - Try to disable I/O operations to the tag
    }


}
