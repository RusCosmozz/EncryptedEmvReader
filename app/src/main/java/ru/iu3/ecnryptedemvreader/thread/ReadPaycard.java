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

        Vibrator vibrator;
        try {
            vibrator = (Vibrator) mContext.getSystemService(Context.VIBRATOR_SERVICE);
            if (vibrator != null) {
                long vibeTime = MainEnvr.READ_PAYCARD_VIBE_TIME;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator.vibrate(VibrationEffect.createOneShot(vibeTime, VibrationEffect.DEFAULT_AMPLITUDE));
                } else {
                    vibrator.vibrate(vibeTime);
                }
            }
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
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

    byte[] cdol1Constructed = null;

    @Override
    public void run() {
        LogUtil.d(TAG, "\"" + TAG + "\": Thread run");
        // If the IsoDep object has not been initialized or the tag is null, return and do nothing
        if (mIsoDep == null || mIsoDep.getTag() == null) {
            return;
        }
        // Log that an NFC tag has been discovered
        LogUtil.d(TAG, "ISO-DEP - Compatible NFC tag discovered: " + mIsoDep.getTag());
        // Connect to the NFC tag using the ISO-DEP protocol
        connect();
        // Get the historical bytes from the NFC tag using the NfcA protocol
        getAndLogHistoricalBytes();
        // Get the high-layer bytes from the NFC tag using the NfcB protocol
        getAndLogHiLayer();
        // Perform the Proximity Payment System Environment (PPSE) command
        performPpse();
        // If the PPSE command was not successful, return and do nothing
        if (!ppseSucceed) {
            cannotReadPaycard();
            return;
        }
        // Get the Application Identifier (AID) from the NFC tag
        getAid();
        // If the AID is null, return and do nothing
        if (aid == null) {
            cannotReadPaycard();
            return;
        }
        // Convert the AID to a hexadecimal string and log it
        aidHexadecimal = HexUtil.bytesToHexadecimal(aid);
        LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.aid) + " [4F]\" Hexadecimal: " + aidHexadecimal);
        // Get the File Control Information (FCI) from the NFC tag
        getFci();
        // If the FCI is null or not valid, return and do nothing
        if (rFci == null || !EmvUtil.isOk(rFci)) {
            cannotReadPaycard();
            return;
        }

        // Get the Dedicated File Name (dfName) and FCI Template (fciTemplate) from the FCI
        dfName = TlvUtil.getTlvValue(rFci, ReadPaycardConstsHelper.DEDICATED_FILE_NAME);
        fciTemplate = TlvUtil.getTlvValue(rFci, ReadPaycardConstsHelper.FCI_TEMPLATE);

        // Convert dfName and fciTemplate to hexadecimal strings and log them
        if (dfName != null) {
            dfNameHexadecimal = HexUtil.bytesToHexadecimal(dfName);
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.df_name) + " [84]\" Hexadecimal: " + dfNameHexadecimal);
        }

        // Check if AID and dfName match
        if (!aidHexadecimal.equals(dfNameHexadecimal)) {
            cannotReadPaycard();
            return;
        }
        if (fciTemplate != null) {
            fciTemplateHexadecimal = HexUtil.bytesToHexadecimal(fciTemplate);
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.fci_template) + " [A5]\" Hexadecimal: " + fciTemplateHexadecimal);
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
        byte[] aip = TlvUtil.getTlvValue(rGpo, ReadPaycardConstsHelper.AIP_TLV_TAG);
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
        constructCdol1();
        // First GAC (Generate Application Cryptogram)
        performFirstGac();
        // CDOL2
        if (cdol_2 != null) {
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_2) + " [8D]\": " + Arrays.toString(cdol_2));

            String cdol_2Hexadecimal = HexUtil.bytesToHexadecimal(cdol_2);
            if (cdol_2Hexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_2) + " [8D]\" Hexadecimal: " + cdol_2Hexadecimal);
            }
        }
        // - CDOL2
        System.out.println("ended");
    }


    private void getAndLogHistoricalBytes() {
        // Try to get the historical bytes of the ISO-DEP connection and catch any exceptions.
        try {
            historicalBytes = mIsoDep.getHistoricalBytes();
        } catch (Exception e) {
            // If an exception is caught, log the error message and stack trace.
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }

        // If historical bytes are present, log them in binary and hexadecimal format.
        if (historicalBytes != null && historicalBytes.length > 0) {
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + ": Supported");
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + ": " + Arrays.toString(historicalBytes));
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + " Hexadecimal: " + HexUtil.bytesToHexadecimal(historicalBytes));
        } else {
            // If historical bytes are not present, log that ISO-DEP is not supported.
            LogUtil.w(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_a) + ": Not supported");
        }
    }


    private void getAndLogHiLayer() {
        // Try to get the HiLayer response of the ISO-DEP connection and catch any exceptions.
        try {
            hiLayerResponse = mIsoDep.getHiLayerResponse();
        } catch (Exception e) {
            // If an exception is caught, log the error message and stack trace.
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }

        // If a HiLayer response is present, log it in binary and hexadecimal format.
        if (hiLayerResponse != null && hiLayerResponse.length > 0) {
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + ": Supported");
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + ": " + Arrays.toString(hiLayerResponse));
            LogUtil.d(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + " Hexadecimal: " + HexUtil.bytesToHexadecimal(hiLayerResponse));
        } else {
            // If a HiLayer response is not present, log that ISO-DEP is not supported.
            LogUtil.w(TAG, "ISO-DEP - " + mContext.getString(R.string.nfc_b) + ": Not supported");
        }
    }


    private void performPpse() {
        // Call the selectPpse() method from the PseUtil class to get the command APDU
        cPpse = PseUtil.selectPpse(null);
        // If the command APDU is not null
        if (cPpse != null) {
            // Log the command APDU in hexadecimal format
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cPpse));
            try {
                // Send the command APDU to the remote device and get the response APDU
                rPpse = mIsoDep.transceive(PseUtil.selectPpse(null));
            } catch (Exception e) {
                // If an exception occurs, log the error message and stack trace
                LogUtil.e(TAG, e.getMessage());
                LogUtil.e(TAG, e.toString());
                e.printStackTrace();
            }
            // If the response APDU is not null
            if (rPpse != null) {
                // Log the response APDU in hexadecimal format
                String rPpseHexadecimal = HexUtil.bytesToHexadecimal(rPpse);
                if (rPpseHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\" Hexadecimal: " + rPpseHexadecimal);
                }
                // Check if the response APDU indicates success
                if (EmvUtil.isOk(rPpse)) {
                    ppseSucceed = true;
                    LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\": Succeed");
                } else {
                    // If the response APDU indicates failure, log a warning
                    LogUtil.w(TAG, "EMV (R-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.ppse) + "\": Not succeed");
                }
            }
        }
    }


    private void getAid() {
        // Check if aid is not already initialized and ppseSucceed flag is true
        if (ppseSucceed) {
            this.aid = TlvUtil.getTlvValue(rPpse, ReadPaycardConstsHelper.AID_TLV_TAG);
        }
    }


    private void getFci() {
        // Select the AID for MIR
        byte[] cFci = AidUtil.selectAid(AidUtil.A0000006581010);
        if (cFci != null) {
            try {
                LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Select\"; Data: \"" + mContext.getString(R.string.fci) + "\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cFci));
                // Send the SELECT command and retrieve the FCI response
                rFci = mIsoDep.transceive(cFci);
            } catch (Exception e) {
                // Log any exceptions that occur
                LogUtil.e(TAG, e.getMessage());
                LogUtil.e(TAG, e.toString());
                e.printStackTrace();
            }
        }
    }


    private void getApplicationLabel() {
        applicationLabel = TlvUtil.getTlvValue(rFci, ReadPaycardConstsHelper.APPLICATION_LABEL_TLV_TAG);
        if (applicationLabel != null) {
            String applicationLabelHexadecimal = HexUtil.bytesToHexadecimal(applicationLabel);
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_label) + " [50]\" Hexadecimal: " + applicationLabelHexadecimal);

            if (applicationLabelHexadecimal != null) {
                applicationLabelAscii = HexUtil.hexadecimalToAscii(applicationLabelHexadecimal);
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.application_label) + " [50]\" ASCII: " + applicationLabelAscii);

            }
        }

    }


    private void getSignedAppTags() {
        signedAppTags = TlvUtil.getTlvValue(rFci, ReadPaycardConstsHelper.SIGN_APP_TAGS);
        if (signedAppTags != null) {
            signedAppTagsHexadecimal = HexUtil.bytesToHexadecimal(signedAppTags);
            if (signedAppTagsHexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.sign_app_tags) + " [BF61]\" Hexadecimal: " + signedAppTagsHexadecimal);
            }
        } else {
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.sign_app_tags) + " [BF61]\": " + "Not found");
        }
    }

    private void getUnsignedAppTags() {
        unsignedAppTags = TlvUtil.getTlvValue(rFci, ReadPaycardConstsHelper.SIGN_APP_TAGS);
        if (unsignedAppTags != null) {
            unsignedAppTagsHexadecimal = HexUtil.bytesToHexadecimal(unsignedAppTags);
            if (unsignedAppTagsHexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.unsign_app_tags) + " [BF62]\" Hexadecimal: " + unsignedAppTagsHexadecimal);
            }
        } else {
            LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.unsign_app_tags) + " [BF62]\": " + "Not found");
        }

    }

    private void constructPdolData() {
        // Get the PDOL value from the TLV data
        byte[] pdolValue = TlvUtil.getTlvValue(rFci, ReadPaycardConstsHelper.PDOL_TLV_TAG);
        // Check if the PDOL value is valid
        if (pdolValue != null && DolUtil.isValidDol(pdolValue, ReadPaycardConstsHelper.PDOL_TLV_TAG)) {
            // Store the PDOL value
            pdol = pdolValue;
            // Log the hexadecimal representation of the PDOL value
            String pdolHexadecimal = HexUtil.bytesToHexadecimal(pdol);
            if (pdolHexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.pdol) + " [9F38]\" Hexadecimal: " + pdolHexadecimal);
            }
        }
        // Generate the constructed PDOL value
        pdolConstructed = new GpoUtil().fillPdol(pdol);
        // Check if the constructed PDOL value was successfully generated
        if (pdolConstructed != null) {
            // Log the hexadecimal representation of the constructed PDOL value
            String pdolConstructedHexadecimal = HexUtil.bytesToHexadecimal(pdolConstructed);
            if (pdolConstructedHexadecimal != null) {
                LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.pdol) + " Constructed\" Hexadecimal: " + pdolConstructedHexadecimal);
            }
        } else {
            // If the constructed PDOL value was not generated, notify the user that the paycard cannot be read and return from the method
            cannotReadPaycard();
        }
    }

    private void constructCdol1() {
        if (cdol_1 == null) {
            return;
        }
        String cdol1Hex = HexUtil.bytesToHexadecimal(cdol_1);
        LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_1) + " [8C]\" Hexadecimal: " + cdol1Hex);
        cdol1Constructed = new GacUtil().fillCdol_1(cdol_1);
        if (cdol1Constructed == null) {
            return;
        }
        String cdol1ConstructedHex = HexUtil.bytesToHexadecimal(cdol1Constructed);
        LogUtil.d(TAG, "EMV (TLV) - Data: \"" + mContext.getString(R.string.cdol_1) + " Constructed\" Hexadecimal: " + cdol1ConstructedHex);
    }


    private void performFirstGac() {
        byte[] cFirstGac = new GacUtil().cGac(cdol1Constructed);
        if (cFirstGac == null) {
            return;
        }
        LogUtil.d(TAG, "EMV (C-APDU) - Command: \"" + mContext.getString(R.string.gac) + "\"; Data: \"First " + mContext.getString(R.string.cdol_1) + "\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cFirstGac));
        try {
            byte[] rFirstGac = mIsoDep.transceive(cFirstGac);
            if (EmvUtil.isOk(rFirstGac)) {
                String rFirstGacHexadecimal = HexUtil.bytesToHexadecimal(rFirstGac);
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"" + mContext.getString(R.string.gac) + "\"; Data: \"First " + mContext.getString(R.string.cdol_1) + "\" Hexadecimal: " + rFirstGacHexadecimal);
                LogUtil.w(TAG, "EMV (R-APDU) - Command: \"" + mContext.getString(R.string.gac) + "\"; Data: \"First " + mContext.getString(R.string.cdol_1) + "\": Succeed");
            } else {
                LogUtil.w(TAG, "EMV (R-APDU) - Command: \"" + mContext.getString(R.string.gac) + "\"; Data: \"First " + mContext.getString(R.string.cdol_1) + "\": Not succeed");
            }
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }
    }



    private void performGpo() {
        cGpo = new GpoUtil().cGpo(pdolConstructed);
        if (cGpo == null) {
            cannotReadPaycard();
            return;
        }
        LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cGpo));
        try {
            rGpo = mIsoDep.transceive(cGpo);
            String rGpoHexadecimal = HexUtil.bytesToHexadecimal(rGpo);
            if (rGpoHexadecimal != null) {
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Get Data\"; Data: \"" + mContext.getString(R.string.gpo) + "\" Hexadecimal: " + rGpoHexadecimal);
            }
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }
    }


    private void getAfl() {
        LogUtil.d(TAG, mContext.getString(R.string.gpo) + " Response message template 2");
        byte[] afl = TlvUtil.getTlvValue(rGpo, ReadPaycardConstsHelper.AFL_TLV_TAG);
        if (afl == null || afl.length % 4 != 0) {
            // todo длина не кратна 4
            cannotReadPaycard();
            return;
        }
        aflData = afl;
    }


    private void readAflRecords() {
        // Get list of AFL records from paycard
        ArrayList<AflObject> aflObjectArrayList = new AflUtil().getAflDataRecords(aflData);
        // If the list of AFL records is null or empty, do not read any records
        if (aflObjectArrayList == null || aflObjectArrayList.isEmpty()) {
            LogUtil.w(TAG, "Will not read \"" + mContext.getString(R.string.afl) + "\" Record(s) (List is not available or empty)");
            cannotReadPaycard();
            return;
        }
        // Initialize lists for read commands and response commands
        RealmList<byte[]> cAflRecordsList = new RealmList<>();
        RealmList<byte[]> rAflRecordsList = new RealmList<>();
        // Loop through each AFL record and read it
        for (AflObject aflObject : aflObjectArrayList) {
            byte[] cReadRecord = aflObject.getReadCommand();
            byte[] rReadRecord = performReadAflCommand(cReadRecord, cAflRecordsList);
            // If the response command is null, skip to the next AFL record
            if (rReadRecord == null) {
                continue;
            }
            // Add the response command to the list of response commands
            rAflRecordsList.add(rReadRecord);
            // Log the hexadecimal value of the response command
            String rReadRecordHexadecimal = HexUtil.bytesToHexadecimal(rReadRecord);
            if (rReadRecordHexadecimal != null) {
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\" Hexadecimal: " + rReadRecordHexadecimal);
            }
            // Check if the response command was successful
            boolean succeedLe = EmvUtil.isOk(rReadRecord);
            // If the response command has a custom Le, send another read command with the custom Le
            if (EmvUtil.getSwBytes(rReadRecord)[0] == (byte) 0x6C) {
                cReadRecord[cReadRecord.length - 1] = (byte) (rReadRecord.length - 1); // Custom Le
                rReadRecord = performReadAflCommand(cReadRecord, cAflRecordsList);
                if (rReadRecord != null) {
                    // Add the response command to the list of response commands
                    rAflRecordsList.add(rReadRecord);
                    // Log the hexadecimal value of the response command with custom Le
                    String rReadRecordCustomLeHexadecimal = HexUtil.bytesToHexadecimal(rReadRecord);
                    if (rReadRecordCustomLeHexadecimal != null) {
                        LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\" Hexadecimal: " + rReadRecordCustomLeHexadecimal);
                    }
                    // Check if the response command with custom Le was successful
                    succeedLe = EmvUtil.isOk(rReadRecord);
                }
            }
            if (succeedLe) {
                LogUtil.d(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\": Succeed");
                cdol_1 = checkAndLogTLVValue(rReadRecord, ReadPaycardConstsHelper.CDOL_1_TLV_TAG, cdol_1, mContext.getString(R.string.cdol_1));
                cdol_2 = checkAndLogTLVValue(rReadRecord, ReadPaycardConstsHelper.CDOL_2_TLV_TAG, cdol_2, mContext.getString(R.string.cdol_2));
                applicationPan = checkAndLogTLVValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_PAN_TLV_TAG, applicationPan, mContext.getString(R.string.application_pan));
                appInfo = checkAndLogTLVValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_INFO_TLV_TAG, appInfo, mContext.getString(R.string.application_info));
                applicationStartDate = checkAndLogTLVValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_START_DATE_TLV_TAG, applicationStartDate, mContext.getString(R.string.app_start_date));
                auc = checkAndLogTLVValue(rReadRecord, ReadPaycardConstsHelper.AUC_TLV_TAG, auc, mContext.getString(R.string.auc));
                applicationExpirationDate = checkAndLogTLVValue(rReadRecord, ReadPaycardConstsHelper.APPLICATION_EXPIRATION_DATE_TLV_TAG, applicationExpirationDate, mContext.getString(R.string.application_expiration_date));
                cardholderName = checkAndLogTLVValueWithAsciiConversion(rReadRecord, ReadPaycardConstsHelper.CARDHOLDER_NAME_TLV_TAG, cardholderName, mContext.getString(R.string.cardholder_name));
            } else {
                LogUtil.w(TAG, "EMV (R-APDU) - Command: \"Read Record\"; Data: \"Read Record\": Not succeed");
            }
        }
    }

    private byte[] checkAndLogTLVValue(byte[] rReadRecord, byte[] tag, byte[] value, String logMessage) {
        if (value == null) {
            value = TlvUtil.getTlvValue(rReadRecord, tag);
            if (value != null && DolUtil.isValidDol(value, tag)) {
                String valueHexadecimal = HexUtil.bytesToHexadecimal(value);
                if (valueHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + logMessage + "\" Hexadecimal: " + valueHexadecimal);
                }
            }
        }
        return value;
    }

    private byte[] checkAndLogTLVValueWithAsciiConversion(byte[] rReadRecord, byte[] tag, byte[] value, String logMessage) {
        if (value == null) {
            value = TlvUtil.getTlvValue(rReadRecord, tag);
            if (value != null) {
                String valueHexadecimal = HexUtil.bytesToHexadecimal(value);
                if (valueHexadecimal != null) {
                    LogUtil.d(TAG, "EMV (TLV) - Data: \"" + logMessage + "\" Hexadecimal: " + valueHexadecimal);
                    String ascii = HexUtil.hexadecimalToAscii(valueHexadecimal);
                    if (ascii != null) {
                        value = ascii.getBytes();
                        LogUtil.d(TAG, "EMV (TLV) - Data: \"" + logMessage + "\" ASCII: " + ascii);
                    }
                }
            }
        }
        return value;
    }

    private byte[] performReadAflCommand(byte[] cReadRecord, RealmList<byte[]> cAflRecordsList) {
        if (cReadRecord != null) {
            cAflRecordsList.add(cReadRecord);
            LogUtil.d(TAG, "EMV (C-APDU) - Command: \"Read Record\"; Data: \"Read Record\" Hexadecimal: " + HexUtil.bytesToHexadecimal(cReadRecord));
            try {
                return mIsoDep.transceive(cReadRecord);
            } catch (Exception e) {
                LogUtil.e(TAG, e.getMessage());
                LogUtil.e(TAG, e.toString());
                e.printStackTrace();
            }
        }
        return null;
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
