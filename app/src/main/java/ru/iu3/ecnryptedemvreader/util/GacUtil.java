package ru.iu3.ecnryptedemvreader.util;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import ru.iu3.ecnryptedemvreader.helper.ReadPaycardConstsHelper;
import ru.iu3.ecnryptedemvreader.object.TlvObject;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class GacUtil {
    private static final String TAG = GacUtil.class.getName();

    @Nullable
    public byte[] cGac(@NonNull byte[] cdolConstructed) {
        byte[] result = null;
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            byteArrayOutputStream.write(ReadPaycardConstsHelper.GENERATE_AC);
            byteArrayOutputStream.write(new byte[]{(byte) 0x00, (byte) 0x00, (byte) cdolConstructed.length});
            byteArrayOutputStream.write(cdolConstructed);
            byteArrayOutputStream.write(new byte[]{(byte) 0x00});
            result = byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }
        return result;
    }

    private static List<TlvObject> parseCdol(byte[] cdol) {
        List<TlvObject> tlvObjects = new ArrayList<>();
        if (cdol == null || cdol.length == 0) {
            return tlvObjects;
        }
        int index = 0;
        while (index < cdol.length) {
            byte[] tag = {cdol[index++]};
            if ((tag[0] & 0x1F) == 0x1F) {
                tag = new byte[]{tag[0], cdol[index++]};
            }
            byte length = cdol[index++];
            TlvObject tlvObject = new TlvObject(tag, length);
            tlvObjects.add(tlvObject);
        }
        return tlvObjects;
    }

    @Nullable
    public byte[] fillCdol_1(@Nullable byte[] cdol_1) {
        byte[] result = null;
        List<TlvObject> tlvObjectArrayList = parseCdol(cdol_1);
        if (tlvObjectArrayList.size() == 0) {
            return result;
        }
        ByteArrayOutputStream byteArrayOutputStream = null;
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            for (TlvObject tlvObject : tlvObjectArrayList) {
                byte[] generatePdolResult = new byte[tlvObject.getTlvTagLength()];
                byte[] resultValue = null;
                Date transactionDate = new Date();
                // TTQ (Terminal Transaction Qualifiers); 9F66; 4 Byte(s)
                if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TTQ_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> TTQ (Terminal Transaction Qualifiers); " + "9F66" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    byte[] data = new byte[4];
                    data[0] |= 1 << 5; // Contactless EMV mode supported (bit index (in the example: "5") <= 7)
                    resultValue = Arrays.copyOf(data, data.length);
                }
                // LVP_SUPPORT_TLV_TAG; 9F7A; 4 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.LVP_SUPPORT_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> LVP Supports; " + "9F7A" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x01
                    };
                }
                // Amount, Authorised (Numeric); 9F02; 6 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.AMOUNT_AUTHORISED_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Amount, Authorised (Numeric); " + "9F02" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[tlvObject.getTlvTagLength()];
                }
                // ADDITIONAL_TERMINAL_CAPABILITIEs; 9F40; 5 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.ADDITIONAL_TERMINAL_CAPABILITIES_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Additional terminal capabilities; " + "9F40" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[tlvObject.getTlvTagLength()];
                }
                // Amount, Other (Numeric); 9F03; 6 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.AMOUNT_OTHER_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Amount, Other (Numeric); " + "9F03" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[tlvObject.getTlvTagLength()];
                }
                // TERMINAL_TYPE_TLV_TAG ; 9F35; 1 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TERMINAL_TYPE_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Terminal Type; " + "9F35" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x01
                    };
                }
                // ADDITIONAL_TERMINAL_CAPABILITIES_TLV_TAG ; 9F40; 5 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.ADDITIONAL_TERMINAL_CAPABILITIES_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Additional terminal capabilities; " + "9F40" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x82,
                            (byte) 0x00,
                            (byte) 0x80,
                            (byte) 0x10,
                            (byte) 0x00,
                    };
                }
                // Terminal Country Code; 9F1A; 2 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TERMINAL_COUNTRY_CODE_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Terminal Country Code; " + "9F1A" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x06,
                            (byte) 0x43
                    };
                }
                // Transaction Currency Code; 5F2A, 2 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TRANSACTION_CURRENCY_CODE_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Transaction Currency Code; " + "5F2A" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x06,
                            (byte) 0x43
                    };
                }
                // Transaction Currency Code; 5F2A, 2 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TRANSACTION_CURRENCY_CODE_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Transaction Currency Code; " + "5F2A" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x06,
                            (byte) 0x43
                    };
                }
                // TVR (Transaction Verification Results); 95; 5 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TVR_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> TVR (Transaction Verification Results); " + "95" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x80, // Byte 1: Offline data authentication was not performed
                            (byte) 0x00, // Byte 2: No issuer authentication failure
                            (byte) 0x80, // Byte 3: SDA failed
                            (byte) 0x10, // Byte 4: Card risk management was performed
                            (byte) 0x00, // Byte 5: No CVM required
                    };
                }
                // CVM (Cardholder Verification Method Results); 9F34; 5 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.CVM_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> CVM (Cardholder Verification Method Results); " + "9F34" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x82,
                            (byte) 0x00,
                            (byte) 0x80,
                            (byte) 0x10,
                            (byte) 0x00,
                    };
                }
                // Transaction Date; 9A, 3 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TRANSACTION_DATE_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Transaction Date; " + "9A" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMdd", Locale.getDefault());
                    String formattedDate = dateFormat.format(transactionDate);
                    resultValue = HexUtil.hexadecimalToBytes(formattedDate);

                }
                // Transaction Type; 9C, 1 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TRANSACTION_TYPE_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Transaction Type; " + "9C" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    resultValue = new byte[]{
                            (byte) 0x00
                    };
                }
                // Transaction Time; 9F21; 3 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.TRANSACTION_TIME_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> Transaction Date; " + "9F21" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    SimpleDateFormat dateFormat = new SimpleDateFormat("HHmmss", Locale.getDefault());
                    String formattedDate = dateFormat.format(transactionDate);
                    resultValue = HexUtil.hexadecimalToBytes(formattedDate);
                }
                // UN (Unpredictable Number); 9F37, 1 or 4 Byte(s)
                else if (Arrays.equals(tlvObject.getTlvTag(), ReadPaycardConstsHelper.UN_TLV_TAG)) {
                    LogUtil.d(TAG, "Generate CDOL1 -> UN (Unpredictable Number); " + "9F37" + "; " + tlvObject.getTlvTagLength() + " Byte(s)");
                    SecureRandom unSecureRandom = new SecureRandom();
                    unSecureRandom.nextBytes(generatePdolResult);
                }
                // - UN (Unpredictable Number); 9F37, 1 or 4 Byte(s)
                if (resultValue != null) {
                    System.arraycopy(resultValue, 0, generatePdolResult, 0, Math.min(resultValue.length, generatePdolResult.length));
                }
                byteArrayOutputStream.write(generatePdolResult); // Data
            }
            byteArrayOutputStream.close();
            result = byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }
        return result;
    }
}
