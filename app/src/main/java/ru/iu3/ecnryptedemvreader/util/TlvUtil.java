package ru.iu3.ecnryptedemvreader.util;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

public class TlvUtil {
    private static final String TAG = TlvUtil.class.getName();

    @Nullable
    public static byte[] getTlvValue(@NonNull byte[] dataBytes, @NonNull byte[] tlvTag) {
        byte[] result = null;

        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(dataBytes)) {
            if (byteArrayInputStream.available() < 2) {
                throw new Exception("Cannot perform TLV byte array stream actions, available bytes < 2; Length is " + byteArrayInputStream.available());
            }
            int i = 0, resultSize;
            byte[] tlvTagLength = new byte[tlvTag.length];
            while (byteArrayInputStream.read() != -1) {
                i++;
                if (i >= tlvTag.length) {
                    tlvTagLength = Arrays.copyOfRange(dataBytes, i - tlvTag.length, i);
                }
                if (Arrays.equals(tlvTag, tlvTagLength)) {
                    resultSize = byteArrayInputStream.read();
                    if (resultSize > byteArrayInputStream.available()) {
                        continue;
                    }
                    if (resultSize != -1) {
                        byte[] resultRes = new byte[resultSize];
                        if (byteArrayInputStream.read(resultRes, 0, resultSize) != 0) {
                            String checkResponse = HexUtil.bytesToHexadecimal(dataBytes), checkResult = HexUtil.bytesToHexadecimal(resultRes);
                            if (checkResponse != null && checkResult != null && checkResponse.contains(checkResult)) {
                                result = resultRes;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
            e.printStackTrace();
        }

        return result;
    }

}
