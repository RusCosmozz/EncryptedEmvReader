package ru.iu3.ecnryptedemvreader.util;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.Arrays;

public class EmvUtil {
    private static final String TAG = EmvUtil.class.getName();

    /**
     * Check if the EMV response is correct and has the correct status
     *
     * @param emvResponse the EMV response to check
     * @return true if the response is correct, false otherwise
     */
    @Nullable
    public static boolean isOk(@NonNull byte[] emvResponse) {
        // Check if the EMV response has SW bytes
        byte[] swBytes = getSwBytes(emvResponse);
        if (swBytes == null) {
            // No SW bytes found in EMV response
            return false;
        }

        // Check if the SW bytes are correct (0x9000)
        return Arrays.equals(swBytes, new byte[] {(byte) 0x90, (byte) 0x00});
    }

    /**
     * Extract the SW bytes from the EMV response
     *
     * @param emvResponse the EMV response
     * @return the SW bytes, or null if not found
     */
    @Nullable
    public static byte[] getSwBytes(@NonNull byte[] emvResponse) {
        byte[] swBytes = null;

        // Check if the EMV response has at least 2 bytes
        if (emvResponse.length >= 2) {
            // Extract the last 2 bytes (SW bytes)
            swBytes = new byte[]{emvResponse[emvResponse.length - 2], emvResponse[emvResponse.length - 1]};
        }

        return swBytes;
    }

}
