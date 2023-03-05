package ru.iu3.ecnryptedemvreader.util;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import ru.iu3.ecnryptedemvreader.helper.ReadPaycardConstsHelper;
import ru.iu3.ecnryptedemvreader.object.AflObject;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;

public class AflUtil {
    private static final String TAG = AflUtil.class.getName();

    @Nullable
    public ArrayList<AflObject> getAflDataRecords(@NonNull byte[] aflData) {
        if (aflData.length < 4) {
            LogUtil.e(TAG, "Cannot perform AFL data byte array actions, available bytes < 4; Length is " + aflData.length);
            return null;
        }

        ArrayList<AflObject> result = new ArrayList<>();

        for (int i = 0; i < aflData.length / 4; i++) {
            int firstRecordNumber = aflData[4 * i + 1], lastRecordNumber = aflData[4 * i + 2];
            int sfi = aflData[4 * i] >> 3;

            for (int recordNumber = firstRecordNumber; recordNumber <= lastRecordNumber; recordNumber++) {
                AflObject aflObject = new AflObject();
                aflObject.setSfi(sfi);
                aflObject.setRecordNumber(recordNumber);

                byte[] readCommand = new byte[] {
                        (byte) 0x00,
                        (byte) 0xB2,
                        (byte) recordNumber,
                        (byte) ((sfi << 0x03) | 0x04),
                        0x00
                };

                aflObject.setReadCommand(readCommand);
                result.add(aflObject);
            }
        }

        return result;
    }


    private byte[] buildReadCommand(int sfi, int recordNumber) {
        ByteArrayOutputStream readRecordByteArrayOutputStream = new ByteArrayOutputStream();

        try {
            readRecordByteArrayOutputStream.write(ReadPaycardConstsHelper.READ_RECORD);
            readRecordByteArrayOutputStream.write(new byte[]{
                    (byte) recordNumber,
                    (byte) ((sfi << 0x03) | 0x04),
            });
            readRecordByteArrayOutputStream.write(new byte[]{ (byte) 0x00 });
        } catch (Exception e) {
            LogUtil.e(TAG, e.getMessage());
            LogUtil.e(TAG, e.toString());
        }

        return readRecordByteArrayOutputStream.toByteArray();
    }

}
