package ru.iu3.ecnryptedemvreader.adapter;

import android.content.Context;
import android.support.annotation.NonNull;
import android.view.LayoutInflater;
import android.widget.ArrayAdapter;

import ru.iu3.ecnryptedemvreader.object.PaymentObject;

import io.realm.RealmResults;

public class PaymentItemCustomArrayAdapter extends ArrayAdapter<PaymentObject> {
    private LayoutInflater mLayoutInflater;

    public PaymentItemCustomArrayAdapter(@NonNull Context context, int resource, RealmResults<PaymentObject> paymentObjectRealmResults) {
        super(context, resource, paymentObjectRealmResults);

        mLayoutInflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
    }
}
