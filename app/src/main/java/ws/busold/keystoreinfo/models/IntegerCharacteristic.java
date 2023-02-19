package ws.busold.keystoreinfo.models;

import android.content.Context;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class IntegerCharacteristic extends KeystoreCharacteristic {
    private int value;

    IntegerCharacteristic(ASN1Sequence hwEnforced, ASN1Sequence swEnforced, int tag) {
        super(hwEnforced, swEnforced, tag);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof IntegerCharacteristic) {
            IntegerCharacteristic other = (IntegerCharacteristic) obj;
            return super.equals(obj) && this.value == other.value;
        }
        return false;
    }

    @Override
    protected void fromASN1Primitive(ASN1Primitive object, KeystoreInfo.Source source) {
        this.value = ASN1Integer.getInstance(object).intValueExact();
        this.source = source;
    }

    @Override
    public String toString(Context context) {
        return super.toValueString(context, Integer.toString(value));
    }
}
