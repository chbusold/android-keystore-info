package ws.busold.keystoreinfo.models;

import android.content.Context;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

public abstract class KeystoreCharacteristic {
    private final int tag;
    protected KeystoreInfo.Source source;

    KeystoreCharacteristic() {
        tag = 0;
        source = KeystoreInfo.Source.notPresent;
    }

    KeystoreCharacteristic(ASN1Sequence hwEnforced, ASN1Sequence swEnforced, int tag) {
        this.tag = tag;
        get(hwEnforced, swEnforced);
    }

    abstract protected void fromASN1Primitive(ASN1Primitive object, KeystoreInfo.Source source);

    protected void get(ASN1Sequence hwEnforced, ASN1Sequence swEnforced) {
        for (ASN1Encodable asn1Encodable : hwEnforced) {
            ASN1TaggedObject characteristic = ASN1TaggedObject.getInstance(asn1Encodable);
            if (characteristic.getTagNo() == tag) {
                fromASN1Primitive(characteristic.getObject(), KeystoreInfo.Source.hwEnforced);
                return;
            }
        }

        for (ASN1Encodable asn1Encodable : swEnforced) {
            ASN1TaggedObject characteristic = ASN1TaggedObject.getInstance(asn1Encodable);
            if (characteristic.getTagNo() == tag) {
                fromASN1Primitive(characteristic.getObject(), KeystoreInfo.Source.swEnforced);
                return;
            }
        }

        source = KeystoreInfo.Source.notPresent;
    }

    public KeystoreInfo.Source getSource() {
        return source;
    }

    abstract public String toString(Context context);

    protected String toValueString(Context context, String value) {
        return source == KeystoreInfo.Source.notPresent ? source.toString(context) : value + " (" + source.toString(context) + ")";
    }
}
