package ws.busold.keystoreinfo.models;

import android.content.Context;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;

public class ByteArrayCharacteristic extends KeystoreCharacteristic {
    private byte[] value;

    ByteArrayCharacteristic(ASN1Sequence hwEnforced, ASN1Sequence swEnforced, int tag) {
        super(hwEnforced, swEnforced, tag);
    }

    @Override
    protected void fromASN1Primitive(ASN1Primitive object, KeystoreInfo.Source source) {
        this.value = ASN1OctetString.getInstance(object).getOctets();
        this.source = source;
    }

    @Override
    public String toString(Context context) {
        return super.toValueString(context, Hex.toHexString(value));
    }
}
