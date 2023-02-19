package ws.busold.keystoreinfo.models;

import android.content.Context;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.StringJoiner;

import ws.busold.keystoreinfo.R;

public class RootOfTrust extends KeystoreCharacteristic {
    public static final int ASN1_TAG_ROOT_OF_TRUST = 704;
    private byte[] verifiedBootKey;
    private boolean deviceLocked;
    private VerifiedBootState verifiedBootState;
    private byte[] verifiedBootHash;

    RootOfTrust(ASN1Sequence hwEnforced, ASN1Sequence swEnforced) {
        super(hwEnforced, swEnforced, ASN1_TAG_ROOT_OF_TRUST);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof RootOfTrust) {
            RootOfTrust other = (RootOfTrust) obj;
            return super.equals(obj)
                && Arrays.equals(this.verifiedBootKey, other.verifiedBootKey)
                && this.deviceLocked == other.deviceLocked
                && Arrays.equals(this.verifiedBootHash, other.verifiedBootHash)
                && this.verifiedBootState == other.verifiedBootState;
        }
        return false;
    }

    @Override
    protected void fromASN1Primitive(ASN1Primitive object, KeystoreInfo.Source source) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(object);
        this.verifiedBootKey = ASN1OctetString.getInstance(sequence.getObjectAt(0)).getOctets();
        this.deviceLocked = ASN1Boolean.getInstance(sequence.getObjectAt(1)).isTrue();
        this.verifiedBootState = verifiedBootStateFromASN1Enumerated(ASN1Enumerated.getInstance(sequence.getObjectAt(2)));
        this.verifiedBootHash = ASN1OctetString.getInstance(sequence.getObjectAt(3)).getOctets();
        this.source = source;
    }

    private static VerifiedBootState verifiedBootStateFromASN1Enumerated(@NotNull ASN1Enumerated object) {
        switch (object.intValueExact()) {
            case 0:
                return VerifiedBootState.Verified;
            case 1:
                return VerifiedBootState.SelfSigned;
            case 2:
                return VerifiedBootState.Unverified;
            case 3:
                return VerifiedBootState.Failed;
            default:
                return VerifiedBootState.None;
        }
    }

    @Override
    public String toString(Context context) {
        StringJoiner joiner = new StringJoiner("\n");

        if (source == KeystoreInfo.Source.notPresent) {
            joiner.add(source.toString(context));
        } else {
            joiner.add(context.getString(R.string.present) + " (" + source.toString(context) + ")");
            joiner.add("Device Lock State: " + (deviceLocked ? "Locked" : "Unlocked"));
            joiner.add("Verified Boot State: " + verifiedBootState.toString(context));
            joiner.add("Verified Boot Key: " + Hex.toHexString(verifiedBootKey));
            joiner.add("Verified Boot Hash: " + Hex.toHexString(verifiedBootHash));
        }

        return joiner.toString();
    }

    public enum VerifiedBootState {
        Verified,
        SelfSigned,
        Unverified,
        Failed,
        None;

        public String toString(Context context) {
            switch (this) {
                case Verified:
                    return "Verified (Green)";
                case SelfSigned:
                    return "Self-signed (Yellow)";
                case Unverified:
                    return "Unverified (Red)";
                case Failed:
                    return "Failed (Red)";
                case None:
                    return context.getResources().getString(R.string.not_present);
            }
            return context.getResources().getString(R.string.value_error);
        }
    }
}