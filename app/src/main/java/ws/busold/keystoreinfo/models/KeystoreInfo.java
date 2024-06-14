package ws.busold.keystoreinfo.models;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Objects;
import java.util.StringJoiner;

import ws.busold.keystoreinfo.R;

public class KeystoreInfo {
    public static final String KEYSTORE_X509_EXTENSION_ID = "1.3.6.1.4.1.11129.2.1.17";
    public static final int ASN1_TAG_OS_VERSION = 705;
    public static final int ASN1_TAG_OS_PATCHLEVEL = 706;
    public static final int ASN1_TAG_ID_BRAND = 710;
    public static final int ASN1_TAG_ID_DEVICE = 711;
    public static final int ASN1_TAG_ID_PRODUCT = 712;
    public static final int ASN1_TAG_ID_SERIAL = 713;
    public static final int ASN1_TAG_ID_IMEI = 714;
    public static final int ASN1_TAG_ID_MEID = 715;
    public static final int ASN1_TAG_ID_MANUFACTURER = 716;
    public static final int ASN1_TAG_ID_MODEL = 717;
    public static final int ASN1_TAG_VENDOR_PATCHLEVEL = 718;
    public static final int ASN1_TAG_BOOT_PATCHLEVEL = 719;
    private final CertInfo ecc = new CertInfo();
    private final CertInfo rsa = new CertInfo();
    private final String instanceName;
    private boolean available;
    private boolean consistent;

    public KeystoreInfo(String name, boolean strongbox) {
        this.instanceName = name;

        try {
            Certificate[] chain = loadKey(KeyType.rsa, strongbox, false);
            available = chain != null;
        } catch (Exception e) {
            available = false;
        }

        if (available) {
            ecc.createAttestation(KeyType.ecc, strongbox);
            rsa.createAttestation(KeyType.rsa, strongbox);
            consistent = !ecc.canAttest || !rsa.canAttest || rsa.infoEquals(ecc);
        }
    }

    private static Certificate[] loadKey(KeyType type, boolean strongbox, boolean attestation) {
        String name = "keystore-info-" + type.toString() + (strongbox ? "-sb" : "") + (attestation ? "-att" : "");
        Certificate[] chain;

        try {
            KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");
            keystore.load(null);
            chain = keystore.getCertificateChain(name);
            if (chain == null) {
                createKey(name, type, strongbox, attestation);
                chain = keystore.getCertificateChain(name);
            }
        } catch (Exception e) {
            chain = null;
        }

        return chain;
    }

    private static void createKey(String name, KeyType type, boolean strongbox, boolean attestation)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
                name,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(type.getSpec())
                .setDigests(KeyProperties.DIGEST_SHA256);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            spec.setIsStrongBoxBacked(strongbox);
        } else {
            // Versions below do not support strongbox API, so we cannot create this key
            if (strongbox) {
                throw new NoSuchProviderException();
            }
        }

        if (attestation) {
            spec.setAttestationChallenge(name.getBytes(StandardCharsets.UTF_8));
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(type.getAlg(), "AndroidKeyStore");
        kpg.initialize(spec.build());
        kpg.generateKeyPair();
    }

    private static void deleteKey(KeyType type, boolean strongbox, boolean attestation) {
        String name = "keystore-info-" + type.toString() + (strongbox ? "-sb" : "") + (attestation ? "-att" : "");

        try {
            KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");
            keystore.load(null);
            keystore.deleteEntry(name);
        } catch (Exception ignored) {

        }
    }

    public boolean isAvailable() {
        return available;
    }

    public String getInstanceName() {
        return instanceName;
    }

    public boolean supportsRsaAttest() {
        return rsa.canAttest;
    }

    public boolean supportsEccAttest() {
        return ecc.canAttest;
    }

    public boolean isCertInfoConsistent() {
        return consistent;
    }

    public String getAttestationVersion(Context context) {
        return rsa.canAttest ? rsa.getAttestationVersion(context) : ecc.getAttestationVersion(context);
    }

    public String getRootOfTrust(Context context) {
        return rsa.canAttest ? rsa.getRootOfTrust(context) : ecc.getRootOfTrust(context);
    }

    public String getPlatformVersions(Context context) {
        return rsa.canAttest ? rsa.getPlatformVersions(context) : ecc.getPlatformVersions(context);
    }

    public String getDeviceIdentifiers(Context context) {
        return rsa.canAttest ? rsa.getDeviceIdentifiers(context) : ecc.getDeviceIdentifiers(context);
    }

    public CertificateChainStatus getCertificateStatus(KeyType type) {
        switch (type) {
            case ecc:
                return ecc.certificateChainStatus;
            case rsa:
                return rsa.certificateChainStatus;
        }
        return null;
    }

    public enum SecurityLevel {
        Software,
        TrustedEnvironment,
        StrongBox,
        None;

        public static SecurityLevel fromASN1Enumerated(@NotNull ASN1Enumerated object) {
            switch (object.intValueExact()) {
                case 0:
                    return SecurityLevel.Software;
                case 1:
                    return SecurityLevel.TrustedEnvironment;
                case 2:
                    return SecurityLevel.StrongBox;
                default:
                    return SecurityLevel.None;
            }
        }

        public String toString(Context context) {
            switch (this) {
                case Software:
                    return "Software";
                case TrustedEnvironment:
                    return "Trusted Execution Environment";
                case StrongBox:
                    return "Strongbox";
                case None:
                    return context.getResources().getString(R.string.not_present);
            }
            return context.getResources().getString(R.string.value_error);
        }
    }

    public enum Source {
        hwEnforced,
        swEnforced,
        notPresent;

        public String toString(Context context) {
            switch (this) {
                case hwEnforced:
                    return context.getString(R.string.hw_enforced);
                case swEnforced:
                    return context.getString(R.string.sw_enforced);
                case notPresent:
                    return context.getResources().getString(R.string.not_present);
            }
            return context.getResources().getString(R.string.value_error);
        }
    }

    public enum KeyType {
        ecc,
        rsa;

        AlgorithmParameterSpec getSpec() throws InvalidAlgorithmParameterException {
            switch (this) {
                case ecc:
                    return new ECGenParameterSpec("secp256r1");
                case rsa:
                    return new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
            }
            throw new InvalidAlgorithmParameterException();
        }

        String getAlg() throws InvalidAlgorithmParameterException {
            switch (this) {
                case ecc:
                    return KeyProperties.KEY_ALGORITHM_EC;
                case rsa:
                    return KeyProperties.KEY_ALGORITHM_RSA;
            }
            throw new InvalidAlgorithmParameterException();
        }
    }

    private static class CharacteristicMap<T extends KeystoreCharacteristic> extends HashMap<String, T> {
        public String toString(Context context) {
            StringJoiner joiner = new StringJoiner("\n");

            for (String key : keySet()) {
                if (Objects.requireNonNull(get(key)).getSource() != Source.notPresent) {
                    joiner.add(key + ": " + Objects.requireNonNull(get(key)).toString(context));
                }
            }

            return joiner.length() == 0 ? context.getResources().getString(R.string.not_present) : joiner.toString();
        }
    }

    private static class CertInfo {
        public final CharacteristicMap<IntegerCharacteristic> platformVersions = new CharacteristicMap<>();
        public final CharacteristicMap<ByteArrayCharacteristic> deviceIdentifiers = new CharacteristicMap<>();
        public boolean canAttest;
        public int attestationVersion;
        public SecurityLevel attestationSecurityLevel;
        public int keymasterVersion;
        public SecurityLevel keymasterSecurityLevel;
        public RootOfTrust rootOfTrust;
        public CertificateChainStatus certificateChainStatus;

        private void extractKeyInfo(X509Certificate certificate) throws IOException {
            byte[] extension = certificate.getExtensionValue(KEYSTORE_X509_EXTENSION_ID);
            byte[] content = DEROctetString.getInstance(ASN1Primitive.fromByteArray(extension)).getOctets();
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(content));

            attestationVersion = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
            attestationSecurityLevel = SecurityLevel.fromASN1Enumerated(ASN1Enumerated.getInstance(seq.getObjectAt(1)));
            keymasterVersion = ASN1Integer.getInstance(seq.getObjectAt(2)).intValueExact();
            keymasterSecurityLevel = SecurityLevel.fromASN1Enumerated(ASN1Enumerated.getInstance(seq.getObjectAt(3)));

            ASN1Sequence swEnforced = ASN1Sequence.getInstance(seq.getObjectAt(6));
            ASN1Sequence hwEnforced = ASN1Sequence.getInstance(seq.getObjectAt(7));

            rootOfTrust = new RootOfTrust(hwEnforced, swEnforced);

            platformVersions.put("OS Version", new IntegerCharacteristic(hwEnforced, swEnforced, ASN1_TAG_OS_VERSION));
            platformVersions.put("OS Patchlevel", new IntegerCharacteristic(hwEnforced, swEnforced, ASN1_TAG_OS_PATCHLEVEL));
            platformVersions.put("Vendor Patchlevel", new IntegerCharacteristic(hwEnforced, swEnforced, ASN1_TAG_VENDOR_PATCHLEVEL));
            platformVersions.put("Boot Patchlevel", new IntegerCharacteristic(hwEnforced, swEnforced, ASN1_TAG_BOOT_PATCHLEVEL));

            deviceIdentifiers.put("Brand", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_BRAND));
            deviceIdentifiers.put("Device", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_DEVICE));
            deviceIdentifiers.put("Product", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_PRODUCT));
            deviceIdentifiers.put("Serial", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_SERIAL));
            deviceIdentifiers.put("IMEI", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_IMEI));
            deviceIdentifiers.put("MEID", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_MEID));
            deviceIdentifiers.put("Manufacturer", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_MANUFACTURER));
            deviceIdentifiers.put("Model", new ByteArrayCharacteristic(hwEnforced, swEnforced, ASN1_TAG_ID_MODEL));
        }

        public boolean infoEquals(CertInfo other) {
            return this.attestationSecurityLevel == other.attestationSecurityLevel
                   && this.attestationVersion == other.attestationVersion
                   && this.keymasterVersion == other.keymasterVersion
                   && this.keymasterSecurityLevel == other.keymasterSecurityLevel
                   && this.rootOfTrust.equals(other.rootOfTrust)
                   && this.platformVersions.equals(other.platformVersions)
                   && this.deviceIdentifiers.equals(other.deviceIdentifiers);
        }

        public void createAttestation(KeyType type, boolean strongbox) {
            try {
                deleteKey(type, strongbox, true);
                Certificate[] chain = loadKey(type, strongbox, true);

                X509Certificate[] x509Chain = new X509Certificate[chain.length];
                for (int i = 0; i < chain.length; i++) {
                    x509Chain[i] = (X509Certificate) chain[i];
                }
                certificateChainStatus = new CertificateChainStatus(x509Chain);

                extractKeyInfo(x509Chain[0]);

                canAttest = true;
            } catch (Exception e) {
                canAttest = false;
                certificateChainStatus = new CertificateChainStatus();
            }
        }

        public String getAttestationVersion(Context context) {
            StringJoiner joiner = new StringJoiner("\n");

            joiner.add("Attestation Version: " + attestationVersion);
            joiner.add("Attestation Security Level: " + attestationSecurityLevel.toString(context));
            joiner.add("Keymaster Version: " + keymasterVersion);
            joiner.add("Keymaster Security Level: " + keymasterSecurityLevel.toString(context));

            return joiner.toString();
        }

        public String getRootOfTrust(Context context) {
            return rootOfTrust.toString(context);
        }

        public String getPlatformVersions(Context context) {
            return platformVersions.toString(context);
        }

        public String getDeviceIdentifiers(Context context) {
            return deviceIdentifiers.toString(context);
        }
    }
}
