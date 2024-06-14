package ws.busold.keystoreinfo.models;

import android.content.Context;

import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.StringJoiner;

import ws.busold.keystoreinfo.R;

public class CertificateChainStatus {
    public static final String[] KEYSTORE_GOOGLE_CERTIFICATES = {
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\n" +
            "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\n" +
            "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\n" +
            "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\n" +
            "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\n" +
            "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\n" +
            "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\n" +
            "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\n" +
            "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\n" +
            "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\n" +
            "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\n" +
            "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==\n" +
            "-----END PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\n" +
            "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy\n" +
            "ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\n" +
            "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\n" +
            "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\n" +
            "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\n" +
            "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\n" +
            "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\n" +
            "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\n" +
            "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\n" +
            "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\n" +
            "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\n" +
            "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\n" +
            "AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD\n" +
            "VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO\n" +
            "BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk\n" +
            "Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD\n" +
            "ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB\n" +
            "Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m\n" +
            "qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY\n" +
            "DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm\n" +
            "QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u\n" +
            "JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD\n" +
            "CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy\n" +
            "ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD\n" +
            "qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic\n" +
            "MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1\n" +
            "wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk\n" +
            "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\n" +
            "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAz\n" +
            "NzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\n" +
            "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\n" +
            "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\n" +
            "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\n" +
            "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\n" +
            "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\n" +
            "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\n" +
            "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\n" +
            "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\n" +
            "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\n" +
            "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\n" +
            "AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud\n" +
            "IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD\n" +
            "VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnu\n" +
            "XKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U\n" +
            "h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cno\n" +
            "L/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2ok\n" +
            "QBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA\n" +
            "D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAI\n" +
            "mMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoW\n" +
            "Fua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91\n" +
            "oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09o\n" +
            "jm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUB\n" +
            "ZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH\n" +
            "ex0SdDrx+tWUDqG8At2JHA==\n" +
            "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFHDCCAwSgAwIBAgIJAMNrfES5rhgxMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\n" +
            "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjExMTE3MjMxMDQyWhcNMzYxMTEzMjMx\n" +
            "MDQyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\n" +
            "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\n" +
            "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\n" +
            "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\n" +
            "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\n" +
            "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\n" +
            "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\n" +
            "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\n" +
            "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\n" +
            "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\n" +
            "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\n" +
            "AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud\n" +
            "IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD\n" +
            "VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBTNNZe5cuf8oiq+jV0itTG\n" +
            "zWVhSTjOBEk2FQvh11J3o3lna0o7rd8RFHnN00q4hi6TapFhh4qaw/iG6Xg+xOan\n" +
            "63niLWIC5GOPFgPeYXM9+nBb3zZzC8ABypYuCusWCmt6Tn3+Pjbz3MTVhRGXuT/T\n" +
            "QH4KGFY4PhvzAyXwdjTOCXID+aHud4RLcSySr0Fq/L+R8TWalvM1wJJPhyRjqRCJ\n" +
            "erGtfBagiALzvhnmY7U1qFcS0NCnKjoO7oFedKdWlZz0YAfu3aGCJd4KHT0MsGiL\n" +
            "Zez9WP81xYSrKMNEsDK+zK5fVzw6jA7cxmpXcARTnmAuGUeI7VVDhDzKeVOctf3a\n" +
            "0qQLwC+d0+xrETZ4r2fRGNw2YEs2W8Qj6oDcfPvq9JySe7pJ6wcHnl5EZ0lwc4xH\n" +
            "7Y4Dx9RA1JlfooLMw3tOdJZH0enxPXaydfAD3YifeZpFaUzicHeLzVJLt9dvGB0b\n" +
            "HQLE4+EqKFgOZv2EoP686DQqbVS1u+9k0p2xbMA105TBIk7npraa8VM0fnrRKi7w\n" +
            "lZKwdH+aNAyhbXRW9xsnODJ+g8eF452zvbiKKngEKirK5LGieoXBX7tZ9D1GNBH2\n" +
            "Ob3bKOwwIWdEFle/YF/h6zWgdeoaNGDqVBrLr2+0DtWoiB1aDEjLWl9FmyIUyUm7\n" +
            "mD/vFDkzF+wm7cyWpQpCVQ==\n" +
            "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\n" +
            "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw\n" +
            "NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\n" +
            "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\n" +
            "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\n" +
            "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\n" +
            "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\n" +
            "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\n" +
            "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\n" +
            "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\n" +
            "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\n" +
            "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\n" +
            "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\n" +
            "AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud\n" +
            "IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD\n" +
            "VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7\n" +
            "174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC\n" +
            "W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G\n" +
            "tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx\n" +
            "oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG\n" +
            "1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF\n" +
            "mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz\n" +
            "lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw\n" +
            "n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu\n" +
            "zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo\n" +
            "vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn\n" +
            "w1IdYIg2Wxg7yHcQZemFQg==\n" +
            "-----END CERTIFICATE-----"
    };
    public static final String KEYSTORE_GOOGLE_CRL_URL = "https://android.googleapis.com/attestation/status";
    private final CertificateStatus certificateStatus;
    private final RevocationStatus revocationStatus;
    private boolean signedByGoogleRoot;
    private X509Certificate[] chain;

    public CertificateChainStatus() {
        this.certificateStatus = new CertificateStatus();
        this.revocationStatus = new RevocationStatus();
        this.signedByGoogleRoot = false;
        this.chain = new X509Certificate[0];
    }

    public CertificateChainStatus(X509Certificate @NotNull [] chain) {
        this();
        this.chain = chain;

        if (chain.length > 1) {
            try {
                for (int i = 0; i < chain.length - 1; i++) {
                    chain[i].verify(chain[i + 1].getPublicKey());
                    chain[i].checkValidity();
                }
                certificateStatus.setStatus(CertificateStatus.Status.Ok);
            } catch (SignatureException e) {
                certificateStatus.setStatus(CertificateStatus.Status.Invalid, CertificateStatus.Reason.InvalidSignature);
            } catch (CertificateExpiredException e) {
                certificateStatus.setStatus(CertificateStatus.Status.Invalid, CertificateStatus.Reason.ValidityExpired);
            } catch (CertificateNotYetValidException e) {
                certificateStatus.setStatus(CertificateStatus.Status.Invalid, CertificateStatus.Reason.ValidityNotYetValid);
            } catch (Exception e) {
                certificateStatus.setStatus(CertificateStatus.Status.Unknown, CertificateStatus.Reason.Unspecified);
            }
        } else {
            certificateStatus.setStatus(CertificateStatus.Status.Invalid, CertificateStatus.Reason.NoChain);
        }

        if (chain.length > 1) {
            try {
                byte[] root = chain[chain.length - 1].getEncoded();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");

                for (String cert_pem : KEYSTORE_GOOGLE_CERTIFICATES) {
                    Certificate cert = cf.generateCertificate(new ByteArrayInputStream(cert_pem.getBytes(StandardCharsets.UTF_8)));
                    if (Arrays.equals(cert.getEncoded(), root)) {
                        signedByGoogleRoot = true;
                        break;
                    }
                }
            } catch (Exception e) {
                signedByGoogleRoot = false;
            }
        }

        if (signedByGoogleRoot) {
            try {
                JsonObject entries = JsonParser.parseReader(new InputStreamReader(new URL(KEYSTORE_GOOGLE_CRL_URL).openStream())).getAsJsonObject().getAsJsonObject("entries");

                boolean found = false;
                for (X509Certificate cert : chain) {
                    String serial = cert.getSerialNumber().toString(16).toLowerCase();
                    if (entries.has(serial)) {
                        revocationStatus.setStatus(entries.get(serial).getAsJsonObject());
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    revocationStatus.setStatus(RevocationStatus.Status.Ok);
                }
            } catch (IOException | JsonIOException e) {
                revocationStatus.setStatus(RevocationStatus.Status.Unknown, RevocationStatus.Reason.NetworkError);
            } catch (IllegalStateException | JsonParseException e) {
                revocationStatus.setStatus(RevocationStatus.Status.Unknown, RevocationStatus.Reason.ParserError);
            } catch (Exception e) {
                revocationStatus.setStatus(RevocationStatus.Status.Unknown, RevocationStatus.Reason.Unspecified);
            }
        } else {
            revocationStatus.setStatus(RevocationStatus.Status.Unknown, RevocationStatus.Reason.NotGoogleRoot);
        }
    }

    public String toString(Context context) {
        StringJoiner serials = new StringJoiner(", ");
        for (X509Certificate cert : chain) {
            serials.add(cert.getSerialNumber().toString(16));
        }

        StringJoiner joiner = new StringJoiner("\n");

        joiner.add(context.getResources().getString(R.string.certificate_status) + ": " + certificateStatus.toString(context));
        joiner.add(context.getResources().getString(R.string.certificate_chain_length) + ": " + chain.length);
        joiner.add(context.getResources().getString(R.string.certificate_chain_serials) + ": " + serials);
        joiner.add(context.getResources().getString(R.string.certificate_signed_by_google_root) + ": " + (signedByGoogleRoot ? context.getResources().getString(R.string.yes) : context.getResources().getString(R.string.no)));
        joiner.add(context.getResources().getString(R.string.revocation_status) + ": " + revocationStatus.toString(context));

        return joiner.toString();
    }

    public X509Certificate[] getChain() {
        return chain;
    }

    public static class CertificateStatus {
        private Status status;
        private Reason reason;

        public CertificateStatus() {
            this.status = Status.Invalid;
            this.reason = Reason.NoChain;
        }

        public void setStatus(Status status) {
            this.status = status;
        }

        public void setStatus(Status status, Reason reason) {
            this.status = status;
            this.reason = reason;
        }

        public String toString(Context context) {
            return status.toString(context) + (status != Status.Ok ? " (" + reason.toString(context) + ")" : "");
        }

        public enum Status {
            Ok,
            Invalid,
            Unknown;

            public String toString(Context context) {
                switch (this) {
                    case Ok:
                        return context.getResources().getString(R.string.status_ok);
                    case Invalid:
                        return context.getResources().getString(R.string.status_invalid);
                    case Unknown:
                        return context.getResources().getString(R.string.status_unknown);
                    default:
                        return context.getResources().getString(R.string.value_error);
                }
            }
        }

        public enum Reason {
            Unspecified,
            NoChain,
            InvalidSignature,
            ValidityExpired,
            ValidityNotYetValid;

            public String toString(Context context) {
                switch (this) {
                    case Unspecified:
                        return context.getResources().getString(R.string.reason_unspecified);
                    case NoChain:
                        return context.getResources().getString(R.string.reason_no_chain);
                    case InvalidSignature:
                        return context.getResources().getString(R.string.reason_invalid_signature);
                    case ValidityExpired:
                        return context.getResources().getString(R.string.reason_validity_expired);
                    case ValidityNotYetValid:
                        return context.getResources().getString(R.string.reason_validity_not_yet_valid);
                    default:
                        return context.getResources().getString(R.string.value_error);
                }
            }
        }
    }

    public static class RevocationStatus {
        private Status status;
        private Reason reason;

        public RevocationStatus() {
            this.status = Status.Unknown;
            this.reason = Reason.Unspecified;
        }

        public void setStatus(Status status) {
            this.status = status;
        }

        public void setStatus(Status status, Reason reason) {
            this.status = status;
            this.reason = reason;
        }

        public void setStatus(@org.jetbrains.annotations.NotNull JsonObject entry) {
            setStatus(Status.fromString(entry.get("status").getAsString()), Reason.fromString(entry.get("reason").getAsString()));
        }

        public String toString(Context context) {
            return status.toString(context) + (status != Status.Ok ? " (" + reason.toString(context) + ")" : "");
        }

        public enum Status {
            Ok,
            Revoked,
            Suspended,
            Unknown;

            public static Status fromString(@NotNull String statusString) {
                switch (statusString) {
                    case "REVOKED":
                        return Revoked;
                    case "SUSPENDED":
                        return Suspended;
                    default:
                        throw new JsonParseException("Invalid status");
                }
            }

            public String toString(Context context) {
                switch (this) {
                    case Ok:
                        return context.getResources().getString(R.string.status_ok);
                    case Revoked:
                        return context.getResources().getString(R.string.status_revoked);
                    case Suspended:
                        return context.getResources().getString(R.string.status_suspended);
                    case Unknown:
                        return context.getResources().getString(R.string.status_unknown);
                    default:
                        return context.getResources().getString(R.string.value_error);
                }
            }
        }

        public enum Reason {
            Unspecified,
            KeyCompromise,
            CaCompromise,
            Superseded,
            SoftwareFlaw,
            ParserError,
            NetworkError,
            NotGoogleRoot;

            public static Reason fromString(String reasonString) {
                switch (reasonString) {
                    case "KEY_COMPROMISE":
                        return KeyCompromise;
                    case "CA_COMPROMISE":
                        return CaCompromise;
                    case "SUPERSEDED":
                        return Superseded;
                    case "SOFTWARE_FLAW":
                        return SoftwareFlaw;
                    default:
                        throw new JsonParseException("Invalid reason");
                }
            }

            public String toString(Context context) {
                switch (this) {
                    case Unspecified:
                        return context.getResources().getString(R.string.reason_unspecified);
                    case KeyCompromise:
                        return context.getResources().getString(R.string.reason_key_compromise);
                    case CaCompromise:
                        return context.getResources().getString(R.string.reason_ca_compromise);
                    case Superseded:
                        return context.getResources().getString(R.string.reason_superseded);
                    case SoftwareFlaw:
                        return context.getResources().getString(R.string.reason_software_flaw);
                    case ParserError:
                        return context.getResources().getString(R.string.reason_parser_error);
                    case NetworkError:
                        return context.getResources().getString(R.string.reason_network_error);
                    case NotGoogleRoot:
                        return context.getResources().getString(R.string.reason_not_google_root);
                    default:
                        return context.getResources().getString(R.string.value_error);
                }
            }
        }
    }
}