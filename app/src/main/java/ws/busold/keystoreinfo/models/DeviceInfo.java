package ws.busold.keystoreinfo.models;

import android.content.Context;
import android.os.Build;
import android.security.ConfirmationPrompt;

public class DeviceInfo {
    private final boolean supportsProtectedConfirmation;

    public DeviceInfo(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            supportsProtectedConfirmation = ConfirmationPrompt.isSupported(context);
        } else {
            supportsProtectedConfirmation = false;
        }
    }

    public boolean supportsProtectedConfirmation() {
        return supportsProtectedConfirmation;
    }
}
