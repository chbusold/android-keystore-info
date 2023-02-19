package ws.busold.keystoreinfo.viewmodels;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import ws.busold.keystoreinfo.R;
import ws.busold.keystoreinfo.models.CertificateChainStatus;
import ws.busold.keystoreinfo.models.KeystoreInfo;

public class InstanceViewModel extends ViewModel {
    private MutableLiveData<List<KeystoreInfo>> instanceList;
    private final MutableLiveData<CertificateChainStatus> selectedChain = new MutableLiveData<>();

    public LiveData<List<KeystoreInfo>> getInstanceList(Context context) {
        if (instanceList == null) {
            instanceList = new MutableLiveData<>();

            ExecutorService executor = Executors.newSingleThreadExecutor();
            Handler handler = new Handler(Looper.getMainLooper());

            executor.execute(() -> {
                ArrayList<KeystoreInfo> info = new ArrayList<>();
                info.add(new KeystoreInfo(context.getString(R.string.default_instance), false));
                info.add(new KeystoreInfo(context.getString(R.string.strongbox_instance), true));

                handler.post(() -> instanceList.setValue(info));
            });
        }
        return instanceList;
    }

    public void setSelectedChain(CertificateChainStatus chain) {
        selectedChain.setValue(chain);
    }

    public LiveData<CertificateChainStatus> getSelectedChain() {
        return selectedChain;
    }
}
