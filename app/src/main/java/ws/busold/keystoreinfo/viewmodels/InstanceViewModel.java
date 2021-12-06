package ws.busold.keystoreinfo.viewmodels;

import android.content.Context;
import android.os.AsyncTask;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ws.busold.keystoreinfo.R;
import ws.busold.keystoreinfo.models.CertificateChainStatus;
import ws.busold.keystoreinfo.models.KeystoreInfo;

public class InstanceViewModel extends ViewModel {
    private MutableLiveData<List<KeystoreInfo>> instanceList;
    private final MutableLiveData<CertificateChainStatus> selectedChain = new MutableLiveData<>();

    public LiveData<List<KeystoreInfo>> getInstanceList(Context context) {
        if (instanceList == null) {
            instanceList = new MutableLiveData<>();
            new CollectKeystoreInfo(context, instanceList).execute();
        }
        return instanceList;
    }

    public void setSelectedChain(CertificateChainStatus chain) {
        selectedChain.setValue(chain);
    }

    public LiveData<CertificateChainStatus> getSelectedChain() {
        return selectedChain;
    }

    static class CollectKeystoreInfo extends AsyncTask<Void, Void, ArrayList<KeystoreInfo>> {
        private final MutableLiveData<List<KeystoreInfo>> instanceList;
        private final HashMap<String, Boolean> instanceNames;

        public CollectKeystoreInfo(@NotNull Context context, MutableLiveData<List<KeystoreInfo>> instanceList) {
            this.instanceList = instanceList;
            this.instanceNames = new HashMap<>();
            instanceNames.put(context.getString(R.string.default_instance), false);
            instanceNames.put(context.getString(R.string.strongbox_instance), true);
        }

        @Override
        protected ArrayList<KeystoreInfo> doInBackground(Void... voids) {
            ArrayList<KeystoreInfo> infoData = new ArrayList<>();
            for(String name : instanceNames.keySet()) {
                infoData.add(new KeystoreInfo(name, instanceNames.get(name)));
            }
            return infoData;
        }

        @Override
        protected void onPostExecute(final @NotNull ArrayList<KeystoreInfo> result) {
            instanceList.setValue(result);
        }
    }
}
