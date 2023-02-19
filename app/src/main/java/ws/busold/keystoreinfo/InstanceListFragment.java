package ws.busold.keystoreinfo;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.RecyclerView;

import ws.busold.keystoreinfo.adapters.KeystoreInfoRecyclerViewAdapter;
import ws.busold.keystoreinfo.models.DeviceInfo;
import ws.busold.keystoreinfo.viewmodels.InstanceViewModel;

public class InstanceListFragment extends Fragment {
    private InstanceViewModel model;
    private KeystoreInfoRecyclerViewAdapter adapter;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_instance_list, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        adapter = new KeystoreInfoRecyclerViewAdapter(this, new DeviceInfo(view.getContext()));

        model = new ViewModelProvider(requireActivity()).get(InstanceViewModel.class);
        model.getInstanceList(getContext()).observe(getViewLifecycleOwner(), instanceList -> adapter.setKeystoreInfo(instanceList));

        RecyclerView recyclerView = view.findViewById(R.id.instanceRecyclerView);
        recyclerView.setAdapter(adapter);
    }

    public InstanceViewModel getViewModel() {
        return model;
    }
}