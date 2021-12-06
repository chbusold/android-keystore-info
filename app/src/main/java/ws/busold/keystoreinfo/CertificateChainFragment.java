package ws.busold.keystoreinfo;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.RecyclerView;

import ws.busold.keystoreinfo.adapters.CertificateRecyclerViewAdapter;
import ws.busold.keystoreinfo.viewmodels.InstanceViewModel;

public class CertificateChainFragment extends Fragment {
    private CertificateRecyclerViewAdapter adapter;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_certificate_chain, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        adapter = new CertificateRecyclerViewAdapter(this);

        InstanceViewModel model = new ViewModelProvider(requireActivity()).get(InstanceViewModel.class);
        model.getSelectedChain().observe(getViewLifecycleOwner(), chain -> adapter.setData(chain.getChain()));

        RecyclerView recyclerView = view.findViewById(R.id.certificateRecyclerView);
        recyclerView.setAdapter(adapter);
    }
}