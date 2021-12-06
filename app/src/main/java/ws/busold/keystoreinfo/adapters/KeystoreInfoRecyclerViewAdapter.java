package ws.busold.keystoreinfo.adapters;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.PopupMenu;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.navigation.Navigation;
import androidx.recyclerview.widget.RecyclerView;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

import ws.busold.keystoreinfo.InstanceListFragment;
import ws.busold.keystoreinfo.R;
import ws.busold.keystoreinfo.models.KeystoreInfo;
import ws.busold.keystoreinfo.viewmodels.InstanceViewModel;

public class KeystoreInfoRecyclerViewAdapter extends RecyclerView.Adapter<KeystoreInfoRecyclerViewAdapter.KeystoreInfoViewHolder> {
    private final ArrayList<KeystoreInfo> data;
    private final InstanceListFragment fragment;

    public KeystoreInfoRecyclerViewAdapter(InstanceListFragment fragment) {
        this.data = new ArrayList<>();
        this.fragment = fragment;
    }

    @NonNull
    @Override
    public KeystoreInfoViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.keystore_instance, parent, false);
        return new KeystoreInfoViewHolder(view, fragment.getViewModel());
    }

    @Override
    public void onBindViewHolder(@NonNull KeystoreInfoViewHolder holder, int position) {
        holder.setContent(data.get(position));
    }

    @Override
    public int getItemCount() {
        return data.size();
    }

    public void setData(List<KeystoreInfo> instances) {
        if (instances != null) {
            data.clear();
            data.addAll(instances);
            notifyDataSetChanged();
        }
    }

    public static class KeystoreInfoViewHolder extends RecyclerView.ViewHolder {
        private final TextView instanceName;
        private final TextView availableValue;
        private final TextView attestationVersionValue;
        private final TextView rootOfTrustValue;
        private final TextView platformVersionsValue;
        private final TextView deviceIdentifiersValue;
        private final TextView eccCertificateStatusValue;
        private final TextView rsaCertificateStatusValue;
        private final View detailsContainer;
        private final InstanceViewModel viewModel;
        private KeystoreInfo content;

        public KeystoreInfoViewHolder(@NonNull View itemView, InstanceViewModel viewModel) {
            super(itemView);

            this.viewModel = viewModel;
            this.content = null;

            instanceName = itemView.findViewById(R.id.instance_name);
            availableValue = itemView.findViewById(R.id.available_value);
            attestationVersionValue = itemView.findViewById(R.id.attestation_version_value);
            rootOfTrustValue = itemView.findViewById(R.id.root_of_trust_value);
            platformVersionsValue = itemView.findViewById(R.id.platform_versions_value);
            deviceIdentifiersValue = itemView.findViewById(R.id.device_identifiers_value);
            eccCertificateStatusValue = itemView.findViewById(R.id.ecc_certificate_status_value);
            rsaCertificateStatusValue = itemView.findViewById(R.id.rsa_certificate_status_value);
            detailsContainer = itemView.findViewById(R.id.details_container);

            ImageButton eccCertificateStatusOptions = itemView.findViewById(R.id.ecc_certificate_status_button);
            eccCertificateStatusOptions.setOnClickListener(createOnClickListener(KeystoreInfo.KeyType.ecc));

            ImageButton rsaCertificateStatusOptions = itemView.findViewById(R.id.rsa_certificate_status_button);
            rsaCertificateStatusOptions.setOnClickListener(createOnClickListener(KeystoreInfo.KeyType.rsa));
        }

        private PopupMenu.OnMenuItemClickListener createOnMenuItemClickListener(View v, KeystoreInfo.KeyType type) {
            return item -> {
                if (item.getItemId() == R.id.get_certificate_chain) {
                    if (content != null) {
                        if (content.isAvailable()) {
                            viewModel.setSelectedChain(content.getCertificateStatus(type));
                            Navigation.findNavController(v).navigate(R.id.action_instanceListFragment_to_certificateChainFragment);
                        }
                    }
                }
                return true;
            };
        }

        private View.OnClickListener createOnClickListener(KeystoreInfo.KeyType type) {
            return v -> {
                PopupMenu popup = new PopupMenu(v.getContext(), v);
                popup.getMenuInflater().inflate(R.menu.popup_certificate_status_options, popup.getMenu());
                popup.setOnMenuItemClickListener(createOnMenuItemClickListener(v, type));
                popup.show();
            };
        }

        public void setContent(@NotNull KeystoreInfo content) {
            this.content = content;
            Context context = itemView.getContext();

            instanceName.setText(content.getInstanceName());
            availableValue.setText(content.getAvailable(context));

            if (content.isAvailable()) {
                attestationVersionValue.setText(content.getAttestationVersion(context));
                rootOfTrustValue.setText(content.getRootOfTrust(context));
                platformVersionsValue.setText(content.getPlatformVersions(context));
                deviceIdentifiersValue.setText(content.getDeviceIdentifiers(context));
                eccCertificateStatusValue.setText(content.getEccCertificateStatus().toString(context));
                rsaCertificateStatusValue.setText(content.getRsaCertificateStatus().toString(context));
            } else {
                detailsContainer.setVisibility(View.GONE);
            }
        }
    }
}
