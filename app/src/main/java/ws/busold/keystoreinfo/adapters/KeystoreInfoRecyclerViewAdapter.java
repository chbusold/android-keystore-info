package ws.busold.keystoreinfo.adapters;

import android.annotation.SuppressLint;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.LinearLayout;
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
import ws.busold.keystoreinfo.models.DeviceInfo;
import ws.busold.keystoreinfo.models.KeystoreInfo;
import ws.busold.keystoreinfo.viewmodels.InstanceViewModel;

public class KeystoreInfoRecyclerViewAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {
    private final ArrayList<KeystoreInfo> instances;
    private final DeviceInfo device;
    private final InstanceListFragment fragment;
    private final int DEVICE_INFO_TYPE = 0;
    private final int KEYSTORE_INSTANCE_TYPE = 1;

    public KeystoreInfoRecyclerViewAdapter(InstanceListFragment fragment, DeviceInfo device) {
        this.instances = new ArrayList<>();
        this.fragment = fragment;
        this.device = device;
    }

    @Override
    public int getItemViewType(int position) {
        return position == 0 ? DEVICE_INFO_TYPE : KEYSTORE_INSTANCE_TYPE;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view;
        switch (viewType) {
            case DEVICE_INFO_TYPE:
                view = LayoutInflater.from(parent.getContext()).inflate(R.layout.device_info, parent, false);
                return new DeviceInfoViewHolder(view);
            case KEYSTORE_INSTANCE_TYPE:
                view = LayoutInflater.from(parent.getContext()).inflate(R.layout.keystore_instance, parent, false);
                return new KeystoreInfoViewHolder(view, fragment.getViewModel());
        }
        throw new RuntimeException();
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        switch (holder.getItemViewType()) {
            case DEVICE_INFO_TYPE:
                DeviceInfoViewHolder device = (DeviceInfoViewHolder) holder;
                device.setContent(this.device);
                break;
            case KEYSTORE_INSTANCE_TYPE:
                KeystoreInfoViewHolder instance = (KeystoreInfoViewHolder) holder;
                instance.setContent(this.instances.get(position - 1));
                break;
        }
    }

    @Override
    public int getItemCount() {
        return instances.size() + 1;
    }

    @SuppressLint("NotifyDataSetChanged")
    public void setKeystoreInfo(List<KeystoreInfo> data) {
        if (data != null) {
            this.instances.clear();
            this.instances.addAll(data);
            notifyDataSetChanged();
        }
    }

    public static class DeviceInfoViewHolder extends RecyclerView.ViewHolder {
        private final TextView instanceName;
        private final TextView protectedConfirmationAvailableValue;

        public DeviceInfoViewHolder(@NonNull View itemView) {
            super(itemView);

            instanceName = itemView.findViewById(R.id.instance_name);
            protectedConfirmationAvailableValue = itemView.findViewById(R.id.protected_confirmation_available_value);
        }

        public void setContent(@NotNull DeviceInfo content) {
            Context context = itemView.getContext();

            instanceName.setText(context.getResources().getText(R.string.device_information));
            protectedConfirmationAvailableValue.setText(context.getResources().getString(content.supportsProtectedConfirmation() ? R.string.yes : R.string.no));
        }
    }

    public static class KeystoreInfoViewHolder extends RecyclerView.ViewHolder {
        private final TextView instanceName;
        private final TextView availableValue;
        private final TextView attestRsaValue;
        private final TextView attestEccValue;
        private final TextView consistentValue;
        private final TextView attestationVersionValue;
        private final TextView rootOfTrustValue;
        private final TextView platformVersionsValue;
        private final TextView deviceIdentifiersValue;
        private final LinearLayout eccCertificateStatus;
        private final TextView eccCertificateStatusValue;
        private final LinearLayout rsaCertificateStatus;
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
            attestEccValue = itemView.findViewById(R.id.supports_attest_ecc_value);
            attestRsaValue = itemView.findViewById(R.id.supports_attest_rsa_value);
            consistentValue = itemView.findViewById(R.id.cert_info_consistent_value);
            attestationVersionValue = itemView.findViewById(R.id.attestation_version_value);
            rootOfTrustValue = itemView.findViewById(R.id.root_of_trust_value);
            platformVersionsValue = itemView.findViewById(R.id.platform_versions_value);
            deviceIdentifiersValue = itemView.findViewById(R.id.device_identifiers_value);
            eccCertificateStatus = itemView.findViewById(R.id.ecc_certificate_status);
            eccCertificateStatusValue = itemView.findViewById(R.id.ecc_certificate_status_value);
            rsaCertificateStatus = itemView.findViewById(R.id.rsa_certificate_status);
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
            availableValue.setText(context.getResources().getString(content.isAvailable() ? R.string.yes : R.string.no));

            if (content.isAvailable()) {
                attestRsaValue.setText(context.getResources().getString(content.supportsRsaAttest() ? R.string.yes : R.string.no));
                attestEccValue.setText(context.getResources().getString(content.supportsEccAttest() ? R.string.yes : R.string.no));
                consistentValue.setText(context.getResources().getString(content.isCertInfoConsistent() ? R.string.yes : R.string.no));
                attestationVersionValue.setText(content.getAttestationVersion(context));
                rootOfTrustValue.setText(content.getRootOfTrust(context));
                platformVersionsValue.setText(content.getPlatformVersions(context));
                deviceIdentifiersValue.setText(content.getDeviceIdentifiers(context));
                if (content.supportsEccAttest()) {
                    eccCertificateStatusValue.setText(content.getCertificateStatus(KeystoreInfo.KeyType.ecc).toString(context));
                } else {
                    eccCertificateStatus.setVisibility(View.GONE);
                    eccCertificateStatusValue.setVisibility(View.GONE);
                }
                if (content.supportsRsaAttest()) {
                    rsaCertificateStatusValue.setText(content.getCertificateStatus(KeystoreInfo.KeyType.rsa).toString(context));
                } else {
                    rsaCertificateStatus.setVisibility(View.GONE);
                    rsaCertificateStatusValue.setVisibility(View.GONE);
                }
            } else {
                detailsContainer.setVisibility(View.GONE);
            }
        }
    }
}
