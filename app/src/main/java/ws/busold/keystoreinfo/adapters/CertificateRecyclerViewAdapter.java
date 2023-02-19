package ws.busold.keystoreinfo.adapters;

import android.annotation.SuppressLint;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import ws.busold.keystoreinfo.CertificateChainFragment;
import ws.busold.keystoreinfo.R;

public class CertificateRecyclerViewAdapter extends RecyclerView.Adapter<CertificateRecyclerViewAdapter.CertificateViewHolder> {
    private final ArrayList<X509Certificate> data;
    private final CertificateChainFragment fragment;

    public CertificateRecyclerViewAdapter(CertificateChainFragment fragment) {
        this.data = new ArrayList<>();
        this.fragment = fragment;
    }

    @NonNull
    @Override
    public CertificateViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.certificate_content, parent, false);
        return new CertificateViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull CertificateViewHolder holder, int position) {
        holder.setContent(getCertificateTitle(position), data.get(position));
    }

    @Override
    public int getItemCount() {
        return data.size();
    }

    @SuppressLint("NotifyDataSetChanged")
    public void setData(X509Certificate[] chain) {
        if (chain != null) {
            data.clear();
            data.addAll(Arrays.asList(chain));
            Collections.reverse(data);
            notifyDataSetChanged();
        }
    }

    private String getCertificateTitle(int position) {
        String title;
        if (position == data.size() - 1) {
            title = fragment.requireContext().getString(R.string.leaf_cert);
        } else if (position == data.size() - 2) {
            title = fragment.requireContext().getString(R.string.device_cert);
        } else if (position == 0) {
            title = fragment.requireContext().getString(R.string.root_cert);
        } else {
            title = fragment.requireContext().getString(R.string.intermediate_cert);
        }
        return title;
    }

    public static class CertificateViewHolder extends RecyclerView.ViewHolder {
        private final TextView certificateTitle;
        private final View certificateContent;
        private final TextView certificateText;
        private final ImageButton collapseButton;
        private boolean expanded;

        public CertificateViewHolder(@NonNull View itemView) {
            super(itemView);

            certificateTitle = itemView.findViewById(R.id.certificateTitle);
            certificateContent = itemView.findViewById(R.id.certificateContent);
            certificateText = itemView.findViewById(R.id.certificateText);
            collapseButton = itemView.findViewById(R.id.certificateCollapser);

            expanded = true;
            View.OnClickListener listener = v -> {
                expanded = !expanded;
                certificateContent.setVisibility(expanded ? View.VISIBLE : View.GONE);
                collapseButton.animate().setDuration(200).rotation(expanded ? 0 : 180);
            };
            collapseButton.setOnClickListener(listener);
            certificateTitle.setOnClickListener(listener);
        }

        public void setContent(String title, X509Certificate content) {
            certificateTitle.setText(title);
            certificateText.setText(content.toString());
        }
    }
}
