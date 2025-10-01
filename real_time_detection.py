import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

# Load dataset with caching for performance
@st.cache_data
def load_data(file_path):
    return pd.read_csv(file_path)

# Detect suspicious IPs based on packet count threshold
def detect_suspicious_ips(df, threshold=500):
    ip_counts = df['Source'].value_counts()
    suspicious_ips = ip_counts[ip_counts > threshold]
    return suspicious_ips

def main():
    st.title("Network Traffic Dashboard - RLJIT")

    uploaded_file = st.file_uploader("Upload your network traffic CSV file", type=["csv"])
    if uploaded_file is not None:
        df = load_data(uploaded_file)

        st.subheader("Raw Data Sample")
        st.dataframe(df.head())

        # Basic stats
        packet_count = len(df)
        unique_ips = df['Source'].nunique()
        avg_packet_size = df['Length'].mean()

        st.metric("Total Packet Count", packet_count)
        st.metric("Unique Source IPs", unique_ips)
        st.metric("Average Packet Size (bytes)", f"{avg_packet_size:.2f}")

        # Detection threshold slider
        threshold = st.slider("Suspicious Packet Count Threshold", min_value=100, max_value=5000, value=500, step=100)
        suspicious_ips = detect_suspicious_ips(df, threshold)

        # Detection status display
        if suspicious_ips.empty:
            detection_status = "NO ATTACK DETECTED"
            st.success(f"✅ {detection_status}")
        else:
            detection_status = "UNDER ATTACK"
            st.error(f"⚠ {detection_status} - {len(suspicious_ips)} suspicious IP(s) detected")

            st.subheader("Suspicious IPs and Packet Counts")
            st.dataframe(suspicious_ips)

        st.metric("Detection Status", detection_status)

        # Plot: Top 20 Source IPs by Packet Count
        st.subheader("Top 20 Source IPs by Packet Count")
        top_ips = df['Source'].value_counts().head(20)

        fig, ax = plt.subplots(figsize=(10,6))
        sns.barplot(x=top_ips.values, y=top_ips.index, ax=ax, palette="viridis")
        ax.set_xlabel("Packet Count")
        ax.set_ylabel("Source IP")
        st.pyplot(fig)

        # Plot: Packet Size Distribution
        st.subheader("Packet Size Distribution")
        fig2, ax2 = plt.subplots()
        sns.histplot(df['Length'], bins=50, kde=True, ax=ax2)
        ax2.set_xlabel("Packet Size (bytes)")
        st.pyplot(fig2)

if __name__== "__main__":
    main()