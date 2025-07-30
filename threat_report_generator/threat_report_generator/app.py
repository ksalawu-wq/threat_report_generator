import streamlit as st
from utils import save_uploaded_file, parse_log_file, generate_report

st.set_page_config(page_title="AI Threat Report Generator", layout="wide")

st.title("🛡️ AI Threat Report Generator")
st.markdown("Upload a `.txt`, `.log`, or `.pcap` file to generate a semi-detailed cyber threat report.")

uploaded_file = st.file_uploader("Upload File", type=["log", "txt", "pcap"])

if uploaded_file:
    filepath = save_uploaded_file(uploaded_file)
    st.write("Saved file to:", filepath)

    # Parse the file depending on type
    if uploaded_file.name.endswith(".pcap"):
        st.write("Parsing PCAP...")
        parsed_logs, metadata = parse_log_file(filepath, is_pcap=True)
    else:
        st.write("Parsing TXT...")
        parsed_logs, metadata = parse_log_file(filepath)

        st.write("Parsed logs preview:")
        st.text(parsed_logs[:1000])

    if parsed_logs:
        st.success("File parsed successfully!")
        if st.button("🧠 Generate Threat Report", key="generate_report"):
            with st.spinner("Analyzing and generating report..."):
                report = generate_report(parsed_logs, metadata)
                st.subheader("📄 Threat Report")
                st.text_area("Executive Summary", report["executive_summary"], height=200)
                st.text_area("Indicators of Compromise (IOCs)", "\n".join(report["iocs"]), height=150)
                st.text_area("Timeline of Events", report["timeline"], height=200)
                st.text_area("Remediation Steps", "\n".join(report["remediation"]), height=150)
                st.text_area("C2 Communication Pattern", report["c2_traffic"], height=150)
                st.text_area("Initial Compromise Analysis", report["compromise_analysis"], height=150)


                if report.get("c2_communications"):
                    st.text_area("C2 Communication Patterns", "\n".join(report["c2_communications"]), height=200)

                if report.get("initial_compromise"):
                    st.text_area("Initial Compromise Analysis", report["initial_compromise"], height=200)
