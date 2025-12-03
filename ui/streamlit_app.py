import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import streamlit as st
import pandas as pd

from core.pipeline import run_scan

st.set_page_config(
    page_title="CT-Driven Subdomain Hunter",
    layout="wide"
)

st.title("🔍 CT-Driven Subdomain Hunter")
st.write(
    "Passive subdomain discovery and risk scoring using Certificate Transparency logs."
)

domain = st.text_input("Target root domain", value="example.com")
run_button = st.button("Run Scan")

if run_button:
    if not domain.strip():
        st.error("Please enter a valid domain.")
    else:
        with st.spinner("Running scan..."):
            findings = run_scan(domain.strip())

        if not findings:
            st.warning("No subdomains found.")
        else:
            df = pd.DataFrame(findings)

            st.subheader("🆕 New subdomains in this scan")
            new_df = df[df["is_new"] == True]
            if new_df.empty:
                st.info("No new subdomains detected.")
            else:
                st.dataframe(
                    new_df[
                        ["subdomain", "ip", "asn", "status_code",
                         "severity", "risk_score", "risk_tags"]
                    ]
                )

            st.subheader("📋 All discovered subdomains")
            severity_filter = st.multiselect(
                "Filter by severity",
                options=["critical", "high", "medium", "low"],
                default=["critical", "high", "medium", "low"],
            )

            filtered_df = df[df["severity"].isin(severity_filter)]
            st.dataframe(
                filtered_df[
                    ["subdomain", "ip", "asn", "status_code",
                     "title", "severity", "risk_score", "risk_tags"]
                ]
            )

            csv = filtered_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download CSV report",
                data=csv,
                file_name=f"{domain}_ct_subdomain_report.csv",
                mime="text/csv",
            )
else:
    st.info("Enter a domain and click **Run Scan** to start.")
