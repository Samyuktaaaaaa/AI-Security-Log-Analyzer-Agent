import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import google.generativeai as genai
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from dotenv import load_dotenv
import os

st.set_page_config(
    page_title="AI Security Log Analyzer",
    page_icon="🛡️"
)
st.title("🛡️AI Security Log Analyzer Agent")
st.write("Upload a network log file and detect suspicious activity using Machine Learning and Gemini AI")

# Load environment variables
load_dotenv()
genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)
model_gemini=genai.GenerativeModel(
    "gemini-2.5-flash"
)
def get_severity_label(risk_score):

    if risk_score > 80:
        return "CRITICAL"
    elif risk_score > 50:
        return "HIGH"
    elif risk_score > 20:
        return "MEDIUM"
    else:
        return "LOW"


def generate_pdf(dataframe, risk_score):

    file_name = "SOC_Incident_Report.pdf"
    doc = SimpleDocTemplate(file_name)

    styles = getSampleStyleSheet()
    content = []

    severity = get_severity_label(risk_score)

    content.append(Paragraph("SOC Incident Report", styles["Title"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph(f"<b>Risk Score:</b> {risk_score}", styles["Normal"]))
    content.append(Spacer(1, 6))

    if severity == "CRITICAL":
        severity_text = f"<b><font color='red'>SEVERITY: {severity}</font></b>"
    elif severity == "HIGH":
        severity_text = f"<b><font color='orange'>SEVERITY: {severity}</font></b>"
    elif severity == "MEDIUM":
        severity_text = f"<b><font color='blue'>SEVERITY: {severity}</font></b>"
    else:
        severity_text = f"<b><font color='green'>SEVERITY: {severity}</font></b>"

    content.append(Paragraph(severity_text, styles["Normal"]))
    content.append(Spacer(1, 12))

    table_data = [list(dataframe.columns)] + dataframe.values.tolist()

    table = Table(table_data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold")
    ]))

    content.append(table)

    doc.build(content)

    return file_name
MITRE_MAPPING = {
    "brute_force": {
        "technique": "T1110 - Brute Force",
        "tactic": "Credential Access"
    },
    "credential_stuffing": {
        "technique": "T1110.004 - Credential Stuffing",
        "tactic": "Credential Access"
    },
    "suspicious_login_spike": {
        "technique": "T1078 - Valid Accounts Abuse",
        "tactic": "Initial Access"
    },
    "data_exfiltration": {
        "technique": "T1041 - Exfiltration Over C2 Channel",
        "tactic": "Exfiltration"
    },
    "port_scan": {
        "technique": "T1046 - Network Service Discovery",
        "tactic": "Discovery"
    }
}
def classify_attack(row):

    if row["failed_attempts"] >= 20:
        return "brute_force"

    elif row["login_count"] >= 40:
        return "suspicious_login_spike"

    elif row["file_accesses"] >= 50:
        return "data_exfiltration"

    else:
        return "unknown"
uploaded_file = st.file_uploader("Upload Network Logs", type=["csv"])
if uploaded_file:
    df=pd.read_csv(uploaded_file)
    st.subheader("Updated Logs")
    st.dataframe(df)
    features = df[
        [
        "failed_attempts",
        "login_count",
        "file_accesses"
        ]
        ]
    model = IsolationForest(
        contamination=0.2,
        random_state=42
        )
    df["anomaly"] = model.fit_predict(features)
    anomalies = df[
        df["anomaly"] == -1
        ]
    st.subheader("Detected Anomalies")
    st.dataframe(anomalies)
    risk_score = len(anomalies) * 20
    st.metric(
        "Risk Score",
        risk_score
        )
    normal = df[df["anomaly"] == 1]
    abnormal = df[df["anomaly"] == -1]
    fig, ax = plt.subplots(figsize=(8,5))
    ax.scatter(
        normal["login_count"],
        normal["failed_attempts"],
        label="Normal"
        )
    ax.scatter(
        abnormal["login_count"],
        abnormal["failed_attempts"],
        label="Anomaly"
        )
    ax.set_xlabel("Login Count")
    ax.set_ylabel("Failed Attempts")
    ax.legend()
    st.pyplot(fig)
    anomalies = anomalies.copy()
    anomalies["attack_type"] = anomalies.apply(classify_attack, axis=1)

    anomalies["mitre_technique"] = anomalies["attack_type"].map(
        lambda x: MITRE_MAPPING.get(x, {}).get("technique", "Unknown")
    )

    anomalies["mitre_tactic"] = anomalies["attack_type"].map(
        lambda x: MITRE_MAPPING.get(x, {}).get("tactic", "Unknown")
    )
    structured_anomalies = anomalies[[
    "attack_type",
    "mitre_technique",
    "mitre_tactic",
    "failed_attempts",
    "login_count",
    "file_accesses"
    ]]
    st.subheader("🗺️ MITRE ATT&CK Mapping")

    cols = ["attack_type", "mitre_technique", "mitre_tactic"]
    if "timestamp" in anomalies.columns:
        cols.insert(0, "timestamp")
    st.dataframe(anomalies[cols])
    prompt = f"""
    You are a senior SOC analyst.
    
    Analyze the following security events:
    
    STRUCTURED THREAT DATA:
    {structured_anomalies.to_string(index=False)}
    TASK:
    1. Executive Summary
    2. Threat Classification
    3. MITRE ATT&CK Analysis
    4. Risk Level
    5. Indicators of Compromise
    6. Recommended Mitigations
    Focus on MITRE mappings for justification.
    """
    if st.button("Generate AI Security Report"):
        with st.spinner("Analyzing Threats..."):
            response = model_gemini.generate_content(prompt)
        st.subheader("🧠 AI Security Report")
        st.write(response.text)
    if st.button("Generate PDF Report"):
        pdf_file = generate_pdf(structured_anomalies, risk_score)
        with open(pdf_file, "rb") as f:
            st.download_button(
                "Download SOC Report (PDF)",f,
                file_name="SOC_Incident_Report.pdf"
                )
