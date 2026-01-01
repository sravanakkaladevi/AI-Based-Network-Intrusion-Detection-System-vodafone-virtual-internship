import streamlit as st
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

import seaborn as sns
import matplotlib.pyplot as plt

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Vodafone Virtual Internship",
    layout="wide"
)

st.title("Vodafone Virtual Internship – AI-Based Network Intrusion Detection System")

st.markdown("""
This project demonstrates an **AI-Based Network Intrusion Detection System (NIDS)**
using the **CIC-IDS2017 dataset** and the **Random Forest algorithm**.

The system classifies network traffic into:
- **Benign (Normal)**
- **Malicious (Attack – DDoS)**
""")

# ---------------- DATA LOADING ----------------
@st.cache_data
def load_data():
    file_path = (
        "data/MachineLearningCVE/"
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    )

    # Load limited rows (RAM safe)
    df = pd.read_csv(file_path, nrows=50000)

    # Clean column names (CIC datasets have hidden spaces)
    df.columns = df.columns.str.strip()

    # Required columns only
    required_cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Packet Length Mean",
        "Flow Bytes/s",
        "Label"
    ]

    df = df[required_cols]

    # Convert features to numeric
    for col in required_cols[:-1]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop rows with NaN
    df.dropna(inplace=True)

    # Clip extreme values (important for stability)
    df["Flow Bytes/s"] = df["Flow Bytes/s"].clip(upper=1_000_000)
    df["Flow Duration"] = df["Flow Duration"].clip(upper=1_000_000)

    # Convert labels to binary
    df["Label"] = df["Label"].apply(
        lambda x: 0 if x == "BENIGN" else 1
    )

    return df

# Load dataset
df = load_data()

st.subheader("Dataset Preview")
st.dataframe(df.head())

# ---------------- PREPROCESSING ----------------
X = df.drop("Label", axis=1)
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ---------------- MODEL TRAINING ----------------
st.divider()
st.subheader("Model Training")

if st.button("Train Model"):
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    st.session_state.model = model
    st.success("Model trained successfully")

# ---------------- EVALUATION ----------------
if "model" in st.session_state:
    model = st.session_state.model
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)

    c1, c2 = st.columns(2)
    c1.metric("Accuracy", f"{acc * 100:.2f}%")
    c2.metric("Samples Used", len(df))

    st.subheader("Confusion Matrix")
    cm = confusion_matrix(y_test, y_pred)

    fig, ax = plt.subplots(figsize=(4, 3))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds", ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    st.pyplot(fig)

    st.subheader("Classification Report")
    report = classification_report(
        y_test,
        y_pred,
        target_names=["Benign", "Malicious"],
        output_dict=True
    )
    st.dataframe(pd.DataFrame(report).transpose())

# ---------------- LIVE TRAFFIC TEST ----------------
st.divider()
st.subheader("Live Traffic Analysis")

fd = st.number_input("Flow Duration", 0, 1_000_000, 500)
fwd = st.number_input("Total Forward Packets", 0, 2000, 50)
bwd = st.number_input("Total Backward Packets", 0, 2000, 20)
pl = st.number_input("Packet Length Mean", 0, 3000, 500)
fb = st.number_input("Flow Bytes/s", 0.0, 1_000_000.0, 10000.0)

if st.button("Analyze Traffic"):
    if "model" in st.session_state:
        sample = np.array([[fd, fwd, bwd, pl, fb]])
        result = st.session_state.model.predict(sample)

        if result[0] == 1:
            st.error("🚨 Malicious Traffic Detected")
        else:
            st.success("✅ Benign Traffic")
    else:
        st.warning("Please train the model first")
