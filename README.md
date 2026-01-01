# Vodafone Virtual Internship – AI-Based Network Intrusion Detection System

This project demonstrates an **AI-Based Network Intrusion Detection System (NIDS)**
using the **CIC-IDS2017 dataset** and **Random Forest algorithm**.

## Features

- Real-world CIC-IDS2017 dataset (DDoS traffic)
- Data cleaning (NaN, infinity, extreme values handled)
- Random Forest classification
- Performance metrics (Accuracy, Confusion Matrix, Classification Report)
- Interactive Streamlit dashboard
- Live traffic analysis

## Tech Stack

- Python
- Pandas, NumPy
- Scikit-learn
- Streamlit
- Matplotlib, Seaborn

## How to Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Dataset

CIC-IDS2017 dataset
(Dataset not uploaded due to size limits)

## Dataset Information

This project uses the **CIC-IDS2017 (Canadian Institute for Cybersecurity)** dataset.

Due to the large size of the dataset files, they are **not included in this GitHub repository**.

### Official Dataset Source

🔗 https://www.unb.ca/cic/datasets/ids-2017.html

### Dataset Used in This Project

- **Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv**
- Traffic Type: Benign + DDoS attacks

### How to Use the Dataset

1. Download the dataset from the official CIC website
2. Extract the CSV files
3. Place the required file inside the project directory:
4. Run the application using:

```bash
streamlit run app.py

### Output

Accuracy ~99.9%

Low false positives and false negatives
## Author

AKKALADEVI.SRAVAN KUMAR
```
