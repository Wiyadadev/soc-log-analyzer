# SOC Log Analyzer Dashboard

A Windows cybersecurity monitoring project that collects and analyzes Sysmon events, applies basic risk scoring, exports reports to CSV, and displays results in a Streamlit dashboard.

## Features

- Sysmon Event ID 1 - Process Create
- Sysmon Event ID 3 - Network Connection
- Sysmon Event ID 11 - File Create
- Sysmon Event ID 22 - DNS Query
- Automatic risk scoring
  - LOW
  - REVIEW
  - SUSPICIOUS
- CSV report export
- Streamlit dashboard
- Investigation queue
- Event filtering by risk level and event type

## Architecture

```text
Windows
   ↓
Sysmon
   ↓
Windows Event Logs
   ↓
soc_analyzer.py
   ↓
Risk Scoring
   ↓
soc_report.csv
   ↓
dashboard.py
   ↓
Streamlit Dashboard
