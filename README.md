\# SOC Log Analyzer Dashboard



A Windows cybersecurity monitoring project that collects and analyzes Sysmon events, applies basic risk scoring, exports reports to CSV, and displays results in a Streamlit dashboard.



\## Features



\- Sysmon Event ID 1 - Process Create

\- Sysmon Event ID 3 - Network Connection

\- Sysmon Event ID 11 - File Create

\- Sysmon Event ID 22 - DNS Query

\- Automatic risk scoring

&#x20; - LOW

&#x20; - REVIEW

&#x20; - SUSPICIOUS

\- CSV report export

\- Streamlit dashboard

\- Investigation queue

\- Event filtering by risk level and event type



\## Architecture



```text

Windows

&#x20; |

Sysmon

&#x20; |

Windows Event Logs

&#x20; |

soc\_analyzer.py

&#x20; |

Risk Scoring

&#x20; |

soc\_report.csv

&#x20; |

dashboard.py

&#x20; |

Streamlit Dashboard



Project Structure

soc-log-analyzer/

|

|-- soc\_analyzer.py

|-- dashboard.py

|-- soc\_report.csv

|-- requirements.txt

|-- .gitignore

`-- README.md



Sysmon Events Used

Event ID	Description

1	Process Create

3	Network Connection

11	File Create

22	DNS Query





Risk Scoring

The analyzer assigns events to three levels:

LOW

Expected or common system activity.

REVIEW

Activity that should be inspected further.

Examples:

\- PowerShell or command-line processes

\- Unknown processes

\- Executables running from temporary directories

\- Uncommon destination ports

SUSPICIOUS

Multiple risk indicators occurring together.

Examples:

\- Script or executable created in a risky directory

\- Unknown process communicating over an uncommon port

\- Command-line process running from a temporary directory

SUSPICIOUS does not automatically mean malware. It indicates that the event should receive higher investigation priority.

Installation

python -m pip install -r requirements.txt



Run the Analyzer

python soc\_analyzer.py



Run the Dashboard

python -m streamlit run dashboard.py



Open:

http://localhost:8501



Dashboard

The dashboard displays:

\- Total events

\- LOW events

\- REVIEW events

\- SUSPICIOUS events

\- Event type distribution

\- Risk distribution

\- Event explorer

\- Investigation queue

SOC Workflow

Process

&#x20; |

DNS Query

&#x20; |

Network Connection

&#x20; |

File Activity

&#x20; |

Risk Triage

&#x20; |

Investigation



Skills Demonstrated

\- Windows Sysmon

\- Windows Event Logs

\- PowerShell

\- Python

\- Log parsing

\- Event correlation

\- IOC investigation

\- Risk triage

\- CSV reporting

\- Streamlit

\- Basic SOC workflow

Purpose

This project was created as a hands-on cybersecurity portfolio project to practice Security Operations Center monitoring, event analysis, process investigation, DNS analysis, network analysis, and incident triage.





