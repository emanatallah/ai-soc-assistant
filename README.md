# AI SOC Assistant

An intelligent Attack Surface Intelligence Platform designed to automate reconnaissance, risk assessment, AI-powered security analysis, MITRE ATT&CK mapping, and professional reporting through a modern command-line interface.

The project combines network reconnaissance, security analytics, artificial intelligence, and threat intelligence to help security professionals quickly understand the security posture of a target.

---

## Overview

AI SOC Assistant is a modular cybersecurity framework that performs automated reconnaissance against domains and IP addresses, evaluates the discovered attack surface, calculates a dynamic risk score, maps findings to the MITRE ATT&CK framework, generates AI-powered security assessments, stores historical scan data, compares scan results, and exports professional PDF reports.

Unlike traditional network scanners that only enumerate services, AI SOC Assistant attempts to provide meaningful security context around discovered assets by combining multiple analysis engines into a single workflow.

---

## Key Features

- Unified network reconnaissance engine
- TCP port and service detection
- Service version fingerprinting
- Banner grabbing
- DNS information gathering
- WHOIS lookup
- SSL/TLS inspection
- HTTP security header analysis
- Technology fingerprinting
- Dynamic risk scoring engine
- AI-generated security assessment
- MITRE ATT&CK technique mapping
- SQLite scan history
- Scan comparison engine
- Professional PDF report generation
- Modern Rich-based command line interface
- Modular architecture
- Extensible plugin-friendly design

---

## Core Capabilities

### Reconnaissance

The scanner automatically collects information about the target including:

- IP Resolution
- DNS Records
- WHOIS Information
- Open TCP Ports
- Running Services
- Service Versions
- SSL Certificate Information
- Supported TLS Versions
- HTTP Response Headers
- Web Technologies

---

### Attack Surface Analysis

The platform automatically identifies the exposed attack surface by analyzing:

- Open Services
- Exposed Administrative Interfaces
- Database Services
- Remote Access Protocols
- Public Web Services
- Encryption Configuration

The collected information is normalized before being passed to the analysis engine.

---

### Risk Assessment Engine

The internal scoring engine evaluates multiple security indicators including:

- Missing Security Headers
- Weak TLS Configuration
- Deprecated Protocols
- High Risk Services
- Anonymous Services
- Outdated Technologies
- Exposed Databases
- Remote Administration Services

Each finding contributes to a weighted risk score that is converted into a severity level.

Severity Levels:

- Informational
- Low
- Medium
- High
- Critical

Risk scores range from 0.0 to 10.0.

---

### Artificial Intelligence Analysis

The AI engine automatically generates a professional security assessment including:

- Executive Summary
- Risk Findings
- Attack Surface Overview
- MITRE ATT&CK Analysis
- Security Recommendations

Instead of simply listing ports, the AI explains what the findings mean from a security perspective.

The generated report follows a structured format suitable for documentation and professional assessments.

---

### MITRE ATT&CK Integration

Detected findings are mapped to MITRE ATT&CK techniques whenever applicable.

Examples include:

| Finding | MITRE Technique |
|----------|-----------------|
| SSH Exposed | T1021.004 |
| RDP Exposed | T1021.001 |
| SMB Exposed | T1021.002 |
| FTP Exposed | T1021 |
| Telnet Exposed | T1021 |
| Weak Cipher | T1557 |
| Anonymous FTP | T1078 |

The mapping provides additional context about how exposed services may be leveraged during adversary operations.

---

### Scan History

Every completed scan is automatically stored inside an SQLite database.

Stored information includes:

- Target
- Scan Timestamp
- Raw Scan Results
- Risk Score
- Severity
- AI Analysis
- MITRE Mapping

Historical data enables long-term monitoring and trend analysis.

---

### Scan Comparison

The comparison engine allows security analysts to compare scan results between different targets.

Displayed information includes:

- Risk Score
- Severity
- Scan Timestamp

This feature simplifies infrastructure comparison during assessments.

---

### PDF Reporting

Each completed assessment can be exported as a professional PDF report.

The generated report includes:

- Target Information
- Open Ports
- Risk Score
- Severity
- AI Analysis
- MITRE ATT&CK Mapping
- Recommendations

Reports are suitable for documentation and client delivery.

---

## Architecture

```
                  +----------------------+
                  |    Target Domain/IP  |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  | Unified Scanner      |
                  +----------+-----------+
                             |
        +--------------------+---------------------+
        |                    |                     |
        v                    v                     v
   Network Scan        Web Analysis         SSL Inspection
        |                    |                     |
        +--------------------+---------------------+
                             |
                             v
                  +----------------------+
                  | Risk Engine          |
                  +----------+-----------+
                             |
                             +------------------+
                             |                  |
                             v                  v
                     MITRE Mapping       AI Analysis
                             |                  |
                             +---------+--------+
                                       |
                                       v
                             SQLite Database
                                       |
                                       v
                           PDF Report Generator
```
## Project Structure

```
AI-SOC-Assistant/
│
├── ai/
│   ├── analyzer.py
│   ├── mitre_mapper.py
│   ├── report_builder.py
│   └── risk_engine.py
│
├── config/
│   ├── settings.py
│   └── constants.py
│
├── database/
│   ├── sqlite.py
│   ├── models.py
│   └── migrations.py
│
├── history/
│   ├── ai_soc.sqlite3
│   ├── reports/
│   └── logs/
│
├── reports/
│   └── pdf.py
│
├── scanner/
│   ├── ports.py
│   ├── dns.py
│   ├── ssl.py
│   ├── headers.py
│   ├── technologies.py
│   ├── whois.py
│   ├── ping.py
│   └── __init__.py
│
├── utils/
│   ├── helpers.py
│   ├── logger.py
│   └── formatter.py
│
├── assets/
│
├── app.py
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Installation

### Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/AI-SOC-Assistant.git

cd AI-SOC-Assistant
```

---

### Create a virtual environment

Windows

```powershell
python -m venv .venv

.venv\Scripts\activate
```

Linux

```bash
python3 -m venv .venv

source .venv/bin/activate
```

---

### Install dependencies

```bash
pip install -r requirements.txt
```

---

### Install Nmap

Windows

Download and install the latest version of Nmap.

https://nmap.org/download.html

Linux

```bash
sudo apt install nmap
```

---

### Install Ollama (Optional)

If local AI analysis is enabled:

```bash
ollama pull qwen
```

---

## Requirements

- Python 3.11+
- Nmap
- SQLite
- Rich
- ReportLab
- Ollama (Optional)

---

## Quick Start

Run the application

```bash
python app.py
```

---

## Menu

```
1  Scan Target

2  Scan History

3  Compare Scans

4  Generate Report

5  Settings

6  About

0  Exit
```

---

## Scan Workflow

```
User Input

↓

Target Validation

↓

DNS Resolution

↓

WHOIS Lookup

↓

Port Scanning

↓

Service Detection

↓

Technology Detection

↓

SSL Inspection

↓

HTTP Security Header Analysis

↓

Risk Scoring

↓

MITRE ATT&CK Mapping

↓

AI Analysis

↓

SQLite Storage

↓

PDF Report Generation
```

---

## Risk Scoring

The scoring engine evaluates security posture using weighted findings.

Examples include

| Finding | Weight |
|---------|--------:|
| Telnet Exposed | 3.0 |
| SMB Exposed | 2.5 |
| RDP Exposed | 2.5 |
| MongoDB Exposed | 2.5 |
| Redis Exposed | 2.5 |
| FTP Exposed | 2.5 |
| MySQL Exposed | 2.0 |
| Weak Cipher | 1.0 |
| Missing CSP | 1.0 |
| Missing HSTS | 1.0 |
| Missing X-Frame-Options | 0.7 |
| Missing X-Content-Type-Options | 0.5 |
| SSH Exposed | 0.5 |

---

## Severity Levels

| Score | Severity |
|--------|----------|
| 0.0 - 1.9 | Informational |
| 2.0 - 3.9 | Low |
| 4.0 - 5.9 | Medium |
| 6.0 - 7.9 | High |
| 8.0 - 10.0 | Critical |

---

## MITRE ATT&CK Integration

The platform maps supported findings to MITRE ATT&CK techniques.

Supported mappings currently include

| Finding | Technique | Tactic |
|----------|-----------|--------------------|
| SSH Exposed | T1021.004 | Lateral Movement |
| FTP Exposed | T1021 | Lateral Movement |
| Telnet Exposed | T1021 | Lateral Movement |
| SMB Exposed | T1021.002 | Lateral Movement |
| RDP Exposed | T1021.001 | Lateral Movement |
| MySQL Exposed | T1213 | Collection |
| MongoDB Exposed | T1213 | Collection |
| Redis Exposed | T1213 | Collection |
| Anonymous FTP | T1078 | Defense Evasion |
| Weak Cipher | T1557 | Credential Access |

---

## AI Generated Assessment

Each completed assessment automatically includes

- Executive Summary
- Risk Findings
- Attack Surface Summary
- MITRE ATT&CK Analysis
- Security Recommendations

The AI attempts to explain the security implications of discovered findings instead of only listing technical information.

---

## Database

Every completed assessment is stored inside SQLite.

Stored information

- Target
- Timestamp
- Scan Results
- Risk Score
- Severity
- AI Analysis
- MITRE ATT&CK Data

Historical scans can later be reviewed or compared.

---

## Scan Comparison

The comparison module allows analysts to compare the latest scans of two different targets.

Compared values include

- Risk Score
- Severity
- Timestamp

This feature helps identify differences between environments.

---

## PDF Reporting

Reports are automatically generated after each scan.

Each report contains

- Executive Summary
- Target Information
- Open Ports
- Service Detection
- Risk Score
- Severity
- AI Analysis
- MITRE ATT&CK Mapping
- Security Recommendations

The generated reports are suitable for documentation and technical reporting.

---

## Technologies

- Python
- Rich
- Nmap
- SQLite
- ReportLab
- Ollama
- MITRE ATT&CK
- ReportLab PDF
- Socket
- SSL
- Requests

---

## Design Principles

The project was designed with the following goals

- Modular architecture
- High readability
- Easy extensibility
- Platform independence
- Professional reporting
- Reusable components
- Clear separation of responsibilities

---

## Current Limitations

The project currently focuses on attack surface intelligence and security posture assessment.

It is **not** intended to replace enterprise vulnerability scanners such as Nessus or OpenVAS.

Current limitations include

- No CVE correlation
- No CVSS scoring
- Limited MITRE ATT&CK coverage
- No authenticated scanning
- No exploit verification
- No web vulnerability exploitation
- No operating system fingerprint confidence scoring

These features are planned for future releases.

---

## Future Roadmap

Future improvements include

- CVE Detection
- CVSS Scoring
- NSE Script Integration
- Web Vulnerability Detection
- AI-Based Risk Prediction
- Machine Learning Risk Model
- Asset Inventory
- HTML Reporting
- JSON Export
- REST API
- Multi-threaded Scanning
- Plugin System
- Dashboard Interface
- Authentication Support
- Docker Deployment
- CI/CD Pipeline

---

## Screenshots

The following screenshots demonstrate the platform capabilities.

- Main Menu
- Scan Result
- Risk Assessment
- MITRE ATT&CK Mapping
- AI Analysis
- Scan Comparison
- PDF Report

Replace this section with screenshots from your own application.

---
## Contributing

Contributions are welcome and greatly appreciated.

If you would like to improve AI SOC Assistant, please follow these steps.

1. Fork the repository.
2. Create a feature branch.

```bash
git checkout -b feature/new-feature
```

3. Commit your changes.

```bash
git commit -m "Add new feature"
```

4. Push the branch.

```bash
git push origin feature/new-feature
```

5. Open a Pull Request.

Please ensure that new code follows the project's coding style and includes appropriate documentation.

---

## Coding Standards

This project follows several development principles.

- PEP 8 compliant
- Modular architecture
- Descriptive function names
- Type hints throughout the codebase
- Comprehensive docstrings
- Minimal external dependencies
- Readable and maintainable code

---

## Security Notice

AI SOC Assistant is intended for educational, research, and authorized security assessment purposes only.

Only scan systems that you own or have explicit authorization to test.

The developers assume no responsibility for misuse of this software.

---

## Performance

Typical scan workflow includes:

- Target validation
- DNS resolution
- WHOIS lookup
- TCP port scanning
- Service fingerprinting
- Technology detection
- HTTP header inspection
- SSL/TLS analysis
- Risk calculation
- MITRE ATT&CK mapping
- AI report generation
- Database storage
- PDF report creation

Performance depends on:

- Network latency
- Number of open ports
- Target responsiveness
- Service fingerprinting time
- AI model response time

---

## Supported Targets

The scanner supports:

- IPv4 Addresses
- Domain Names
- Public Hosts
- Internal Network Hosts
- Web Servers
- Linux Servers
- Windows Servers

Examples:

```text
scanme.nmap.org

example.com

8.8.8.8

192.168.1.1
```

---

## Example Output

```
Target: scanme.nmap.org

Risk Score: 0.5

Severity: Informational

Open Ports

22 SSH
25 SMTP
80 HTTP

MITRE ATT&CK

T1021.004
SSH
Lateral Movement

AI Assessment

Executive Summary

Risk Findings

Attack Surface

Recommendations
```

---

## Why AI SOC Assistant?

Traditional scanners often generate thousands of lines of technical output.

AI SOC Assistant transforms that information into an analyst-friendly security assessment by combining:

- Network reconnaissance
- Threat intelligence
- AI-powered reasoning
- Risk scoring
- Professional reporting

The objective is to reduce analysis time while improving situational awareness.

---

## Intended Audience

AI SOC Assistant is suitable for:

- Security Analysts
- SOC Teams
- Blue Team Engineers
- Penetration Testers
- Students
- Researchers
- Security Enthusiasts

---

## Tested Environment

Operating Systems

- Windows 10
- Windows 11
- Ubuntu Linux

Python

- Python 3.11+
- Python 3.12+
- Python 3.13+
- Python 3.14

Scanning Engine

- Nmap 7.x

Database

- SQLite

AI

- Ollama
- Qwen

---

## License

This project is released under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files to use, modify, distribute, and sublicense the software under the terms of the MIT License.

See the LICENSE file for complete license information.

---

## Citation

If you use this project in academic research, educational material, or demonstrations, please cite the repository appropriately.

---

## Acknowledgments

This project builds upon ideas and technologies from the following communities and projects.

- MITRE ATT&CK Framework
- Nmap
- Rich
- SQLite
- Ollama
- Python Community
- ReportLab

Special thanks to the open-source community for providing the tools and knowledge that made this project possible.

---

## Author

**Yusef Dafsher**

AI Engineer | Cybersecurity Enthusiast | Python Developer

GitHub

```
https://github.com/YOUR_USERNAME
```

LinkedIn

```
https://linkedin.com/in/YOUR_PROFILE
```

---

## Project Status

Current Version

```
v1.0.0
```

Status

```
Active Development
```

Last Updated

```
July 2026
```

---

## Repository Statistics

Project Type

```
Attack Surface Intelligence Platform
```

Language

```
Python
```

Architecture

```
Modular
```

Interface

```
Command Line Interface
```

Database

```
SQLite
```

Reporting

```
PDF
```

AI

```
Local Large Language Model
```

Threat Intelligence

```
MITRE ATT&CK
```

---

Copyright © 2026 Yusef Dafsher.

All rights reserved.