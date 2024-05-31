# Snake Eye - Advanced Network Attack Detection Tool

## Introduction

Welcome to Snake Eye, a robust and versatile network attack detection tool designed to safeguard your infrastructure from various cyber threats. This tool leverages advanced packet inspection techniques to identify and report malicious activities, ensuring your network remains secure and resilient.

Snake Eye is equipped to detect a wide array of attacks, including but not limited to:

- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Server-Side Template Injection (SSTI)**
- **Cross-Site Request Forgery (CSRF)**
- **Port Scans**
- **Distributed Denial of Service (DDoS)**
- **MAC Flooding**
- **ARP Spoofing**
- **ICMP Ping Flooding**
- **CRLF Injection**
  
## Features

### Comprehensive Packet Inspection
- **Request and Response Analysis**: Inspects both HTTP request and response payloads to identify potential SQL injection attempts.
- **Pattern Matching**: Utilizes predefined patterns to detect various types of attacks, ensuring broad coverage and effective detection.

### Real-Time Monitoring
- **Continuous Packet Capture**: Captures live network traffic on specified interfaces, enabling real-time analysis and detection.
- **Logging and Reporting**: Detailed logging and reporting mechanisms to record detected incidents and provide actionable insights.

### Versatile Detection Capabilities
- **SQL Injection Detection**: Identifies and reports SQL injection attempts by analyzing HTTP packets for malicious SQL code.
- **XSS and SSTI Detection**: Detects Cross-Site Scripting and Server-Side Template Injection attacks by scanning for malicious scripts and template injections.
- **CSRF Detection**: Identifies Cross-Site Request Forgery attempts through heuristic analysis of hidden form fields and meta tags.
- **Network Attack Detection**: Detects network-based attacks such as port scans, DDoS, MAC flooding, ARP spoofing, and ICMP ping floods.

### Customizable Configuration
- **Flexible Thresholds**: Configurable detection thresholds and time windows for various types of attacks.
- **Pattern Customization**: Easily update and extend attack patterns to keep up with evolving threats.

### User-Friendly Interface
- **Simple Setup**: Easy to configure and deploy, with clear documentation and configuration files.
- **Detailed Documentation**: Comprehensive guides and documentation to help you get started and make the most of Snake Eye.

### Web-Based Dashboard
- **Apache2 Integration**: Displays reports via a web server hosted on Apache2, providing an accessible and user-friendly interface for monitoring.
- **Real-Time Reporting**: View real-time data on detected attacks, including detailed information about each incident.
- **Historical Data Analysis**: Access historical data and trends to understand the nature and frequency of attacks over time.
- **Customizable Views**: Tailor the dashboard to display the information most relevant to your security needs.
- **Alert Management**: Manage and review alerts, ensuring critical incidents are addressed promptly.
 
## Installation

Get started with Snake Eye by following these steps:
```sh
git clone https://github.com/0Xdarkday/Snake-Eye.git
cd Snake-Eye
sudo chmod +x Setup.sh
./Setup.sh
```

## Dashboard Overview
![Dashboard Overview](images/dashboard.png)
The Snake Eye dashboard, hosted on an Apache2 web server, provides a comprehensive and user-friendly interface for monitoring network security. Here’re the steps to access dashbord:
   ```sh
- service apache2 start
- http://127.0.0.1/view_reports.php 
