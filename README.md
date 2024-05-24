# ToolboxSDV
# Intrusion Test Toolbox

## Description

Intrusion Test Toolbox is a comprehensive tool designed to assist in security testing and vulnerability assessment of network systems and web applications. The application offers functionalities for port scanning, vulnerability detection, OS detection, web server identification, subdomain enumeration, directory and file discovery, password analysis, HTML scraping, SSL certificate scanning, and various attack simulations including brute force, SQL injection, remote code execution (RCE), and cross-site scripting (XSS).

## Prerequisites

Before running the Intrusion Test Toolbox, ensure you have the following prerequisites installed on your system:

- **Python 3.x**: Make sure Python 3 is installed on your system.
- **pip**: Python package installer should be installed.
- **nmap**: Network mapper tool for port scanning.
- **requests**: Python library to make HTTP requests.
- **paramiko**: Python library for SSH connectivity.
- **BeautifulSoup4**: Python library for web scraping.
- **reportlab**: Python library for PDF generation.
- **tkinter**: Python library for GUI applications.
- **Threading**: Standard library for concurrent programming.
- **Queue**: Standard library for queue data structure.
- **ssl**: Standard library for SSL connections.
- **socket**: Standard library for low-level networking.
- **logging**: Standard library for logging messages.

To install the required Python libraries, run the following command:

```bash
pip install nmap requests paramiko beautifulsoup4 reportlab

How to Use
1.Clone the Repository: Download the code from the repository.
2.Navigate to the Directory: Open your terminal and navigate to the directory containing the code.
3.Run the Application: Execute the main Python script to start the GUI application.
                python intrusion_test_toolbox.py

User Interface: The application features a graphical user interface with tabs for different functionalities.
Tabs and Functionalities
Scanning:

Discover Ports/Services: Enter a target IP address to scan for open ports and available services.
Detect Vulnerabilities: Scan for known vulnerabilities on the target system.
OS Detection: Detect the operating system running on the target system.
Service Version Detection: Identify versions of services running on the target system.
Web Server Detection: Identify the type and version of the web server on the target system.
Subdomain Enumeration: Discover subdomains associated with the target domain.
Directory and File Discovery: Discover accessible directories and files on the target URL.

Analysis:

Generate Report: Generate a PDF report of the scan results.
Scrape HTML: Scrape and analyze the HTML content of a target URL.
Test Password Strength: Analyze the strength of a given password.
Scan SSL Certificate: Scan and analyze the SSL certificate of a target domain.

Attack:
Brute Force Attack: Simulate a brute force attack on a target IP with a given username and password list.
SSH Connect: Connect to a target system via SSH using provided credentials.
SQL Injection Attack: Test for SQL injection vulnerabilities on a target URL with a specified parameter.
Remote Code Execution: Simulate an RCE attack with brute force on SSH credentials.
XSS Attack: Test for XSS vulnerabilities on a target URL with a specified parameter.

Advantages

Comprehensive Testing: Provides multiple tools for network and web application security testing.

User-Friendly Interface: Easy to use with a graphical interface.

Automated Reporting: Generates detailed PDF reports of the test results.

Real-Time Feedback: Displays log messages and progress in real-time.

Notes

Security and Legal Compliance: Ensure you have proper authorization before conducting any tests on target systems to avoid legal issues.

Updates and Maintenance: Regularly update the tool and dependencies to ensure compatibility and security.

Author

Created by Amine (4|\/|1|\|3)

This README provides a clear overview of the Intrusion Test Toolbox, its prerequisites, usage instructions, functionalities, advantages, and important notes for users who may not be familiar with security testing tools.



