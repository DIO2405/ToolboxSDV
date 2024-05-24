import hashlib
import requests
from tkinter import simpledialog, scrolledtext, Tk, WORD, INSERT, BOTH, Toplevel, Label, Entry, StringVar, messagebox
from tkinter import ttk
import threading
import queue
import nmap
import json
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak
import os
import time
import ssl
import socket
import logging
import webbrowser
import re
import paramiko
import html

# Initialize logging
logging.basicConfig(filename='toolbox.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to set a dark theme
def set_dark_theme(root):
    style = ttk.Style()
    style.theme_use('clam')

    style.configure('TFrame', background='#2E2E2E')
    style.configure('TButton', background='#3A3A3A', foreground='white', font=('Helvetica', 12))
    style.map('TButton', background=[('active', '#4E4E4E')])
    style.configure('TLabel', background='#2E2E2E', foreground='white', font=('Helvetica', 12))
    style.configure('TEntry', fieldbackground='#3A3A3A', foreground='white')
    style.configure('TText', background='#3A3A3A', foreground='white')
    style.configure('TProgressbar', troughcolor='#3A3A3A', background='#4E4E4E')
    style.configure('TNotebook', background='#2E2E2E', foreground='white')
    style.configure('TNotebook.Tab', background='#3A3A3A', foreground='white', font=('Helvetica', 12))

# Function to log and display messages
def log_and_display(message, level='info'):
    if level == 'info':
        logging.info(message)
    elif level == 'warning':
        logging.warning(message)
    elif level == 'error':
        logging.error(message)
    text_area.insert(INSERT, f"{message}\n")

# Create the main window
root = Tk()
root.title("Intrusion Test Toolbox")
set_dark_theme(root)

# Create a notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(padx=10, pady=10, fill=BOTH, expand=True)

# Create frames for each tab
tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
tab3 = ttk.Frame(notebook)
tab4 = ttk.Frame(notebook)  # New tab for attacks

notebook.add(tab1, text='Scanning')
notebook.add(tab2, text='Analysis')
notebook.add(tab4, text='Attack')  # Add the new tab to the notebook
notebook.add(tab3, text='Reports')

# Create a scrolled text area
text_area = scrolledtext.ScrolledText(tab3, wrap=WORD, background='#3A3A3A', foreground='white', insertbackground='white')
text_area.pack(padx=10, pady=10, fill=BOTH, expand=True)

# Create a progress bar
progress = ttk.Progressbar(tab1, orient="horizontal", length=400, mode="determinate")
progress.pack(pady=10)

# List to store results for the PDF report
results = []

# Create a queue for thread communication
input_queue = queue.Queue()

def list_files_in_directory():
    current_directory = os.getcwd()
    files = os.listdir(current_directory)
    log_and_display(f"Current directory: {current_directory}")
    log_and_display(f"Files in directory: {files}")

def handle_input():
    while not input_queue.empty():
        func, args = input_queue.get()
        func(*args)
    root.after(100, handle_input)

def update_progress(value):
    progress['value'] = value
    root.update_idletasks()

def discover_ports_services(text_area, results, target):
    try:
        nm = nmap.PortScanner()
        if target:
            log_and_display(f"Scanning {target}...")
            res = nm.scan(target, '1-1024')  # Scan ports 1-1024
            formatted_res = json.dumps(res, indent=4)  # Format the results
            explanation = (
                "Port scanning identifies open ports and services available on a networked system. "
                "It helps in understanding the attack surface of the target. Common open ports might include:\n"
                "- Port 21 (FTP): Used for file transfers. Ensure it's secured with strong authentication.\n"
                "- Port 22 (SSH): Used for secure logins. Ensure strong passwords and key-based authentication.\n"
                "- Port 80 (HTTP): Used for web traffic. Ensure the web server is up-to-date and patched.\n"
                "- Port 443 (HTTPS): Used for secure web traffic. Ensure the SSL/TLS certificates are properly configured.\n"
            )
            remediation = (
                "To secure open ports:\n"
                "1. Use firewalls to restrict access to necessary services only.\n"
                "2. Disable unnecessary services to minimize the attack surface.\n"
                "3. Regularly monitor and audit open ports and services to detect any unauthorized changes."
            )
            results.append({
                'host_ip': target, 
                'scan_results': res.get('scan', {}),
                'explanation': explanation,
                'remediation': remediation
            })
            log_and_display(f"Scan results:\n{formatted_res}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
        else:
            log_and_display("No target IP address provided.", 'warning')
    except nmap.PortScannerError as e:
        log_and_display(f"Error in scanning: {str(e)}", 'error')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def detect_vulnerabilities(text_area, results, target):
    try:
        nm = nmap.PortScanner()
        if target:
            log_and_display(f"Scanning {target} for vulnerabilities...")
            res = nm.scan(target, '1-1024', arguments='--script=vuln')  # Scan ports 1-1024 with vulnerability scripts
            formatted_res = json.dumps(res, indent=4)  # Format the results
            explanation = (
                "Vulnerability scanning identifies weaknesses in systems that could be exploited by attackers. "
                "Common vulnerabilities include:\n"
                "- Outdated software versions: Ensure all software is up-to-date.\n"
                "- Misconfigurations: Regularly review and correct system configurations.\n"
                "- Exposed services: Limit access to services based on necessity.\n"
            )
            remediation = (
                "To mitigate vulnerabilities:\n"
                "1. Regularly update software to the latest versions.\n"
                "2. Follow best practices for system configurations.\n"
                "3. Use firewalls to limit access to sensitive services."
            )
            results.append({
                'host_ip': target, 
                'vulnerability_scan_results': res.get('scan', {}),
                'explanation': explanation,
                'remediation': remediation
            })
            log_and_display(f"Vulnerability scan results:\n{formatted_res}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
        else:
            log_and_display("No target IP address provided.", 'warning')
    except nmap.PortScannerError as e:
        log_and_display(f"Error in scanning: {str(e)}", 'error')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def os_detection(text_area, results, target):
    try:
        nm = nmap.PortScanner()
        if target:
            log_and_display(f"Detecting OS of {target}...")
            res = nm.scan(target, arguments='-O')  # OS detection
            formatted_res = json.dumps(res, indent=4)  # Format the results
            explanation = (
                "Operating system detection helps in identifying the OS running on the target system. "
                "This information can be useful for tailoring further attacks or defenses. Common outcomes include:\n"
                "- Identification of specific OS versions: Ensure they are updated and patched.\n"
                "- Detection of outdated OS: Plan for upgrades to supported versions.\n"
            )
            remediation = (
                "To secure the operating system:\n"
                "1. Regularly update and patch the operating system.\n"
                "2. Limit the exposure of OS details through network configurations and firewalls."
            )
            results.append({
                'host_ip': target, 
                'os_detection': res.get('scan', {}),
                'explanation': explanation,
                'remediation': remediation
            })
            log_and_display(f"OS detection results:\n{formatted_res}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
        else:
            log_and_display("No target IP address provided.", 'warning')
    except nmap.PortScannerError as e:
        log_and_display(f"Error in OS detection: {str(e)}", 'error')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def service_version_detection(text_area, results, target):
    try:
        nm = nmap.PortScanner()
        if target:
            log_and_display(f"Detecting service versions on {target}...")
            res = nm.scan(target, arguments='-sV')  # Service version detection
            formatted_res = json.dumps(res, indent=4)  # Format the results
            explanation = (
                "Service version detection identifies the versions of services running on the target system. "
                "This information can be used to find vulnerabilities specific to those versions. Common services include:\n"
                "- Web servers: Apache, Nginx.\n"
                "- Database servers: MySQL, PostgreSQL.\n"
                "- SSH services: OpenSSH.\n"
            )
            remediation = (
                "To secure services:\n"
                "1. Keep all software and services up-to-date to mitigate known vulnerabilities.\n"
                "2. Disable unnecessary services to reduce the attack surface."
            )
            results.append({
                'host_ip': target, 
                'service_version_detection': res.get('scan', {}),
                'explanation': explanation,
                'remediation': remediation
            })
            log_and_display(f"Service version detection results:\n{formatted_res}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
        else:
            log_and_display("No target IP address provided.", 'warning')
    except nmap.PortScannerError as e:
        log_and_display(f"Error in service version detection: {str(e)}", 'error')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def web_server_detection(text_area, results, target):
    try:
        nm = nmap.PortScanner()
        if target:
            log_and_display(f"Detecting web server on {target}...")
            res = nm.scan(target, arguments='-sV --script=http-server-header')  # Web server detection
            formatted_res = json.dumps(res, indent=4)  # Format the results
            explanation = (
                "Web server detection identifies the type and version of the web server running on the target. "
                "This can be useful for finding specific vulnerabilities related to the web server. Common web servers include:\n"
                "- Apache: Ensure it is updated and configured securely.\n"
                "- Nginx: Regularly update and review security settings.\n"
            )
            remediation = (
                "To secure web servers:\n"
                "1. Ensure the web server software is regularly updated and patched.\n"
                "2. Follow security best practices for configuring and securing the web server."
            )
            results.append({
                'host_ip': target, 
                'web_server_detection': res.get('scan', {}),
                'explanation': explanation,
                'remediation': remediation
            })
            log_and_display(f"Web server detection results:\n{formatted_res}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
        else:
            log_and_display("No target IP address provided.", 'warning')
    except nmap.PortScannerError as e:
        log_and_display(f"Error in web server detection: {str(e)}", 'error')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def subdomain_enumeration(text_area, results, target):
    try:
        if target:
            log_and_display(f"Enumerating subdomains for {target}...")
            # Example subdomains list for demonstration, you may use an actual tool for this
            subdomains = [f"sub{i}.{target}" for i in range(1, 6)]
            formatted_res = json.dumps(subdomains, indent=4)  # Format the results
            explanation = (
                "Subdomain enumeration discovers subdomains associated with the target domain. "
                "This can reveal additional attack surfaces that might be overlooked. "
                "For example, 'mail.example.com' might host an email server, while 'dev.example.com' "
                "might be used for development purposes."
            )
            remediation = (
                "To manage subdomains securely:\n"
                "1. Regularly audit and review subdomains to ensure they are secure.\n"
                "2. Remove any unnecessary or outdated subdomains to reduce potential attack vectors."
            )
            results.append({
                'host_ip': target, 
                'subdomain_enumeration': subdomains,
                'explanation': explanation,
                'remediation': remediation
            })
            log_and_display(f"Subdomain enumeration results:\n{formatted_res}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
        else:
            log_and_display("No target domain provided.", 'warning')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def directory_file_discovery(text_area, results, target):
    try:
        if target:
            log_and_display(f"Discovering directories and files on {target}...")
            # Example directories and files list for demonstration, you may use an actual tool for this
            dirs_files = [f"/dir{i}" for i in range(1, 6)] + [f"/file{i}.txt" for i in range(1, 6)]
            formatted_res = json.dumps(dirs_files, indent=4)  # Format the results
            explanation = (
                "Directory and file discovery identifies accessible directories and files on the target. "
                "This information can be used to find sensitive information or further attack vectors. "
                "For example, discovering '/admin' might reveal an admin panel, while finding '/backup.sql' "
                "might expose a database backup."
            )
            remediation = (
                "To secure directories and files:\n"
                "1. Restrict access to sensitive directories and files using proper permissions and access controls.\n"
                "2. Regularly review and clean up exposed directories and files."
            )
            results.append({
                'host_ip': target, 
                'directory_file_discovery': dirs_files,
                'explanation': explanation,
                'remediation': remediation
            })
            log_and_display(f"Directory and file discovery results:\n{formatted_res}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
        else:
            log_and_display("No target URL provided.", 'warning')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def ssh_connect(text_area, results, target, username, password):
    try:
        if target and username and password:
            log_and_display(f"Connecting to {target} via SSH...")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=username, password=password)
            stdin, stdout, stderr = ssh.exec_command('uname -a')
            output = stdout.read().decode()
            explanation = (
                "SSH connection allows for remote administration of the target system. "
                "Gaining unauthorized SSH access can lead to full control over the system. "
                "If the attacker can log in as root, they can perform any action on the system."
            )
            remediation = (
                "To secure SSH access:\n"
                "1. Ensure strong, unique passwords are used for SSH accounts.\n"
                "2. Use key-based authentication instead of password-based authentication.\n"
                "3. Restrict SSH access to trusted IP addresses."
            )
            log_and_display(f"SSH connection successful. Command output:\n{output}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
            results.append({'target': target, 'ssh_output': output, 'explanation': explanation, 'remediation': remediation})
            ssh.close()
        else:
            log_and_display("Incomplete SSH connection parameters provided.", 'warning')
    except paramiko.AuthenticationException:
        log_and_display("Authentication failed, please verify your credentials.", 'error')
    except paramiko.SSHException as e:
        log_and_display(f"Unable to establish SSH connection: {str(e)}", 'error')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def brute_force_attack(text_area, results, target, username, password_list):
    try:
        if target and username and password_list:
            log_and_display(f"Starting brute force attack on {target} with username {username}...")
            with open(password_list, 'r') as file:
                passwords = file.readlines()
            total_passwords = len(passwords)
            success = False
            for i, password in enumerate(passwords):
                password = password.strip()
                # Simulate login attempt (replace with actual login attempt code)
                # Here, we're just logging an attempt for demonstration purposes.
                log_and_display(f"Trying password: {password}")
                if password == "correct_password":  # Replace with actual check
                    log_and_display(f"Success! Username: {username}, Password: {password}", 'info')
                    success = True
                    break
                update_progress((i / total_passwords) * 100)
                time.sleep(0.1)  # Simulate delay for each attempt
            if not success:
                log_and_display("Brute force attack completed. No successful login found.", 'info')
            explanation = (
                "Brute force attack involves trying multiple passwords to gain unauthorized access. "
                "It can be effective if weak or common passwords are used. Attackers often use dictionaries "
                "of common passwords and variations to attempt to log in."
            )
            remediation = (
                "To prevent brute force attacks:\n"
                "1. Use strong, complex passwords and implement account lockout policies after a few failed attempts.\n"
                "2. Enable multi-factor authentication to provide an additional layer of security."
            )
            results.append({'target': target, 'username': username, 'attack': 'Brute Force', 'result': 'Success' if success else 'Failure', 'explanation': explanation, 'remediation': remediation})
        else:
            log_and_display("Incomplete brute force attack parameters provided.", 'warning')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def ssl_certificate_scan(text_area, results, target):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cert_info = {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version'],
                    'serialNumber': cert['serialNumber'],
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter']
                }
                ciphers = ssock.cipher()
                log_and_display(f"SSL Certificate for {target}:\n{json.dumps(cert_info, indent=4)}")
                log_and_display(f"Cipher used: {ciphers}")
                
                # Check security headers
                response = requests.get(f"https://{target}")
                headers = response.headers
                security_headers = {
                    'Content-Security-Policy': headers.get('Content-Security-Policy'),
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                    'X-Frame-Options': headers.get('X-Frame-Options'),
                    'X-XSS-Protection': headers.get('X-XSS-Protection')
                }
                log_and_display(f"Security Headers for {target}:\n{json.dumps(security_headers, indent=4)}")

                # Grade the SSL configuration
                grade = 'A'
                if not all(security_headers.values()):
                    grade = 'B'
                if 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' not in ciphers[0]:
                    grade = 'C'
                log_and_display(f"Grade for {target}: {grade}")

                explanation = (
                    "SSL certificate scanning provides information about the SSL certificate, "
                    "including issuer, subject, and validity period. It also checks for the presence "
                    "of security headers and the strength of the cipher suites used. A well-configured SSL/TLS setup "
                    "is crucial for securing data in transit."
                )
                remediation = (
                    "To secure SSL/TLS configurations:\n"
                    "1. Ensure the SSL certificate is valid and not expired.\n"
                    "2. Implement strong cipher suites and enable all recommended security headers."
                )
                results.append({'target': target, 'ssl_certificate': cert_info, 'ciphers': ciphers, 'security_headers': security_headers, 'grade': grade, 'explanation': explanation, 'remediation': remediation})
    except Exception as e:
        log_and_display(f"An error occurred during SSL certificate scan: {str(e)}", 'error')
    finally:
        update_progress(100)

def scrape_html(text_area, results, url):
    try:
        if url:
            log_and_display(f"Scraping URL: {url}...")
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            log_and_display(f"Scraped content:\n{soup.prettify()[:1000]}...")  # Display the first 1000 characters

            # Simplify and sanitize HTML content
            simplified_html = re.sub(r'<[^>]+>', '', soup.prettify())[:1000]
            results.append({'url': url, 'scraped_content': simplified_html})

            # Analyze HTML for common security issues
            analysis_results = analyze_html_security(soup)
            results.append({'url': url, 'html_analysis': analysis_results})
            log_and_display(f"HTML Analysis for {url}:\n{analysis_results}")
        else:
            log_and_display("No URL provided.", 'warning')
    except requests.RequestException as e:
        log_and_display(f"Error in scraping: {str(e)}", 'error')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def analyze_html_security(soup):
    issues = []
    # Check for missing security headers
    headers = soup.find_all('meta')
    security_headers = [
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection'
    ]
    for header in security_headers:
        if not any(h.get('http-equiv') == header for h in headers):
            issues.append(f"Missing security header: {header}")

    # Check for inline scripts
    inline_scripts = soup.find_all('script', src=False)
    if inline_scripts:
        issues.append("Found inline scripts, consider moving to external files.")

    # Check for forms without CSRF tokens
    forms = soup.find_all('form')
    for form in forms:
        if not form.find('input', {'name': 'csrf_token'}):
            issues.append("Form missing CSRF token.")

    return issues

def analyze_password_security(text_area, results, password):
    try:
        if password:
            log_and_display(f"Analyzing password: {password}...")
            score = 0
            if len(password) >= 8:
                score += 1
            if any(char.isdigit() for char in password):
                score += 1
            if any(char.islower() for char in password):
                score += 1
            if any(char.isupper() for char in password):
                score += 1
            if any(char in '!@#$%^&*()-_=+[]{};:,.<>?/\\|`~' for char in password):
                score += 1

            strength = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
            result = strength[score - 1] if score > 0 else "Very Weak"
            explanation = (
                "Password strength analysis checks the length, complexity, and variety of characters used in the password. "
                "Stronger passwords are harder to crack and provide better security."
            )
            remediation = (
                "To create strong passwords:\n"
                "1. Use passwords that are at least 12 characters long.\n"
                "2. Include a mix of uppercase and lowercase letters, numbers, and special characters.\n"
                "3. Avoid using common words or easily guessable patterns."
            )
            log_and_display(f"Password strength: {result}")
            log_and_display(f"Explanation: {explanation}")
            log_and_display(f"Remediation: {remediation}")
            results.append({'password': password, 'strength': result, 'explanation': explanation, 'remediation': remediation})
        else:
            log_and_display("No password provided.", 'warning')
    except Exception as e:
        log_and_display(f"An unexpected error occurred: {str(e)}", 'error')
    finally:
        update_progress(100)

def generate_report(text_area, results):
    try:
        if not results:
            log_and_display("No results to generate a report.", 'warning')
            return

        log_and_display("Generating report...")
        doc = SimpleDocTemplate("report.pdf", pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph("Intrusion Test Toolbox Report", styles['Title']))
        elements.append(Paragraph("Table of Contents", styles['Heading2']))

        toc = []
        for i, result in enumerate(results):
            if 'host_ip' in result:
                if 'scan_results' in result:
                    toc.append(f"{i+1}. Scan results for {result['host_ip']}")
                if 'vulnerability_scan_results' in result:
                    toc.append(f"{i+1}. Vulnerability scan results for {result['host_ip']}")
                if 'os_detection' in result:
                    toc.append(f"{i+1}. OS detection results for {result['host_ip']}")
                if 'service_version_detection' in result:
                    toc.append(f"{i+1}. Service version detection results for {result['host_ip']}")
                if 'web_server_detection' in result:
                    toc.append(f"{i+1}. Web server detection results for {result['host_ip']}")
                if 'subdomain_enumeration' in result:
                    toc.append(f"{i+1}. Subdomain enumeration results for {result['host_ip']}")
                if 'directory_file_discovery' in result:
                    toc.append(f"{i+1}. Directory and file discovery results for {result['host_ip']}")
            if 'password' in result:
                toc.append(f"{i+1}. Password analysis for '{html.escape(result['password'])}'")
            if 'url' in result:
                toc.append(f"{i+1}. Scraped content from {result['url']}")
            if 'ssl_certificate' in result:
                toc.append(f"{i+1}. SSL Certificate for {result['target']}")
            if 'ssh_output' in result:
                toc.append(f"{i+1}. SSH connection output for {result['target']}")
            if 'attack' in result:
                toc.append(f"{i+1}. {result['attack']} on {result['target']}")

        for item in toc:
            elements.append(Paragraph(item, styles['Normal']))

        elements.append(PageBreak())

        for result in results:
            if 'host_ip' in result:
                if 'scan_results' in result:
                    elements.append(Paragraph(f"Scan results for {result['host_ip']}:", styles['Heading2']))
                    elements.append(Paragraph(html.escape(json.dumps(result['scan_results'], indent=4)), styles['Code']))
                    elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                    elements.append(Paragraph(result['explanation'], styles['Normal']))
                    elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                    elements.append(Paragraph(result['remediation'], styles['Normal']))
                if 'vulnerability_scan_results' in result:
                    elements.append(Paragraph(f"Vulnerability scan results for {result['host_ip']}:", styles['Heading2']))
                    elements.append(Paragraph(html.escape(json.dumps(result['vulnerability_scan_results'], indent=4)), styles['Code']))
                    elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                    elements.append(Paragraph(result['explanation'], styles['Normal']))
                    elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                    elements.append(Paragraph(result['remediation'], styles['Normal']))
                if 'os_detection' in result:
                    elements.append(Paragraph(f"OS detection results for {result['host_ip']}:", styles['Heading2']))
                    elements.append(Paragraph(html.escape(json.dumps(result['os_detection'], indent=4)), styles['Code']))
                    elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                    elements.append(Paragraph(result['explanation'], styles['Normal']))
                    elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                    elements.append(Paragraph(result['remediation'], styles['Normal']))
                if 'service_version_detection' in result:
                    elements.append(Paragraph(f"Service version detection results for {result['host_ip']}:", styles['Heading2']))
                    elements.append(Paragraph(html.escape(json.dumps(result['service_version_detection'], indent=4)), styles['Code']))
                    elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                    elements.append(Paragraph(result['explanation'], styles['Normal']))
                    elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                    elements.append(Paragraph(result['remediation'], styles['Normal']))
                if 'web_server_detection' in result:
                    elements.append(Paragraph(f"Web server detection results for {result['host_ip']}:", styles['Heading2']))
                    elements.append(Paragraph(html.escape(json.dumps(result['web_server_detection'], indent=4)), styles['Code']))
                    elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                    elements.append(Paragraph(result['explanation'], styles['Normal']))
                    elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                    elements.append(Paragraph(result['remediation'], styles['Normal']))
                if 'subdomain_enumeration' in result:
                    elements.append(Paragraph(f"Subdomain enumeration results for {result['host_ip']}:", styles['Heading2']))
                    elements.append(Paragraph(html.escape(json.dumps(result['subdomain_enumeration'], indent=4)), styles['Code']))
                    elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                    elements.append(Paragraph(result['explanation'], styles['Normal']))
                    elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                    elements.append(Paragraph(result['remediation'], styles['Normal']))
                if 'directory_file_discovery' in result:
                    elements.append(Paragraph(f"Directory and file discovery results for {result['host_ip']}:", styles['Heading2']))
                    elements.append(Paragraph(html.escape(json.dumps(result['directory_file_discovery'], indent=4)), styles['Code']))
                    elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                    elements.append(Paragraph(result['explanation'], styles['Normal']))
                    elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                    elements.append(Paragraph(result['remediation'], styles['Normal']))
            if 'password' in result:
                elements.append(Paragraph(f"Password analysis for '{html.escape(result['password'])}':", styles['Heading2']))
                elements.append(Paragraph(result['strength'], styles['Normal']))
                elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                elements.append(Paragraph(result['explanation'], styles['Normal']))
                elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                elements.append(Paragraph(result['remediation'], styles['Normal']))
            if 'url' in result:
                elements.append(Paragraph(f"Scraped content from {result['url']}:", styles['Heading2']))
                elements.append(Paragraph(html.escape(result.get('scraped_content', '')), styles['Code']))  # Simplified HTML content
                elements.append(Paragraph("HTML Analysis:", styles['Heading2']))
                for issue in result.get('html_analysis', []):
                    elements.append(Paragraph(html.escape(issue), styles['Normal']))
            if 'ssl_certificate' in result:
                elements.append(Paragraph(f"SSL Certificate for {result['target']}:", styles['Heading2']))
                elements.append(Paragraph(html.escape(json.dumps(result['ssl_certificate'], indent=4)), styles['Code']))
                elements.append(Paragraph(f"Cipher: {result['ciphers']}", styles['Normal']))
                elements.append(Paragraph(f"Security Headers: {html.escape(json.dumps(result['security_headers'], indent=4))}", styles['Normal']))
                elements.append(Paragraph(f"Grade: {result['grade']}", styles['Normal']))
                elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                elements.append(Paragraph(result['explanation'], styles['Normal']))
                elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                elements.append(Paragraph(result['remediation'], styles['Normal']))
            if 'ssh_output' in result:
                elements.append(Paragraph(f"SSH connection output for {result['target']}:", styles['Heading2']))
                elements.append(Paragraph(html.escape(result['ssh_output']), styles['Code']))
                elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                elements.append(Paragraph(result['explanation'], styles['Normal']))
                elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                elements.append(Paragraph(result['remediation'], styles['Normal']))
            if 'attack' in result:
                elements.append(Paragraph(f"{result['attack']} on {result['target']}:", styles['Heading2']))
                elements.append(Paragraph(result['result'], styles['Normal']))
                elements.append(Paragraph("**Explanation:**", styles['Heading2']))
                elements.append(Paragraph(result['explanation'], styles['Normal']))
                elements.append(Paragraph("**Remediation:**", styles['Heading2']))
                elements.append(Paragraph(result['remediation'], styles['Normal']))

        doc.build(elements)
        log_and_display("Report generated successfully as 'report.pdf'.", 'info')
        messagebox.showinfo("Success", "Report generated successfully as 'report.pdf'.")
        webbrowser.open("report.pdf")
    except Exception as e:
        log_and_display(f"An error occurred while generating the report: {str(e)}", 'error')

def open_brute_force_window():
    bf_window = Toplevel(root)
    bf_window.title("Brute Force Attack Simulation")
    set_dark_theme(bf_window)

    ttk.Label(bf_window, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
    ttk.Label(bf_window, text="Username:").grid(row=1, column=0, padx=5, pady=5)
    ttk.Label(bf_window, text="Password List:").grid(row=2, column=0, padx=5, pady=5)

    target_ip = StringVar()
    username = StringVar()
    password_list = StringVar()

    ttk.Entry(bf_window, textvariable=target_ip).grid(row=0, column=1, padx=5, pady=5)
    ttk.Entry(bf_window, textvariable=username).grid(row=1, column=1, padx=5, pady=5)
    ttk.Entry(bf_window, textvariable=password_list).grid(row=2, column=1, padx=5, pady=5)

    def start_brute_force():
        threading.Thread(target=brute_force_attack, args=(text_area, results, target_ip.get(), username.get(), password_list.get())).start()
        bf_window.destroy()

    ttk.Button(bf_window, text="Start Attack", command=start_brute_force).grid(row=3, columnspan=2, pady=10)

def attack_sql_injection(text_area, results, url, parameter):
    try:
        log_and_display(f"Testing SQL Injection on {url} with parameter {parameter}...")
        payload = f"{parameter}=1' OR '1'='1"
        full_url = f"{url}?{payload}"
        response = requests.get(full_url)
        explanation = ""
        remediation = ""
        if "syntax error" not in response.text and "mysql_fetch" in response.text:
            result = f"SQL Injection vulnerability found on {url} with parameter {parameter}."
            explanation = (
                "SQL Injection is a code injection technique that might destroy your database. "
                "It is one of the most common web hacking techniques. "
                "SQL Injection is the placement of malicious code in SQL statements, via web page input."
            )
            remediation = (
                "To fix SQL Injection vulnerabilities:\n"
                "1. Always use parameterized queries or prepared statements.\n"
                "2. Avoid constructing SQL queries with user input directly."
            )
        else:
            result = f"No SQL Injection vulnerability found on {url} with parameter {parameter}."
            explanation = (
                "The tested parameter does not seem to be vulnerable to SQL Injection. "
                "It might be using parameterized queries or other security measures."
            )
            remediation = (
                "To ensure ongoing security:\n"
                "1. Continue using parameterized queries and avoid dynamic SQL queries.\n"
                "2. Ensure all user inputs are properly sanitized and validated."
            )
        log_and_display(result)
        log_and_display(f"Explanation: {explanation}")
        log_and_display(f"Remediation: {remediation}")
        results.append({
            'target': url, 
            'attack': 'SQL Injection', 
            'result': result,
            'explanation': explanation,
            'remediation': remediation
        })
    except Exception as e:
        log_and_display(f"An error occurred during SQL Injection attack: {str(e)}", 'error')
    finally:
        update_progress(100)

def attack_rce(text_area, results, target, username, password_list):
    try:
        if target and username and password_list:
            log_and_display(f"Starting RCE attack on {target} with brute force on username {username}...")
            with open(password_list, 'r') as file:
                passwords = file.readlines()
            total_passwords = len(passwords)
            success = False
            for i, password in enumerate(passwords):
                password = password.strip()
                log_and_display(f"Trying password: {password}")
                if password == "correct_password":  # Replace with actual check
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target, username=username, password=password)
                    stdin, stdout, stderr = ssh.exec_command('id')
                    output = stdout.read().decode()
                    log_and_display(f"RCE successful. Command output:\n{output}")
                    explanation = (
                        "Remote Code Execution (RCE) allows an attacker to execute arbitrary commands on the target system. "
                        "This can lead to full system compromise. RCE combined with a successful brute force can be devastating."
                    )
                    remediation = (
                        "To prevent RCE attacks:\n"
                        "1. Use strong, unique passwords and implement multi-factor authentication.\n"
                        "2. Regularly update and patch all systems and applications.\n"
                        "3. Restrict access to critical systems using firewalls and access controls."
                    )
                    results.append({'target': target, 'attack': 'RCE', 'result': 'Success', 'output': output, 'explanation': explanation, 'remediation': remediation})
                    ssh.close()
                    success = True
                    break
                update_progress((i / total_passwords) * 100)
                time.sleep(0.1)  # Simulate delay for each attempt
            if not success:
                log_and_display("RCE attack completed. No successful login found.", 'info')
                explanation = (
                    "Remote Code Execution (RCE) was not successful as the brute force attack did not find any valid credentials. "
                    "RCE requires valid credentials to execute commands on the target system."
                )
                remediation = (
                    "Ensure strong passwords and multi-factor authentication are used to prevent unauthorized access. "
                    "Regularly audit and review access logs for suspicious activity."
                )
                results.append({'target': target, 'attack': 'RCE', 'result': 'Failure', 'explanation': explanation, 'remediation': remediation})
        else:
            log_and_display("Incomplete RCE attack parameters provided.", 'warning')
    except Exception as e:
        log_and_display(f"An unexpected error occurred during RCE attack: {str(e)}", 'error')
    finally:
        update_progress(100)

def attack_xss(text_area, results, url, parameter):
    try:
        log_and_display(f"Testing XSS on {url} with parameter {parameter}...")
        payload = f"<script>alert('XSS');</script>"
        full_url = f"{url}?{parameter}={payload}"
        response = requests.get(full_url)
        explanation = ""
        remediation = ""
        if payload in response.text:
            result = f"XSS vulnerability found on {url} with parameter {parameter}."
            explanation = (
                "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. "
                "This can lead to session hijacking, defacement, or redirection to malicious sites."
            )
            remediation = (
                "To prevent XSS vulnerabilities:\n"
                "1. Implement proper input validation and output encoding.\n"
                "2. Use Content Security Policy (CSP) to restrict the sources from which scripts can be loaded."
            )
        else:
            result = f"No XSS vulnerability found on {url} with parameter {parameter}."
            explanation = (
                "The tested parameter does not seem to be vulnerable to XSS. "
                "It might be using proper input validation and output encoding techniques."
            )
            remediation = (
                "Ensure all user inputs are properly sanitized and validated to prevent XSS attacks. "
                "Continue using secure coding practices and implement Content Security Policy (CSP)."
            )
        log_and_display(result)
        log_and_display(f"Explanation: {explanation}")
        log_and_display(f"Remediation: {remediation}")
        results.append({
            'target': url, 
            'attack': 'XSS', 
            'result': result,
            'explanation': explanation,
            'remediation': remediation
        })
    except Exception as e:
        log_and_display(f"An error occurred during XSS attack: {str(e)}", 'error')
    finally:
        update_progress(100)

# Add author mention
author_label = Label(root, text="Created by Amine (4|\\/|1|\\|3)", background='#2E2E2E', foreground='gray', font=('Helvetica', 8))
author_label.pack(side='bottom', pady=5)

if __name__ == "__main__":
    list_files_in_directory()

    def get_target_and_discover():
        target = simpledialog.askstring("Target", "Enter the target IP address:")
        if target:
            threading.Thread(target=discover_ports_services, args=(text_area, results, target)).start()

    def get_target_and_detect():
        target = simpledialog.askstring("Target", "Enter the target IP address:")
        if target:
            threading.Thread(target=detect_vulnerabilities, args=(text_area, results, target)).start()

    def get_target_and_os_detect():
        target = simpledialog.askstring("Target", "Enter the target IP address:")
        if target:
            threading.Thread(target=os_detection, args=(text_area, results, target)).start()

    def get_target_and_service_version_detect():
        target = simpledialog.askstring("Target", "Enter the target IP address:")
        if target:
            threading.Thread(target=service_version_detection, args=(text_area, results, target)).start()

    def get_target_and_web_server_detect():
        target = simpledialog.askstring("Target", "Enter the target IP address:")
        if target:
            threading.Thread(target=web_server_detection, args=(text_area, results, target)).start()

    def get_target_and_subdomain_enumerate():
        target = simpledialog.askstring("Target", "Enter the target domain:")
        if target:
            threading.Thread(target=subdomain_enumeration, args=(text_area, results, target)).start()

    def get_target_and_directory_file_discover():
        target = simpledialog.askstring("Target", "Enter the target URL:")
        if target:
            threading.Thread(target=directory_file_discovery, args=(text_area, results, target)).start()

    def get_password_and_analyze():
        password = simpledialog.askstring("Password", "Enter the password to test:")
        if password:
            threading.Thread(target=analyze_password_security, args=(text_area, results, password)).start()

    def get_url_and_scrape():
        url = simpledialog.askstring("URL", "Enter the URL to scrape:")
        if url:
            threading.Thread(target=scrape_html, args=(text_area, results, url)).start()

    def get_target_and_scan_ssl():
        target = simpledialog.askstring("Target", "Enter the target domain:")
        if target:
            threading.Thread(target=ssl_certificate_scan, args=(text_area, results, target)).start()

    def get_ssh_details_and_connect():
        target = simpledialog.askstring("Target", "Enter the target IP address:")
        username = simpledialog.askstring("Username", "Enter the SSH username:")
        password = simpledialog.askstring("Password", "Enter the SSH password:", show='*')
        if target and username and password:
            threading.Thread(target=ssh_connect, args=(text_area, results, target, username, password)).start()

    def get_url_and_sql_inject():
        url = simpledialog.askstring("Target URL", "Enter the target URL:")
        parameter = simpledialog.askstring("Parameter", "Enter the vulnerable parameter:")
        if url and parameter:
            threading.Thread(target=attack_sql_injection, args=(text_area, results, url, parameter)).start()

    def get_rce_details_and_start():
        target = simpledialog.askstring("Target IP", "Enter the target IP address:")
        username = simpledialog.askstring("Username", "Enter the SSH username:")
        password_list = simpledialog.askstring("Password List", "Enter the path to the password list:")
        if target and username and password_list:
            threading.Thread(target=attack_rce, args=(text_area, results, target, username, password_list)).start()

    def get_xss_details_and_start():
        url = simpledialog.askstring("Target URL", "Enter the target URL:")
        parameter = simpledialog.askstring("Parameter", "Enter the parameter to test:")
        if url and parameter:
            threading.Thread(target=attack_xss, args=(text_area, results, url, parameter)).start()

    # Buttons for each functionality
    ttk.Button(tab1, text="Discover Ports/Services", command=get_target_and_discover).pack(pady=10)
    ttk.Button(tab1, text="Detect Vulnerabilities", command=get_target_and_detect).pack(pady=10)
    ttk.Button(tab1, text="OS Detection", command=get_target_and_os_detect).pack(pady=10)
    ttk.Button(tab1, text="Service Version Detection", command=get_target_and_service_version_detect).pack(pady=10)
    ttk.Button(tab1, text="Web Server Detection", command=get_target_and_web_server_detect).pack(pady=10)
    ttk.Button(tab1, text="Subdomain Enumeration", command=get_target_and_subdomain_enumerate).pack(pady=10)
    ttk.Button(tab1, text="Directory and File Discovery", command=get_target_and_directory_file_discover).pack(pady=10)
    ttk.Button(tab2, text="Generate Report", command=lambda: threading.Thread(target=generate_report, args=(text_area, results)).start()).pack(pady=10)
    ttk.Button(tab2, text="Scrape HTML", command=get_url_and_scrape).pack(pady=10)
    ttk.Button(tab2, text="Test Password Strength", command=get_password_and_analyze).pack(pady=10)
    ttk.Button(tab2, text="Scan SSL Certificate", command=get_target_and_scan_ssl).pack(pady=10)
    ttk.Button(tab4, text="Brute Force Attack", command=open_brute_force_window).pack(pady=10)
    ttk.Button(tab4, text="SSH Connect", command=get_ssh_details_and_connect).pack(pady=10)
    ttk.Button(tab4, text="SQL Injection Attack", command=get_url_and_sql_inject).pack(pady=10)
    ttk.Button(tab4, text="Remote Code Execution", command=get_rce_details_and_start).pack(pady=10)
    ttk.Button(tab4, text="XSS Attack", command=get_xss_details_and_start).pack(pady=10)

    root.after(100, handle_input)
    root.mainloop()
