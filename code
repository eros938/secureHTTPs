import tkinter as tk
import datetime
import ssl
import socket
from urllib.parse import urlparse
import requests

# Function to analyze SSL/TLS configuration and provide recommendations
def analyze_ssl_config(hostname):
    try:
        # Establish SSL connection
        with socket.create_connection((hostname, 443)) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as s:
                # Protocol version analysis
                protocol_version = s.version()
                result_text.insert(tk.END, f"Protocol Version: {protocol_version}\n")

                # Cipher suite analysis
                cipher_suite = s.cipher()
                result_text.insert(tk.END, f"Cipher Suite: {cipher_suite}\n")

                # Check for recommended protocol version
                if protocol_version in ['TLSv1.2', 'TLSv1.3']:
                    result_text.insert(tk.END, "Recommended protocol version is being used.\n")
                else:
                    result_text.insert(tk.END, "Consider upgrading to a recommended protocol version.\n")

                # Recommended cipher suites
                recommended_cipher_suites = [
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_AES_128_GCM_SHA256',
                    'ECDHE-RSA-AES256-GCM-SHA384',
                    'ECDHE-RSA-AES128-GCM-SHA256',
                    'ECDHE-RSA-AES256-SHA',
                    'ECDHE-RSA-AES128-SHA',
                ]

                # Check if current cipher suite is recommended
                if cipher_suite[0] in recommended_cipher_suites:
                    result_text.insert(tk.END, "The current cipher suite is recommended.\n\n")
                else:
                    result_text.insert(tk.END, "The current cipher suite is not recommended. Consider using one of the following:\n")
                    for suite in recommended_cipher_suites:
                        result_text.insert(tk.END, f"- {suite}\n")
                    result_text.insert(tk.END, "\n")

    except ssl.SSLError as e:
        result_text.insert(tk.END, f"SSL Error analyzing SSL/TLS configuration for {hostname}: {e}\n\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error analyzing SSL/TLS configuration for {hostname}: {e}\n\n")

# Function to check SSL/TLS certificate expiration
def check_certificate_expiration(hostname):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.create_connection((hostname, 443)), server_hostname=hostname) as s:
            cert = s.getpeercert()
            expiration_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y GMT")
            days_until_expire = expiration_date - datetime.datetime.now()
            return days_until_expire.days
    except Exception as e:
        result_text.insert(tk.END, f"Error checking certificate expiration for {hostname}: {e}\n")
        return None

# Function to analyze CSP (Content Security Policy) configuration
def analyze_csp_config(hostname):
    try:
        # Send HTTP request to retrieve response headers
        response = requests.get(f"https://{hostname}")
        headers = response.headers

        # Check if CSP header is present
        if 'Content-Security-Policy' in headers:
            csp_header = headers['Content-Security-Policy']
            result_text.insert(tk.END, f"Content Security Policy (CSP): {csp_header}\n\n")
        else:
            result_text.insert(tk.END, "No Content Security Policy (CSP) found.\n\n")

    except Exception as e:
        result_text.insert(tk.END, f"Error analyzing CSP for {hostname}: {e}\n\n")

# Function to convert HTTP URLs to HTTPS
def convert_to_https(url):
    if not url.startswith("https://"):
        url = "https://" + url[len("http://"):]
    return url

# Function to analyze the URL provided by the user
def analyze_website():
    website_url = website_entry.get()

    # Check if URL is HTTP and convert it to HTTPS
    if website_url.startswith("http://"):
        result_text.insert(tk.END, "The website is being accessed via HTTP. Converting to HTTPS...\n\n")
        converted_url = convert_to_https(website_url)
        result_text.insert(tk.END, f"Converted URL: {converted_url}\n\n")
        website_url = converted_url

    # Parse the URL to extract the hostname
    parsed_url = urlparse(website_url)
    hostname = parsed_url.hostname

    if not hostname:
        result_text.insert(tk.END, "Invalid URL. Please provide a valid URL.\n\n")
        return

    # Check SSL/TLS certificate expiration first
    days_until_expire = check_certificate_expiration(hostname)
    if days_until_expire is not None:
        result_text.insert(tk.END, f"Days until certificate expiration: {days_until_expire}\n\n")
    else:
        result_text.insert(tk.END, "Certificate expiration check failed.\n\n")

    # Analyze SSL/TLS configuration
    result_text.insert(tk.END, f"Analyzing website: {hostname}\n\n")
    analyze_ssl_config(hostname)

    # Analyze CSP configuration
    analyze_csp_config(hostname)

# Create the GUI window
root = tk.Tk()
root.title("Website Security Analyzer")
root.geometry("600x400")

# Create a label and entry for the website URL
website_label = tk.Label(root, text="Website URL:")
website_label.pack()

website_entry = tk.Entry(root, width=50)
website_entry.pack()

# Create a button to analyze the website
analyze_button = tk.Button(root, text="Analyze", command=analyze_website)
analyze_button.pack()

# Create a text widget to display the results
result_text = tk.Text(root, wrap="word", height=15, width=60)
result_text.pack()

# Run the GUI event loop
root.mainloop()
