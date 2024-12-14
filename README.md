# secureHTTPs
This tool is designed to analyze the security configuration of a website by checking its SSL/TLS setup, Content Security Policy (CSP), and certificate expiration date. The tool provides recommendations on improving the security of the website.

## Preinstallation steps:


## Installation guide:
### 1) Clone Repository:
```bash
git clonehttps://github.com/eros938/secureHTTPs.git
```
### 2) Move into repo directory:

```bash
cd Web-Security-Scanner
```
### 3) Run the script:
```shell
sudo python3 analyzer.py 
```

## Features
 * **SSL/TLS Configuration Analysis:**

Checks the protocol version being used (e.g., TLSv1.2, TLSv1.3).
Analyzes the cipher suite and compares it against a list of recommended cipher suites.
Provides recommendations for upgrading to more secure protocol versions and cipher suites if necessary.
* **Certificate Expiration Check:**

Retrieves and displays the number of days until the SSL/TLS certificate expires.
* **Content Security Policy (CSP) Analysis:**

Checks for the presence of the CSP header and displays its contents if found.
Provides a note if the CSP header is not found.
* **HTTP to HTTPS Redirection:**

Automatically converts HTTP URLs to HTTPS to ensure secure connections.
How It Works
The tool uses Python's tkinter library for the GUI, ssl and socket libraries for analyzing SSL/TLS configurations, and requests library for fetching CSP headers.

## Main Components:
* **GUI**: A simple user interface built with tkinter where users can input a website URL and view the analysis results.
SSL/TLS Analysis: Establishes an SSL connection to the provided URL, retrieves the protocol version and cipher suite, and compares them with recommended settings.
Certificate Expiration: Checks the SSL/TLS certificate for its expiration date and calculates the number of days until expiration.
CSP Analysis: Sends an HTTP request to fetch and analyze the CSP header from the website's response.
How to Use:

* **Install the necessary Python libraries:**

Ensure you have requests and tkinter libraries installed. You can install requests using pip install requests.
* **Run the script:**

Execute the Python script to launch the GUI.
Enter the URL of the website you want to analyze in the input field.
Click the "Analyze" button to start the analysis.
* **View Results:**

The tool will display the SSL/TLS configuration, certificate expiration date, and CSP details in the text area of the GUI.
Recommendations will be provided based on the analysis results.
## Example

1. When you enter a URL and click "Analyze," the tool will display information similar to the following:

2. Analyzing website: example.com

3. Days until certificate expiration: 123


4. **Output:**
- Protocol Version: TLSv1.3
- Cipher Suite: ('TLS_AES_128_GCM_SHA256', 'TLSv1.3', 128)
- The current cipher suite is recommended.
- Content Security Policy (CSP): default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'; connect-src 'self'; frame-ancestors 'self'

  
![image](https://github.com/eros938/Web-Security-Scanner/assets/150992485/5eaf8046-3e97-4b31-b36f-814f1cc31e22)






