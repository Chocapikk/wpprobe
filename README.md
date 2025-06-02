![WPProbe](./images/logo.jpg)

**"Because why scan blind when WordPress exposes itself?"**  

---

![WPProbe](./images/wpprobe.png)

[![Go CI](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml)
[![Latest Release](https://img.shields.io/github/v/release/Chocapikk/wpprobe)](https://github.com/Chocapikk/wpprobe/releases/latest)


## 🧐 What is WPProbe?  

**WPProbe** is a **fast and efficient WordPress plugin scanner** that leverages **REST API enumeration (`?rest_route`)** to detect installed plugins **without brute-force**.  

Unlike traditional scanners that hammer websites with requests, WPProbe takes a smarter approach by querying the exposed REST API. This technique allows us to **identify plugins stealthily**, reducing detection risks and **speeding up the scan process**.  

📌 **Currently, over 3030 plugins** can be identified using the stealthy method, and thousands more with the brute-force capabilities!

---

## 🚀 How It Works  

### Stealthy Mode (Default)
1️⃣ **Fetch** a list of known WordPress plugins from a precompiled database (Wordfence).  
2️⃣ **Scan** the target site for exposed REST API routes (`?rest_route=/`).  
3️⃣ **Match** the discovered endpoints with known plugin signatures.  
4️⃣ **Retrieve** the installed version (when possible) by extracting metadata from files like `readme.txt`.  
5️⃣ **Correlate** detected plugins with publicly known vulnerabilities (CVE mapping).  
6️⃣ **Output** the results in a structured format (CSV or JSON) for easy analysis.  

🔥 **This means fewer requests, faster scans, and a lower chance of getting blocked by WAFs or security plugins!**  

### Brute-Force Mode
1️⃣ **Load** a comprehensive list of WordPress plugins (10k+ common plugins by default).  
2️⃣ **Check** for the existence of each plugin by directly requesting its directory.  
3️⃣ **Detect** plugins based on HTTP response codes (non-404 responses indicate plugin exists).  
4️⃣ **Retrieve** versions and check for vulnerabilities as in stealthy mode.  
5️⃣ **Output** the results in your preferred format.  

### Hybrid Mode
1️⃣ **Start** with a stealthy scan using REST API endpoints.  
2️⃣ **Record** all plugins found via the stealthy method.  
3️⃣ **Continue** with a brute-force scan, skipping plugins already detected.  
4️⃣ **Combine** results from both methods for maximum detection coverage.  
5️⃣ **Process** vulnerability information and output results.  

🔄 **Hybrid mode gives you the best of both worlds: the stealth of REST API scanning with the thoroughness of brute-force!**  

---

## ⚙️ Features  

- ✅ **Multiple scanning modes**:
   - **Stealthy mode** – Uses REST API to detect plugins with minimal footprint
   - **Brute-force mode** – Comprehensive plugin detection using direct requests
   - **Hybrid mode** – Starts with stealthy scanning then uses brute-force only for remaining plugins
- ✅ **High-speed scanning** – Multithreaded scanning with a sleek progress bar.  
- ✅ **Vulnerability mapping** – Automatically associates detected plugins with known CVEs.  
- ✅ **Multiple output formats** – Save results in **CSV** or **JSON**.  
- ✅ **Resilient scanning** – Handles sites with missing version info gracefully.  
- ✅ **Optimized detection** – Intelligently combines methods to maximize plugin discovery.

---

## 📌 Limitations  

### Stealthy Mode
🔹 Some plugins don't expose REST API endpoints, making them undetectable via this method.  
🔹 If a plugin is outdated, disabled, or hidden by security plugins, it may not be detected.  
🔹 The technique relies on a predefined plugin-to-endpoint mapping, which is regularly updated.  

### Brute-Force Mode
🔹 Generates more HTTP requests, which may trigger security mechanisms or rate limits.  
🔹 Less stealthy than REST API scanning as it directly probes for plugin directories.  
🔹 Limited by the plugin list's comprehensiveness.  

### Hybrid Mode
🔹 Still generates a significant number of requests after the stealthy phase.  
🔹 May take longer to complete than pure stealthy mode.  

---

## 🔧 Installation

### Option 1️⃣ (Quick setup via `go install`)

```bash
go install github.com/Chocapikk/wpprobe@latest
```
- **Requires Go 1.22+**  
- Ensure `$(go env GOPATH)/bin` is in your `$PATH`  

### Option 2️⃣ (Manual build)

1. **Clone the repository**  
   ```bash
   git clone https://github.com/Chocapikk/wpprobe
   cd wpprobe
   ```
2. **Install dependencies**  
   ```bash
   go mod tidy
   ```
3. **Build the binary**  
   ```bash
   go build -o wpprobe
   ```
   Move or copy `wpprobe` into a directory listed in your `$PATH`.

### Option 3️⃣ (Docker)
1. **Build Image**
   ```bash
   docker build -t wpprobe .
   ```
2. **Run**
   ```bash
   docker run -it --rm wpprobe
   ```

---

## 🕵️ Usage  

### **🔄 Update WPProbe**  
Update WPProbe to the latest version:  
```bash
./wpprobe update
```

### **Update the Wordfence database**  
Update the local Wordfence vulnerability database:  
```bash
./wpprobe update-db
```

### **Basic scan for a single website (Stealthy mode - default)**  
Scan a single WordPress site using the default stealthy mode:  
```bash
./wpprobe scan -u https://example.com
```

### **Use brute-force mode for comprehensive scanning**  
Scan a WordPress site using brute-force detection:  
```bash
./wpprobe scan -u https://example.com --mode bruteforce
```

### **Use hybrid mode for optimal balance of stealth and thoroughness**  
Scan a WordPress site using hybrid mode (stealthy first, then brute-force for remaining plugins):  
```bash
./wpprobe scan -u https://example.com --mode hybrid
```

### **Provide a custom plugin list for brute-force scanning**  
Use a custom list of plugins for brute-force or hybrid scanning:  
```bash
./wpprobe scan -u https://example.com --mode bruteforce --plugin-list my-plugins.txt
```

### **Scan multiple targets from a file with 20 concurrent threads**  
Scan multiple sites from a `targets.txt` file using 20 threads:  
```bash
./wpprobe scan -f targets.txt -t 20
```

### **Save results to a CSV file**  
Save scan results to a CSV file:  
```bash
./wpprobe scan -f targets.txt -t 20 -o results.csv
```

### **Save results to a JSON File**  
Save scan results to a JSON file:  
```bash
./wpprobe scan -f targets.txt -t 20 -o results.json
```

---

## 📜 Example Output  

### **CSV Format**  

```
URL,Plugin,Version,Severity,AuthType,CVEs,CVE Links,CVSS Score,CVSS Vector,Title
http://localhost:5555,give,2.20.1,critical,Unauth,CVE-2025-22777,https://www.cve.org/CVERecord?id=CVE-2025-22777,9.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,GiveWP <= 3.19.3 - Unauthenticated PHP Object Injection
http://localhost:5555,give,2.20.1,high,Privileged,CVE-2024-9130,https://www.cve.org/CVERecord?id=CVE-2024-9130,7.2,CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H,GiveWP <= 3.16.1 - Authenticated SQL Injection
http://localhost:5555,give,2.20.1,medium,Auth,CVE-2024-1957,https://www.cve.org/CVERecord?id=CVE-2024-1957,6.4,CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N,GiveWP <= 3.6.1 - Stored XSS via Shortcode
http://localhost:5555,give,2.20.1,medium,Unauth,CVE-2024-47315,https://www.cve.org/CVERecord?id=CVE-2024-47315,4.3,CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N,GiveWP <= 3.15.1 - Cross-Site Request Forgery
http://localhost:5555,give,2.20.1,medium,Privileged,CVE-2022-28700,https://www.cve.org/CVERecord?id=CVE-2022-28700,5.5,CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:H/A:N,GiveWP <= 2.20.2 - Authenticated Arbitrary File Creation
http://localhost:5555,jetpack,14.3,,,,,,,No vulnerabilities found
http://localhost:5555,woocommerce,9.6.0,,,,,,,No vulnerabilities found
```

### **JSON Format**  

```json
{
  "url": "http://localhost:5555",
  "plugins": {
    "give": [
      {
        "version": "2.20.1",
        "severities": {
          "critical": [
            {
              "auth_type": "Unauth",
              "vulnerabilities": [
                {
                  "cve": "CVE-2025-22777",
                  "cve_link": "https://www.cve.org/CVERecord?id=CVE-2025-22777",
                  "cvss_score": 9.8,
                  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  "title": "GiveWP <= 3.19.3 - Unauthenticated PHP Object Injection"
                }
              ]
            }
          ],
          "high": [
            {
              "auth_type": "Privileged",
              "vulnerabilities": [
                {
                  "cve": "CVE-2024-9130",
                  "cve_link": "https://www.cve.org/CVERecord?id=CVE-2024-9130",
                  "cvss_score": 7.2,
                  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                  "title": "GiveWP <= 3.16.1 - Authenticated SQL Injection"
                }
              ]
            }
          ],
          "medium": [
            {
              "auth_type": "Auth",
              "vulnerabilities": [
                {
                  "cve": "CVE-2024-1957",
                  "cve_link": "https://www.cve.org/CVERecord?id=CVE-2024-1957",
                  "cvss_score": 6.4,
                  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
                  "title": "GiveWP <= 3.6.1 - Stored XSS via Shortcode"
                }
              ]
            }
          ]
        }
      }
    ],
    "woocommerce": [
      {
        "version": "9.6.0",
        "severities": {}
      }
    ]
  }
}
```

---

## 🎯 Why WPProbe?  

💡 **The idea behind WPProbe** comes from the realization that **WordPress exposes plugin data through its REST API (`?rest_route`)**. Instead of wasting time brute-forcing plugin paths, this tool **matches REST endpoints with known plugin signatures**, allowing for faster and more stealthy scans.  

**Over 3030 plugins** are currently detectable using this method, making WPProbe one of the most effective tools for WordPress reconnaissance.  

---

## 🤖 Future Improvements  

🛠️ **Expanding the plugin database** – More plugins, better detection.  
⚡ **Adding more fingerprinting techniques** – Beyond REST API, integrating alternative detection methods.  
📊 **Enhanced reporting** – JSON output and integration with security dashboards.  

---

## 📈 Stats

<a href="https://star-history.com/#Chocapikk/wpprobe&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date" />
  </picture>
</a>

---

## ✨ Credits  

Developed by **@Chocapikk** 🍫, inspired by modern recon methodologies and the **REST API enumeration trick**.  

👀 Stay stealthy, scan smart! 🚀
