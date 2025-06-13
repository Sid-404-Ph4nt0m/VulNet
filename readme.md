# VulNet: Advanced Vulnerability Scanner and Exploitation Framework

**Disclaimer:**  
This project is intended for educational purposes and authorized security testing only. Do **NOT** use this tool against websites or systems without explicit, written permission. Unauthorized use may be illegal and unethical.

## Project Overview

VulNet is a modular framework designed for ethical vulnerability scanning and exploitation. Built using Python and HTML, it leverages advanced port scanning and multiple exploit tests to provide a comprehensive security assessment, featuring:

- **Advanced Port Scanning:**  
  Uses extended Nmap capabilities including OS detection, service/version identification, and default script scanning.

- **Multiple Exploit Tests:**  
  Modules include:
  - SQL injection testing with parameter fuzzing.
  - Cross-Site Scripting (XSS) vulnerability explorations.
  - Command injection evaluations.
  - Simulated buffer overflow demonstrations.

- **Modern Flask UI & History Dashboard:**  
  A dark-themed interface that:
  - Accepts target website inputs.
  - Displays real-time scan and exploit results.
  - Archives current results (saved to `results.json`) along with historical data (`history.json`).
  - Provides a dashboard with tabular analytics and detailed reporting.

- **Inline Logging & Auditing:**  
  Each module logs its operations and encountered errors to facilitate debugging and forensic analysis. Logs are maintained in `app.log`.

## Project Structure

```plaintext
VulNet/
├── app.py                      # Main Flask application integrating scanning and exploitation tests.
├── network_scanner.py          # Module for advanced port scanning utilizing python-nmap for OS, script, and version detection.
├── vulnerability_scanner.py    # Module implementing SQL injection, XSS, command injection, and buffer overflow tests.
├── utils.py                    # Utility module for logging configuration, file operations, and analytics.
├── requirements.txt            # Python dependencies required for the project.
└── templates/                  # HTML templates for the Flask UI.
    ├── index.html              # Entry point for scanning targets in a dark-themed interface.
    ├── results.html            # Displays detailed output for current scan and exploit results.
    ├── dashboard.html          # Shows historical data with analytics in an organized, tabular format.
    └── indepthdetail.html      # Provides in-depth reporting on vulnerabilities and assessments.
```

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Sid-404-Ph4nt0m/VulNet.git
   cd VulNet
   ```

2. **Set Up a Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Customize settings as needed for your scanning and testing requirements:
- **Scanning Options:**  
  Adjust port ranges, OS detection, service/version scanning, and Nmap scripts in `network_scanner.py`.
- **Exploit Modules:**  
  Modify payloads or extend functionalities in `vulnerability_scanner.py`.
- **Logging:**  
  Logging levels and file paths are configurable in `utils.py`.

## Usage

1. **Run the Application:**
   ```bash
   python app.py
   ```

2. **Access the Web Interface:**
   Open your web browser and navigate to [http://127.0.0.1:5000/](http://127.0.0.1:5000/) to begin scanning.

3. **Review Results:**
   - **Results Page:** View immediate scan outcomes and exploit tests.
   - **Dashboard:** Check historical scans, detailed logs, and analytic summaries.

## Logging & Data Management

- **Inline Logging:**  
  Each module employs Python’s `logging` module. Check `app.log` for detailed logs.
- **Data Storage:**  
  - Real-time results are saved in `results.json`.
  - Historical data is archived in `history.json` for ongoing analysis.

## Ethical Considerations

VulNet is intended for use in ethical hacking and penetration testing under authorized scenarios only. Always secure explicit permission from the system owner prior to conducting any tests.

## Contributing

Contributions are encouraged! Please fork the repository and submit pull requests with enhancements, bug fixes, or additional features.

## License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for more details.