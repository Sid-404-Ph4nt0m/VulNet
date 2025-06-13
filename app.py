import time
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for
from network_scanner import scan_host, check_common_vulnerabilities
from vulnerability_scanner import sql_injection_test, xss_test, command_injection_test, buffer_overflow_test
from utils import setup_logging, save_results, save_history, read_history, get_analytics
import logging

# Set up logging
setup_logging()
logger = logging.getLogger("app")

app = Flask(__name__)

# In-memory storage for current results (can be replaced by a database)
results_storage = {}


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        website = request.form.get('website')
        if website:
            logger.info("Received website to scan: %s", website)
            # Perform network scan using advanced Nmap functionalities
            network_scan_data = scan_host(website)
            print(network_scan_data)
            network_vulns = check_common_vulnerabilities(network_scan_data)
            print(network_vulns)
            # Perform vulnerability scans (application-level tests)
            sql_injection_result = sql_injection_test(website)
            xss_result = xss_test(website)
            command_injection_result = command_injection_test(website)
            buffer_overflow_result = buffer_overflow_test(website)
            vulnerability_scan_results = {
                'sql_injection_test': sql_injection_result,
                'xss_test': xss_result,
                'command_injection_test': command_injection_result,
                'buffer_overflow_test': buffer_overflow_result
            }
            # Consolidate both network scan and vulnerability scan results for the website
            results = {
                'website': website,
                'network_scan': network_scan_data,
                'network_vulnerabilities': network_vulns,
                'vulnerability_scan': vulnerability_scan_results
            }
            # Save immediate results and update history
            save_results(results)
            save_history(results)
            # Save results in memory for display
            results_storage[website] = results
            print(results_storage)
            return redirect(url_for('results', website=website))
    return render_template('index.html')


@app.route('/results')
def results():
    website = request.args.get('website')
    result = results_storage.get(website)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template('results.html', result=result, now=now)


@app.route('/dashboard')
def dashboard():
    # Read historical scan data and compute analytics
    history = read_history()
    analytics = get_analytics(history)
    return render_template('dashboard.html', history=history, analytics=analytics)


@app.route('/indepth')
def indepth():
    website = request.args.get('website')
    timestamp = request.args.get('timestamp')
    # Retrieve historical scan data
    history = read_history()
    result = None
    for record in history:
        if record.get('website') == website and record.get('timestamp') == timestamp:
            result = record
            break
    if not result:
        # If no matching record is found, redirect to dashboard
        return redirect(url_for('dashboard'))
    return render_template('indepthdetail.html', result=result)


if __name__ == '__main__':
    print("http://127.0.0.1:5000")
    app.run(debug=True)
