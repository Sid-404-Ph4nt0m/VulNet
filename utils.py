import logging
import json
import os
from datetime import datetime
import re


def extract_hostname(url):
    """
    Extract the hostname from a full URL using regex.
    Returns the hostname if found, otherwise None.
    """
    # This regex matches an optional "http://" or "https://" at the beginning,
    # then captures the hostname up until the first '/', '?', or '#' character.
    pattern = r'^(?:https?://)?([^/?#]+)'
    match = re.search(pattern, url)
    return match.group(1) if match else None


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler('app.log')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(file_handler)


def save_results(results, filename='results.json'):
    """
    Saves the immediate testing results to a JSON file.
    Overwrites any existing contents with the latest results.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info("Results saved to %s", filename)
    except Exception as e:
        logging.error("Failed to save results: %s", e)


def save_history(result, filename='history.json'):
    """
    Appends a new scan result with a timestamp to the historical JSON file.
    If the file doesn't exist, it creates one.
    """
    history = []
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                history = json.load(f)
        except Exception as e:
            logging.error("Failed to read %s: %s", filename, e)
    # Add a timestamp to the result for historical tracking
    result['timestamp'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    history.append(result)
    try:
        with open(filename, 'w') as f:
            json.dump(history, f, indent=4)
        logging.info("Historical results updated in %s", filename)
    except Exception as e:
        logging.error("Failed to save historical results: %s", e)


def read_history(filename='history.json'):
    """
    Reads and returns the historical scan data from the history file.
    If the file doesn't exist or there's an error, returns an empty list.
    """
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error("Failed to read history from %s: %s", filename, e)
            return []
    return []


def get_analytics(history):
    """
    Computes basic analytics from the historical scan results including:
      - Total number of scans performed.
      - Total number of network vulnerabilities detected across all scans.
      - Total number of application vulnerabilities detected across all scans.
      - Timestamp of the latest scan.

    For application vulnerabilities, it checks each vulnerability scan result for the keyword "Potential".

    Returns:
        dict: Analytics details.
    """
    total_scans = len(history)
    total_network_vulnerabilities = 0
    total_application_vulnerabilities = 0
    latest_timestamp = None

    for entry in history:
        # Count network vulnerabilities
        network_vulns = entry.get("network_vulnerabilities", [])
        total_network_vulnerabilities += len(network_vulns)

        # Count application vulnerabilities from vulnerability_scan results
        vulnerability_scan = entry.get("vulnerability_scan", {})
        for test in vulnerability_scan.values():
            if "Potential" in test:
                total_application_vulnerabilities += 1

        ts = entry.get("timestamp")
        if ts:
            if latest_timestamp is None or ts > latest_timestamp:
                latest_timestamp = ts

    return {
        "total_scans": total_scans,
        "total_network_vulnerabilities": total_network_vulnerabilities,
        "total_vulnerability_scans": total_application_vulnerabilities,
        "latest_scan": latest_timestamp or "N/A"
    }