import nmap
import logging
from utils import extract_hostname

# Configure logging for the network_scanner module
logger = logging.getLogger("network_scanner")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - network_scanner - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def scan_host(host):
    """
    Perform an advanced port scan on the given host using Nmap.
    This scan includes:
      - Port scan on ports 1-65535 (expanded from 1-1024)
      - Service and version detection (-sV)
      - OS detection (-O)
      - Default script scanning (-sC)

    Returns a dictionary containing scan results including OS details.
    """
    host = extract_hostname(host)
    logger.info("\nStarting advanced scan on %s", host)
    scanner = nmap.PortScanner()
    try:
        # Perform an advanced scan with OS detection and default scripts.
        # scanner.scan(host, '1-65535', arguments='-sV -O -sC')
        scanner.scan(host, '1-1024', arguments='-sV -O -sC')
        scan_data = {}
        for scanned_host in scanner.all_hosts():
            host_data = scanner[scanned_host]
            # Log the raw scan data to help with debugging.
            logger.debug("Raw scan data for host %s: %s", scanned_host, host_data)
            # Extract OS detection info if available.
            os_matches = host_data.get('osmatch', [])
            os_details = os_matches[0] if os_matches else {}
            scan_data[scanned_host] = {
                "addresses": host_data.get("addresses", {}),
                "hostnames": host_data.get("hostnames", []),
                "ports": host_data.get("tcp", {}),
                "os": os_details,
                "nmap_scripts": host_data.get("script", {})
            }
            logger.debug("Scan results for host %s: %s", scanned_host, scan_data[scanned_host])
        logger.info("Completed advanced port scanning")
        return scan_data
    except Exception as e:
        logger.error("Error during advanced scanning: %s", e)
        return None


def check_common_vulnerabilities(scan_data):
    """
    An enhanced function to check for common vulnerabilities using
    results from the advanced network scan. This includes checks based on:
      - Known vulnerable open ports and services.
      - OS vulnerabilities based on detection.
      - Script scan results suggesting outdated software.

    Returns a list of messages regarding potential vulnerabilities.
    """
    vulnerabilities = []
    if not scan_data:
        return vulnerabilities
    for host, result in scan_data.items():
        # Check open ports vulnerabilities.
        tcp_ports = result.get("ports", {})
        for port, port_data in tcp_ports.items():
            service = port_data.get("name", "").lower()
            product = port_data.get("product", "").lower()
            version = port_data.get("version", "")
            vuln_msg = None

            # Enhanced check: old HTTP server severity using numeric comparison.
            if service == 'http' and ("apache" in product or "nginx" in product):
                try:
                    version_float = float(version)
                    if version_float < 2.0:
                        vuln_msg = f"Host {host}: Port {port} running outdated {product} (version {version})."
                except ValueError:
                    # Fallback check if version is not convertible.
                    if '1.0' in version:
                        vuln_msg = f"Host {host}: Port {port} running outdated {product} (version {version})."

            # FTP might be misconfigured.
            if service == 'ftp':
                vuln_msg = f"Host {host}: Port {port} running FTP service which may be vulnerable to anonymous access."

            # Commonly vulnerable service like telnet.
            if service == 'telnet':
                vuln_msg = f"Host {host}: Port {port} running Telnet service which is considered insecure."

            if vuln_msg:
                vulnerabilities.append(vuln_msg)
                logger.warning(vuln_msg)

        # Check for OS vulnerabilities.
        os_info = result.get("os", {})
        if os_info:
            os_name = os_info.get("name", "").lower()
            # Example: flagging if OS is an outdated version of Windows or Linux.
            if "windows xp" in os_name or "ubuntu 10.04" in os_name:
                vuln_msg = f"Host {host}: Detected outdated operating system ({os_name})."
                vulnerabilities.append(vuln_msg)
                logger.warning(vuln_msg)

        # Evaluate nmap script scan results for potential issues.
        script_results = result.get("nmap_scripts", {})
        if script_results:
            for script, output in script_results.items():
                if "vuln" in output.lower() or "outdated" in output.lower():
                    vuln_msg = f"Host {host}: Nmap script {script} indicates a potential vulnerability: {output}"
                    vulnerabilities.append(vuln_msg)
                    logger.warning(vuln_msg)

    return vulnerabilities

# import nmap
# import logging
#
# # Configure logging for the network_scanner module
# logger = logging.getLogger("network_scanner")
# logger.setLevel(logging.DEBUG)
# console_handler = logging.StreamHandler()
# formatter = logging.Formatter('%(asctime)s - network_scanner - %(levelname)s - %(message)s')
# console_handler.setFormatter(formatter)
# logger.addHandler(console_handler)
#
#
# def scan_host(host):
#     """
#     Perform an advanced port scan on the given host using Nmap.
#     This scan includes:
#       - Port scan on ports 1-65535 (expanded from 1-1024)
#       - Service and version detection (-sV)
#       - OS detection (-O)
#       - Default script scanning (-sC)
#
#     Returns a dictionary containing scan results including OS details.
#     """
#     logger.info("Starting advanced scan on %s", host)
#     scanner = nmap.PortScanner()
#     try:
#         # Perform an advanced scan with OS detection and default scripts.
#         scanner.scan(host, '1-65535', arguments='-sV -O -sC')
#         scan_data = {}
#         for scanned_host in scanner.all_hosts():
#             host_data = scanner[scanned_host]
#             # Log the raw scan data to help with debugging.
#             logger.debug("Raw scan data for host %s: %s", scanned_host, host_data)
#             # Extract OS detection info if available.
#             os_matches = host_data.get('osmatch', [])
#             os_details = os_matches[0] if os_matches else {}
#             scan_data[scanned_host] = {
#                 "addresses": host_data.get("addresses", {}),
#                 "hostnames": host_data.get("hostnames", []),
#                 "ports": host_data.get("tcp", {}),
#                 "os": os_details,
#                 "nmap_scripts": host_data.get("script", {})
#             }
#             logger.debug("Scan results for host %s: %s", scanned_host, scan_data[scanned_host])
#         logger.info("Completed advanced port scanning")
#         return scan_data
#     except Exception as e:
#         logger.error("Error during advanced scanning: %s", e)
#         return None
#
#
# def check_common_vulnerabilities(scan_data):
#     """
#     An enhanced function to check for common vulnerabilities using
#     results from the advanced network scan. This includes checks based on:
#       - Known vulnerable open ports and services.
#       - OS vulnerabilities based on detection.
#       - Script scan results suggesting outdated software.
#
#     Returns a list of messages regarding potential vulnerabilities.
#     """
#     vulnerabilities = []
#     if not scan_data:
#         return vulnerabilities
#     for host, result in scan_data.items():
#         # Check open ports vulnerabilities.
#         tcp_ports = result.get("ports", {})
#         for port, port_data in tcp_ports.items():
#             service = port_data.get("name", "").lower()
#             product = port_data.get("product", "").lower()
#             version = port_data.get("version", "")
#             # Additional debug logging for each port scanned.
#             logger.debug("Host %s, Port %s - service: %s, product: %s, version: %s", host, port, service, product, version)
#             vuln_msg = None
#
#             # Enhanced check: old HTTP server severity using numeric comparison.
#             if service == 'http' and ("apache" in product or "nginx" in product):
#                 try:
#                     version_float = float(version)
#                     if version_float < 2.0:
#                         vuln_msg = f"Host {host}: Port {port} running outdated {product} (version {version})."
#                 except ValueError:
#                     # Fallback check if version is not convertible.
#                     if '1.0' in version:
#                         vuln_msg = f"Host {host}: Port {port} running outdated {product} (version {version})."
#
#             # FTP might be misconfigured.
#             if service == 'ftp':
#                 vuln_msg = f"Host {host}: Port {port} running FTP service which may be vulnerable to anonymous access."
#
#             # Commonly vulnerable service like telnet.
#             if service == 'telnet':
#                 vuln_msg = f"Host {host}: Port {port} running Telnet service which is considered insecure."
#
#             if vuln_msg:
#                 vulnerabilities.append(vuln_msg)
#                 logger.warning(vuln_msg)
#             else:
#                 logger.debug("No vulnerability found for host %s, port %s", host, port)
#
#         # Check for OS vulnerabilities.
#         os_info = result.get("os", {})
#         if os_info:
#             os_name = os_info.get("name", "").lower()
#             logger.debug("Host %s OS information: %s", host, os_name)
#             # Example: flagging if OS is an outdated version of Windows or Linux.
#             if "windows xp" in os_name or "ubuntu 10.04" in os_name:
#                 vuln_msg = f"Host {host}: Detected outdated operating system ({os_name})."
#                 vulnerabilities.append(vuln_msg)
#                 logger.warning(vuln_msg)
#             else:
#                 logger.debug("OS not flagged as vulnerable for host %s", host)
#         else:
#             logger.debug("No OS info available for host %s", host)
#
#         # Evaluate nmap script scan results for potential issues.
#         script_results = result.get("nmap_scripts", {})
#         if script_results:
#             for script, output in script_results.items():
#                 logger.debug("Host %s, Script %s output: %s", host, script, output)
#                 if "vuln" in output.lower() or "outdated" in output.lower():
#                     vuln_msg = f"Host {host}: Nmap script {script} indicates a potential vulnerability: {output}"
#                     vulnerabilities.append(vuln_msg)
#                     logger.warning(vuln_msg)
#                 else:
#                     logger.debug("Script %s output not flagged as vulnerable for host %s", script, host)
#         else:
#             logger.debug("No script results available for host %s", host)
#
#     return vulnerabilities

# import nmap
# import logging
#
# # Configure logging for the network_scanner module
# logger = logging.getLogger("network_scanner")
# logger.setLevel(logging.DEBUG)
# console_handler = logging.StreamHandler()
# formatter = logging.Formatter('%(asctime)s - network_scanner - %(levelname)s - %(message)s')
# console_handler.setFormatter(formatter)
# logger.addHandler(console_handler)
#
#
# def scan_host(host):
#     """
#     Perform an advanced port scan on the given host using Nmap.
#     This scan includes:
#       - Port scan on ports 1-65535 (expanded from 1-1024)
#       - Service and version detection (-sV)
#       - OS detection (-O)
#       - Default script scanning (-sC)
#
#     Returns a dictionary containing scan results including OS details.
#     """
#     logger.info("Starting advanced scan on %s", host)
#     scanner = nmap.PortScanner()
#     try:
#         # Perform an advanced scan with OS detection and default scripts.
#         scanner.scan(host, '1-65535', arguments='-sV -O -sC')
#         scan_data = {}
#         for scanned_host in scanner.all_hosts():
#             host_data = scanner[scanned_host]
#             # Log the raw scan data to help with debugging.
#             logger.debug("Raw scan data for host %s: %s", scanned_host, host_data)
#             # Extract OS detection info if available.
#             os_matches = host_data.get('osmatch', [])
#             os_details = os_matches[0] if os_matches else {}
#             scan_data[scanned_host] = {
#                 "addresses": host_data.get("addresses", {}),
#                 "hostnames": host_data.get("hostnames", []),
#                 "ports": host_data.get("tcp", {}),
#                 "os": os_details,
#                 "nmap_scripts": host_data.get("script", {})
#             }
#             logger.debug("Parsed scan results for host %s: %s", scanned_host, scan_data[scanned_host])
#         logger.info("Completed advanced port scanning")
#         return scan_data
#     except Exception as e:
#         logger.error("Error during advanced scanning: %s", e)
#         return None
#
#
# def check_common_vulnerabilities(scan_data):
#     """
#     An enhanced function to check for common vulnerabilities using
#     results from the advanced network scan. This includes checks based on:
#       - Known vulnerable open ports and services.
#       - OS vulnerabilities based on detection.
#       - Script scan results suggesting outdated software.
#
#     Returns a list of messages regarding potential vulnerabilities.
#     """
#     vulnerabilities = []
#     if not scan_data:
#         logger.debug("No scan data available to check vulnerabilities.")
#         return vulnerabilities
#     for host, result in scan_data.items():
#         # Check open ports vulnerabilities.
#         tcp_ports = result.get("ports", {})
#         for port, port_data in tcp_ports.items():
#             service = port_data.get("name", "").lower()
#             product = port_data.get("product", "").lower()
#             version = port_data.get("version", "")
#             # Debug logging for port details.
#             logger.debug("Host %s, Port %s - service: '%s', product: '%s', version: '%s'",
#                          host, port, service, product, version)
#             vuln_msg = None
#
#             # Enhanced check: old HTTP server severity using numeric comparison.
#             if service == 'http' and ("apache" in product or "nginx" in product):
#                 try:
#                     # Some version strings may have extra characters, so filter numeric parts.
#                     version_numeric = ''.join([ch for ch in version if ch.isdigit() or ch == '.'])
#                     version_float = float(version_numeric) if version_numeric else 0.0
#                     if version_float and version_float < 2.0:
#                         vuln_msg = f"Host {host}: Port {port} running outdated {product} (version {version})."
#                 except ValueError:
#                     # Fallback check if version is not convertible.
#                     if '1.0' in version:
#                         vuln_msg = f"Host {host}: Port {port} running outdated {product} (version {version})."
#
#             # FTP might be misconfigured.
#             if service == 'ftp':
#                 vuln_msg = f"Host {host}: Port {port} running FTP service which may be vulnerable to anonymous access."
#
#             # Commonly vulnerable service like telnet.
#             if service == 'telnet':
#                 vuln_msg = f"Host {host}: Port {port} running Telnet service which is considered insecure."
#
#             if vuln_msg:
#                 vulnerabilities.append(vuln_msg)
#                 logger.warning(vuln_msg)
#             else:
#                 logger.debug("No vulnerability condition met for host %s, port %s", host, port)
#
#         # Check for OS vulnerabilities.
#         os_info = result.get("os", {})
#         if os_info:
#             os_name = os_info.get("name", "").lower()
#             logger.debug("Host %s OS information: '%s'", host, os_name)
#             # Example: flagging if OS is an outdated version of Windows or Linux.
#             if "windows xp" in os_name or "ubuntu 10.04" in os_name:
#                 vuln_msg = f"Host {host}: Detected outdated operating system ({os_name})."
#                 vulnerabilities.append(vuln_msg)
#                 logger.warning(vuln_msg)
#             else:
#                 logger.debug("OS not flagged as vulnerable for host %s", host)
#         else:
#             logger.debug("No OS info available for host %s", host)
#
#         # Evaluate nmap script scan results for potential issues.
#         script_results = result.get("nmap_scripts", {})
#         if script_results:
#             for script, output in script_results.items():
#                 logger.debug("Host %s, Script '%s' output: '%s'", host, script, output)
#                 if output and ("vuln" in output.lower() or "outdated" in output.lower()):
#                     vuln_msg = f"Host {host}: Nmap script {script} indicates a potential vulnerability: {output}"
#                     vulnerabilities.append(vuln_msg)
#                     logger.warning(vuln_msg)
#                 else:
#                     logger.debug("Script '%s' output not flagged as vulnerable for host %s", script, host)
#         else:
#             logger.debug("No script results available for host %s", host)
#
#     return vulnerabilities
