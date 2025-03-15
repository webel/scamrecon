"""
Core domain investigation functionality for gathering information about domains.
"""

import json
import re
import socket
import ssl
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Union

import dns.resolver
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from scamrecon.utils.config import APIKeys, Config
from scamrecon.utils.console import log, print_header
from scamrecon.utils.helpers import (
    extract_ips_from_text,
    is_cloudflare_ip,
    is_valid_domain,
    normalize_domain,
    resolve_domain,
)

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class DomainInvestigator:
    """
    Investigates domains for security information, origin servers, and more.
    """

    def __init__(
        self,
        domain: str,
        config: Optional[Config] = None,
        output_file: Optional[str] = None,
    ):
        """
        Initialize the Domain Investigator.

        Args:
            domain: The domain to investigate
            config: Configuration object with API keys and settings
            output_file: File to save results to
        """
        self.domain = normalize_domain(domain)
        self.config = config or Config.load_default()
        self.output_file = output_file

        # User agents for requests
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
        ]

        # Create a resolver with custom settings
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.config.timeout
        self.resolver.lifetime = self.config.timeout

        # Set of potential origin IPs
        self.potential_origin_ips = set()

        # Results storage
        self.results = {
            "domain": self.domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "is_cloudflare_protected": False,
            "main_ip_addresses": [],
            "cloudflare_status": {},
            "origin_candidates": [],
            "confirmed_origins": [],
            "subdomains": [],
            "dns_records": {},
            "ssl_info": {},
            "security_issues": [],
            "malware_detections": {},
            "technology_stack": [],
            "historical_ips": [],
            "whois_info": {},
            "http_headers": {},
            "nameservers": [],
        }

    def check_main_domain(self) -> bool:
        """Check the main domain's IP addresses and detect Cloudflare"""
        print_header(f"MAIN DOMAIN CHECK: {self.domain}")

        if not is_valid_domain(self.domain):
            log(f"Invalid domain format: {self.domain}", "error")
            return False

        ips = resolve_domain(self.domain, timeout=self.config.timeout)
        if not ips:
            log(f"Could not resolve {self.domain}", "error")
            return False

        self.results["main_ip_addresses"] = ips

        log(f"IP addresses for {self.domain}:")
        cloudflare_protected = False

        for ip in ips:
            is_cf = is_cloudflare_ip(ip)
            self.results["cloudflare_status"][ip] = is_cf

            cf_status = "Cloudflare" if is_cf else "Non-Cloudflare"
            log(f"  {ip} ({cf_status})")

            if is_cf:
                cloudflare_protected = True

        self.results["is_cloudflare_protected"] = cloudflare_protected

        if cloudflare_protected:
            log(f"Domain {self.domain} is behind Cloudflare", "success")
        else:
            log(
                f"Domain {self.domain} does not appear to be behind Cloudflare",
                "warning",
            )
            log("These might be the actual origin IPs", "info")

        return cloudflare_protected

    def check_all_dns_records(self) -> None:
        """Check various DNS record types for information leakage"""
        print_header(f"DNS RECORDS CHECK")

        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV"]
        self.results["dns_records"] = {}

        for record_type in record_types:
            try:
                records = resolve_domain(self.domain, record_type, self.config.timeout)

                if records:
                    self.results["dns_records"][record_type] = records
                    log(f"{record_type} records:")

                    for record in records:
                        log(f"  {record}")

                        # For MX records, extract the mail server domain and resolve it
                        if record_type == "MX" and " " in record:
                            mx_domain = record.split(" ")[1].rstrip(".")
                            log(f"  Checking mail server: {mx_domain}")

                            mx_ips = resolve_domain(
                                mx_domain, timeout=self.config.timeout
                            )
                            mx_data = {"domain": mx_domain, "ips": []}

                            for ip in mx_ips:
                                is_cf = is_cloudflare_ip(ip)
                                status = "Cloudflare" if is_cf else "Non-Cloudflare"
                                log(f"    IP: {ip} ({status})")

                                mx_data["ips"].append(
                                    {"ip": ip, "is_cloudflare": is_cf}
                                )

                                if not is_cf:
                                    self.potential_origin_ips.add(ip)
                                    self.results["origin_candidates"].append(
                                        {
                                            "ip": ip,
                                            "source": f"Mail server ({mx_domain})",
                                            "confidence": "Medium",
                                        }
                                    )

                            if "mail_servers" not in self.results:
                                self.results["mail_servers"] = []

                            self.results["mail_servers"].append(mx_data)

                        # For NS records, store nameservers
                        if record_type == "NS":
                            if record not in self.results["nameservers"]:
                                self.results["nameservers"].append(record)

            except Exception as e:
                log(f"Error checking {record_type} records: {str(e)}", "error")

    def check_security_trails_data(self) -> None:
        """Check SecurityTrails API for historical DNS data"""
        print_header("SECURITY TRAILS HISTORICAL DATA")

        api_key = self.config.api_keys.securitytrails
        if not api_key:
            log("SecurityTrails API key not provided", "warning")
            return

        try:
            url = f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a"
            headers = {
                "APIKEY": api_key,
                "Accept": "application/json",
            }

            response = requests.get(url, headers=headers, timeout=self.config.timeout)

            if response.status_code == 200:
                data = response.json()
                records = data.get("records", [])

                if records:
                    log(f"Found {len(records)} historical DNS records", "success")

                    for record in records[:10]:  # Limit to 10 most recent records
                        first_seen = record.get("first_seen", "Unknown")
                        last_seen = record.get("last_seen", "Unknown")

                        for value in record.get("values", []):
                            ip = value.get("ip", "")
                            if ip:
                                is_cf = is_cloudflare_ip(ip)
                                status = "Cloudflare" if is_cf else "Non-Cloudflare"

                                log(
                                    f"IP: {ip} ({status}) - First seen: {first_seen}, Last seen: {last_seen}"
                                )

                                self.results["historical_ips"].append(
                                    {
                                        "ip": ip,
                                        "first_seen": first_seen,
                                        "last_seen": last_seen,
                                        "is_cloudflare": is_cf,
                                    }
                                )

                                if not is_cf:
                                    self.potential_origin_ips.add(ip)
                                    self.results["origin_candidates"].append(
                                        {
                                            "ip": ip,
                                            "source": "Historical DNS",
                                            "confidence": "High",
                                            "first_seen": first_seen,
                                            "last_seen": last_seen,
                                        }
                                    )
                else:
                    log("No historical DNS records found", "warning")

            elif response.status_code == 401:
                log("SecurityTrails API key is invalid", "error")
            elif response.status_code == 429:
                log("SecurityTrails API rate limit exceeded", "error")
            else:
                log(f"SecurityTrails API error: {response.status_code}", "error")

        except Exception as e:
            log(f"Error checking SecurityTrails data: {str(e)}", "error")

    def check_common_subdomains(self) -> None:
        """Check common subdomains that might bypass Cloudflare"""
        print_header("SUBDOMAIN CHECK")

        # Common subdomains to check
        subdomains = [
            "www",
            "mail",
            "email",
            "webmail",
            "cpanel",
            "whm",
            "ftp",
            "direct",
            "api",
            "dev",
            "staging",
            "stage",
            "app",
            "admin",
            "portal",
            "server",
            "host",
            "smtp",
            "blog",
            "forum",
            "status",
            "secure",
            "origin",
        ]

        log(f"Checking {len(subdomains)} common subdomains...")
        active_subdomains = []

        for subdomain in subdomains:
            result = self.check_subdomain(subdomain)
            if result:
                active_subdomains.append(result)

        if active_subdomains:
            log(f"Found {len(active_subdomains)} active subdomains", "success")
            for subdomain_data in active_subdomains:
                self.results["subdomains"].append(subdomain_data)
        else:
            log("No active subdomains found", "warning")

    def check_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Check a single subdomain and return information if it exists"""
        full_domain = f"{subdomain}.{self.domain}"

        try:
            ips = resolve_domain(full_domain, timeout=self.config.timeout)
            if ips:
                log(f"Found subdomain: {full_domain}", "debug")

                subdomain_data = {"name": full_domain, "ips": []}

                for ip in ips:
                    is_cf = is_cloudflare_ip(ip)
                    status = "Cloudflare" if is_cf else "Non-Cloudflare"
                    log(f"  {ip} ({status})", "debug")

                    subdomain_data["ips"].append({"ip": ip, "is_cloudflare": is_cf})

                    if not is_cf:
                        self.potential_origin_ips.add(ip)
                        self.results["origin_candidates"].append(
                            {
                                "ip": ip,
                                "source": f"Subdomain ({full_domain})",
                                "confidence": "High",
                            }
                        )

                return subdomain_data
        except Exception:
            pass

        return None

    def check_ssl_certificate(self) -> None:
        """Check SSL certificate for alternative names that might reveal true origin"""
        print_header("SSL CERTIFICATE CHECK")

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)

            # Try to connect to the domain
            try:
                sock.connect((self.domain, 443))
            except socket.gaierror:
                # If domain doesn't resolve directly, use the resolved IP
                ips = resolve_domain(self.domain, timeout=self.config.timeout)
                if ips:
                    sock.connect((ips[0], 443))
                else:
                    log(
                        "Could not establish SSL connection - domain doesn't resolve",
                        "error",
                    )
                    return

            # Wrap the socket in SSL
            ssl_sock = context.wrap_socket(sock, server_hostname=self.domain)

            # Get the certificate
            cert = ssl_sock.getpeercert(binary_form=False)
            if not cert:
                log("Could not retrieve certificate information", "error")
                ssl_sock.close()
                return

            # Extract certificate information
            issuer_cn = None
            for issuer_entry in cert.get("issuer", []):
                for attr in issuer_entry:
                    if len(attr) == 2 and attr[0] == "commonName":
                        issuer_cn = attr[1]
                        break

            subject_cn = None
            for subject_entry in cert.get("subject", []):
                for attr in subject_entry:
                    if len(attr) == 2 and attr[0] == "commonName":
                        subject_cn = attr[1]
                        break

            not_before = cert.get("notBefore", "Unknown")
            not_after = cert.get("notAfter", "Unknown")

            log("Certificate details:")
            log(f"  Issued to: {subject_cn or 'Unknown'}")
            log(f"  Issued by: {issuer_cn or 'Unknown'}")
            log(f"  Valid until: {not_after}")

            # Store in results
            self.results["ssl_info"] = {
                "issuer": issuer_cn,
                "subject": subject_cn,
                "valid_from": not_before,
                "valid_until": not_after,
                "alternative_names": [],
            }

            # Check if it's a Cloudflare certificate
            is_cloudflare_cert = issuer_cn and "cloudflare" in issuer_cn.lower()
            self.results["ssl_info"]["is_cloudflare_cert"] = is_cloudflare_cert

            if is_cloudflare_cert:
                log("This is a Cloudflare-issued certificate", "info")

            # Alternative names can reveal true origin server domains
            alt_names = []
            san = cert.get("subjectAltName", [])
            for type_name, name in san:
                if type_name == "DNS":
                    alt_names.append(name)

            if alt_names:
                log("\nAlternative names in certificate:")
                for name in alt_names:
                    log(f"  {name}")
                    self.results["ssl_info"]["alternative_names"].append(name)

                    # Skip the main domain, wildcard versions, and Cloudflare certs
                    if (
                        name != self.domain
                        and not name.startswith("*.")
                        and "cloudflare" not in name.lower()
                        and "sectigo" not in name.lower()
                        and "digicert" not in name.lower()
                    ):

                        log(f"  Checking possible origin: {name}")
                        try:
                            name_ips = resolve_domain(name, timeout=self.config.timeout)
                            for ip in name_ips:
                                is_cf = is_cloudflare_ip(ip)
                                status = "Cloudflare" if is_cf else "Non-Cloudflare"
                                log(f"    {ip} ({status})")

                                if not is_cf:
                                    self.potential_origin_ips.add(ip)
                                    self.results["origin_candidates"].append(
                                        {
                                            "ip": ip,
                                            "source": f"SSL Alt Name ({name})",
                                            "confidence": "Medium",
                                        }
                                    )
                        except Exception:
                            log(f"    Could not resolve {name}")

            ssl_sock.close()

        except ssl.SSLError as e:
            log(f"SSL Error: {str(e)}", "error")
            self.results["security_issues"].append(
                {"issue": "SSL Error", "details": str(e), "severity": "High"}
            )
        except Exception as e:
            log(f"Error checking SSL certificate: {str(e)}", "error")

    def check_http_headers(self) -> None:
        """Check HTTP headers for information disclosure"""
        print_header("HTTP HEADERS CHECK")

        self.results["http_headers"] = {}
        protocols = ["https", "http"]

        for protocol in protocols:
            url = f"{protocol}://{self.domain}"
            log(f"Checking {protocol.upper()} headers:", "info")

            try:
                headers = {
                    "User-Agent": self.user_agents[0],
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                }

                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.config.timeout,
                    allow_redirects=False,
                    verify=False,  # Bypass SSL verification for potentially invalid certs
                )

                # Interesting headers that might reveal server info
                interesting_headers = {
                    "Server",
                    "X-Powered-By",
                    "X-Generator",
                    "X-Server",
                    "X-Hosted-By",
                    "X-AspNet-Version",
                    "X-Runtime",
                    "Via",
                    "X-Origin",
                    "X-Backend",
                    "X-Cache-Backend",
                    "X-Application-Server",
                }

                log(f"  Status code: {response.status_code}")
                self.results["http_headers"][protocol] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "interesting_headers": {},
                }

                revealed_headers = []

                for header, value in response.headers.items():
                    log(f"  {header}: {value}")

                    if header.lower() in [h.lower() for h in interesting_headers]:
                        revealed_headers.append(f"{header}: {value}")
                        self.results["http_headers"][protocol]["interesting_headers"][
                            header
                        ] = value

                        # Check for IP addresses in headers
                        ip_matches = extract_ips_from_text(value)
                        for ip in ip_matches:
                            if not is_cloudflare_ip(ip):
                                self.potential_origin_ips.add(ip)
                                self.results["origin_candidates"].append(
                                    {
                                        "ip": ip,
                                        "source": f"HTTP Header ({header})",
                                        "confidence": "Medium",
                                    }
                                )

                if revealed_headers:
                    log("\nPotentially revealing headers found:", "warning")
                    for header in revealed_headers:
                        log(f"  {header}")
                else:
                    log("\nNo revealing headers found", "info")

                # If this isn't a Cloudflare-protected page, the IP might be the origin
                if "CF-RAY" not in response.headers and "Server" in response.headers:
                    server = response.headers["Server"]
                    if "cloudflare" not in server.lower():
                        log(
                            f"\nNon-Cloudflare server header detected: {server}",
                            "warning",
                        )
                        # Extract IP from the domain
                        try:
                            ip = socket.gethostbyname(self.domain)
                            if not is_cloudflare_ip(ip):
                                self.potential_origin_ips.add(ip)
                                self.results["origin_candidates"].append(
                                    {
                                        "ip": ip,
                                        "source": f"Direct connection, Server: {server}",
                                        "confidence": "High",
                                    }
                                )
                        except Exception:
                            pass

            except requests.exceptions.RequestException as e:
                log(f"Error making {protocol} request: {str(e)}", "error")
            except Exception as e:
                log(f"Error checking HTTP headers: {str(e)}", "error")

    def check_website_source(self) -> None:
        """Check website source code for origin clues"""
        print_header("WEBSITE SOURCE CHECK")

        url = f"https://{self.domain}"

        try:
            headers = {"User-Agent": self.user_agents[0]}

            response = requests.get(
                url, headers=headers, timeout=self.config.timeout, verify=False
            )

            # Look for IP addresses in page source
            ip_matches = extract_ips_from_text(response.text)

            if ip_matches:
                log("IP addresses found in website source:", "warning")
                for ip in ip_matches:
                    is_cf = is_cloudflare_ip(ip)
                    status = "Cloudflare" if is_cf else "Non-Cloudflare"
                    log(f"  {ip} ({status})")

                    if not is_cf:
                        self.potential_origin_ips.add(ip)
                        self.results["origin_candidates"].append(
                            {
                                "ip": ip,
                                "source": "Website source",
                                "confidence": "Medium",
                            }
                        )
            else:
                log("No IP addresses found in website source", "info")

            # Look for domains/subdomains in page source
            domain_pattern = r"(?:https?:\/\/)?(?:[\w-]+\.)+[a-zA-Z]{2,}(?:\/\S*)?"
            domain_matches = re.findall(domain_pattern, response.text)

            domains_to_check = set()
            main_domain_parts = self.domain.split(".")
            main_domain_suffix = ".".join(main_domain_parts[-2:])  # e.g., example.com

            for d in domain_matches:
                # Clean up the domain
                d = d.lower().strip("/\"'")
                if d.startswith("http"):
                    parsed = urlparse(d)
                    d = parsed.netloc

                # Only consider subdomains of the main domain, but not the main domain itself
                if main_domain_suffix in d and d != self.domain:
                    domains_to_check.add(d)

            if domains_to_check:
                log("\nDomains/subdomains found in website source:", "info")
                for d in domains_to_check:
                    log(f"  Checking: {d}")
                    ips = resolve_domain(d, timeout=self.config.timeout)
                    if ips:
                        for ip in ips:
                            is_cf = is_cloudflare_ip(ip)
                            status = "Cloudflare" if is_cf else "Non-Cloudflare"
                            log(f"    {ip} ({status})")

                            if not is_cf:
                                self.potential_origin_ips.add(ip)
                                self.results["origin_candidates"].append(
                                    {
                                        "ip": ip,
                                        "source": f"Related domain ({d})",
                                        "confidence": "Medium",
                                    }
                                )

            # Technology fingerprinting
            tech_patterns = {
                "WordPress": r"wp-content|wp-includes|wordpress",
                "Joomla": r"joomla|com_content|com_contact",
                "Drupal": r"drupal|sites/default|sites/all",
                "Magento": r"magento|skin/frontend|js/varien",
                "Shopify": r"cdn.shopify.com|myshopify.com",
                "WooCommerce": r"woocommerce|wc-api",
                "Laravel": r"laravel|livewire",
                "React": r"react|reactjs",
                "Angular": r"angular|ng\-",
                "Vue.js": r"vue|vuejs|vue-router",
                "jQuery": r"jquery",
                "Bootstrap": r"bootstrap",
                "Cloudflare": r"cloudflare|__cf",
            }

            log("\nTechnology fingerprinting:", "info")
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, response.text, re.IGNORECASE):
                    log(f"  ✓ {tech} detected")
                    self.results["technology_stack"].append(tech)
                else:
                    log(f"  ✗ {tech} not detected", "debug")

        except requests.exceptions.RequestException as e:
            log(f"Error fetching website source: {str(e)}", "error")
        except Exception as e:
            log(f"Error analyzing website source: {str(e)}", "error")

    def check_virustotal(self, target: str, is_ip: bool = False) -> None:
        """Check VirusTotal for domain or IP information and malware reports"""
        print_header(f"VIRUSTOTAL SECURITY CHECK: {target}")

        api_key = self.config.api_keys.virustotal
        if not api_key:
            log("VirusTotal API key not provided", "warning")
            return

        try:
            # VirusTotal API v3
            base_url = "https://www.virustotal.com/api/v3/"
            endpoint = f"ip_addresses/{target}" if is_ip else f"domains/{target}"

            headers = {"x-apikey": api_key}

            response = requests.get(
                base_url + endpoint, headers=headers, timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                # Basic information
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)

                # Malicious detections
                malicious = last_analysis_stats.get("malicious", 0)
                suspicious = last_analysis_stats.get("suspicious", 0)
                total_engines = (
                    sum(last_analysis_stats.values()) if last_analysis_stats else 0
                )

                # Last analysis date
                last_analysis_date = attributes.get("last_analysis_date", 0)
                last_analysis_date_str = (
                    datetime.fromtimestamp(last_analysis_date).strftime("%Y-%m-%d")
                    if last_analysis_date
                    else "Unknown"
                )

                log(f"VirusTotal results for {target}:", "info")
                log(f"  Last scanned: {last_analysis_date_str}")
                log(f"  Detection ratio: {malicious + suspicious}/{total_engines}")
                log(f"  Reputation score: {reputation}")

                if malicious > 0 or suspicious > 0:
                    detection_percentage = (
                        ((malicious + suspicious) / total_engines) * 100
                        if total_engines > 0
                        else 0
                    )
                    severity = (
                        "Low"
                        if detection_percentage < 5
                        else "Medium" if detection_percentage < 15 else "High"
                    )

                    log(f"  Malicious detections: {malicious}", "error")
                    log(f"  Suspicious detections: {suspicious}", "warning")

                    self.results["security_issues"].append(
                        {
                            "issue": f"Malware detected ({target})",
                            "details": f"{malicious} malicious, {suspicious} suspicious detections",
                            "severity": severity,
                            "source": "VirusTotal",
                        }
                    )

                    self.results["malware_detections"][target] = {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "total_engines": total_engines,
                        "last_scanned": last_analysis_date_str,
                        "detection_percentage": detection_percentage,
                        "severity": severity,
                    }
                else:
                    log("  No malicious detections", "success")

            elif response.status_code == 401:
                log("VirusTotal API key is invalid", "error")
            elif response.status_code == 429:
                log("VirusTotal API rate limit exceeded", "error")
            else:
                log(f"VirusTotal API error: {response.status_code}", "error")

        except Exception as e:
            log(f"Error checking VirusTotal: {str(e)}", "error")

    def check_abuseipdb(self, ip: str) -> None:
        """Check IP against AbuseIPDB for reputation information"""
        api_key = self.config.api_keys.abuseipdb
        if not api_key:
            log("AbuseIPDB API key not provided", "debug")
            return

        try:
            url = "https://api.abuseipdb.com/api/v2/check"

            querystring = {"ipAddress": ip, "maxAgeInDays": "90"}

            headers = {"Key": api_key, "Accept": "application/json"}

            response = requests.get(
                url, headers=headers, params=querystring, timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)

                severity = (
                    "Low"
                    if abuse_score < 25
                    else "Medium" if abuse_score < 75 else "High"
                )
                status = "Clean" if abuse_score < 5 else "Suspicious"

                log(f"AbuseIPDB score for {ip}: {abuse_score}% ({status})", "debug")

                if abuse_score >= 25:
                    self.results["security_issues"].append(
                        {
                            "issue": f"Suspicious IP detected ({ip})",
                            "details": f"AbuseIPDB confidence score: {abuse_score}%",
                            "severity": severity,
                            "source": "AbuseIPDB",
                        }
                    )

        except Exception as e:
            log(f"Error checking AbuseIPDB: {str(e)}", "debug")

    def check_urlscan(self) -> None:
        """Check domain on urlscan.io for recent scans and security issues"""
        print_header(f"URLSCAN.IO CHECK: {self.domain}")

        api_key = self.config.api_keys.urlscan
        if not api_key:
            # Try without API key (limited results)
            api_key = ""

        try:
            # First check for existing scans
            search_url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"

            headers = {}
            if api_key:
                headers["API-Key"] = api_key

            response = requests.get(
                search_url, headers=headers, timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])

                if results:
                    log(f"Found {len(results)} recent scans on urlscan.io", "success")

                    # Get the most recent result
                    latest_result = results[0]
                    scan_id = latest_result.get("_id")
                    result_url = latest_result.get("result")
                    task_url = latest_result.get("task", {}).get("url")

                    log(f"Most recent scan: {result_url}")

                    # Get details of the most recent scan
                    if scan_id:
                        detail_url = f"https://urlscan.io/api/v1/result/{scan_id}"
                        detail_response = requests.get(
                            detail_url, headers=headers, timeout=self.config.timeout
                        )

                        if detail_response.status_code == 200:
                            detail_data = detail_response.json()

                            # Extract useful information
                            page = detail_data.get("page", {})
                            ip = page.get("ip")
                            server = page.get("server")
                            country = page.get("country")
                            asn = page.get("asn")
                            asnname = page.get("asnname")

                            log(f"  Scanned URL: {task_url}")
                            log(f"  Server IP: {ip}")
                            log(f"  Server: {server}")
                            log(f"  Country: {country}")
                            log(f"  ASN: {asn} ({asnname})")

                            # Check for malicious indicators
                            verdicts = detail_data.get("verdicts", {})
                            overall = verdicts.get("overall", {})
                            malicious = overall.get("malicious", False)

                            if malicious:
                                score = overall.get("score", 0)
                                categories = overall.get("categories", [])

                                log(f"  Malicious: Yes (Score: {score})", "error")
                                log(f"  Categories: {', '.join(categories)}")

                                self.results["security_issues"].append(
                                    {
                                        "issue": "Malicious website detected",
                                        "details": f"urlscan.io verdict: {', '.join(categories)}",
                                        "severity": "High",
                                        "source": "urlscan.io",
                                    }
                                )
                            else:
                                log("  Malicious: No", "success")

                            # Check IP information
                            if ip and not is_cloudflare_ip(ip):
                                self.potential_origin_ips.add(ip)
                                self.results["origin_candidates"].append(
                                    {
                                        "ip": ip,
                                        "source": "urlscan.io scan",
                                        "confidence": "Medium",
                                        "server": server,
                                    }
                                )
                else:
                    log("No existing scans found on urlscan.io", "info")

                    # If API key is provided, submit a new scan
                    if api_key:
                        log("Submitting a new scan...", "info")

                        submit_url = "https://urlscan.io/api/v1/scan/"
                        headers = {
                            "API-Key": api_key,
                            "Content-Type": "application/json",
                        }
                        payload = {
                            "url": f"https://{self.domain}",
                            "visibility": "public",
                        }

                        submit_response = requests.post(
                            submit_url,
                            headers=headers,
                            json=payload,
                            timeout=self.config.timeout,
                        )

                        if submit_response.status_code == 200:
                            submit_data = submit_response.json()
                            scan_id = submit_data.get("uuid")
                            result_url = submit_data.get("result")

                            log(f"Scan submitted successfully: {result_url}", "success")
                            log("Results will be available in a few minutes", "info")

                            self.results["urlscan"] = {
                                "scan_id": scan_id,
                                "result_url": result_url,
                            }
                        else:
                            log(
                                f"Error submitting scan: {submit_response.status_code}",
                                "error",
                            )

            elif response.status_code == 401:
                log("urlscan.io API key is invalid", "error")
            else:
                log(f"urlscan.io API error: {response.status_code}", "error")

        except Exception as e:
            log(f"Error checking urlscan.io: {str(e)}", "error")

    def verify_origin_ip(self, ip: str) -> Dict:
        """Verify if an IP is likely the origin server by directly connecting to it"""
        log(f"\nVerifying potential origin IP: {ip}")

        is_origin = False
        verification_data = {
            "ip": ip,
            "http_connection": False,
            "https_connection": False,
            "server_header": None,
            "response_similarity": 0,
            "is_origin": False,
        }

        # Try HTTP connection with Host header
        try:
            headers = {
                "User-Agent": self.user_agents[0],
                "Host": self.domain,  # Important - tells the server which site we want
                "Accept": "text/html,application/xhtml+xml",
            }

            log("  Attempting HTTP connection with Host header...")
            response = requests.get(
                f"http://{ip}", headers=headers, timeout=5, verify=False
            )

            log(f"  Response status code: {response.status_code}")
            verification_data["http_connection"] = True
            verification_data["http_status"] = response.status_code

            if "Server" in response.headers:
                server = response.headers["Server"]
                log(f"  Server header: {server}")
                verification_data["server_header"] = server

            if 200 <= response.status_code < 400:
                log("  ✓ Successfully connected with Host header")
                log("  ✓ Response looks valid")
                is_origin = True

                # Compare with the actual website content to verify
                try:
                    real_response = requests.get(
                        f"https://{self.domain}",
                        headers={"User-Agent": self.user_agents[0]},
                        timeout=5,
                        verify=False,
                    )

                    # Basic content similarity check
                    direct_content = response.text
                    real_content = real_response.text

                    # Calculate a very basic similarity score
                    similarity = self.calculate_content_similarity(
                        direct_content, real_content
                    )
                    log(f"  Content similarity: {similarity:.2f}%")
                    verification_data["response_similarity"] = similarity

                    if similarity < 30:
                        log(
                            "  ✗ Content differs significantly from the actual website",
                            "warning",
                        )
                        is_origin = False if similarity < 10 else is_origin
                    else:
                        log("  ✓ Content is similar to the actual website", "success")
                        is_origin = True
                except Exception as e:
                    log(f"  Could not compare with actual website: {str(e)}", "warning")
            else:
                log("  ✗ Received error status code")
        except Exception as e:
            log(f"  ✗ HTTP connection failed: {str(e)}")

        # Try HTTPS connection if HTTP failed
        if not is_origin:
            try:
                log("  Attempting HTTPS connection with SNI...")
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(5)
                conn.connect((ip, 443))

                ssl_conn = context.wrap_socket(conn, server_hostname=self.domain)
                ssl_conn.close()

                log("  ✓ Successfully established SSL connection")
                is_origin = True
                verification_data["https_connection"] = True
            except Exception as e:
                log(f"  ✗ HTTPS connection failed: {str(e)}")

        # Return verdict
        verification_data["is_origin"] = is_origin

        if is_origin:
            log("  VERDICT: This is likely the origin server", "success")
        else:
            log("  VERDICT: Could not confirm as origin server", "warning")

        return verification_data

    def calculate_content_similarity(self, content1: str, content2: str) -> float:
        """Calculate a basic similarity score between two HTML contents"""
        # Strip HTML tags for a more meaningful comparison
        tag_pattern = re.compile(r"<.*?>")
        content1_text = re.sub(tag_pattern, "", content1).strip()
        content2_text = re.sub(tag_pattern, "", content2).strip()

        # Get a set of words from each content
        words1 = set(content1_text.lower().split())
        words2 = set(content2_text.lower().split())

        # Calculate Jaccard similarity
        if not words1 or not words2:
            return 0.0

        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))

        similarity = (intersection / union) * 100 if union > 0 else 0
        return similarity

    def check_malware_hosting(self, ip: str) -> None:
        """Check if the IP is known for hosting malware"""
        print_header(f"MALWARE HOSTING CHECK: {ip}")

        # Check with VirusTotal
        self.check_virustotal(ip, is_ip=True)

        # Check with AbuseIPDB
        self.check_abuseipdb(ip)

    def run_whois(self) -> None:
        """Run WHOIS lookup on the domain"""
        print_header(f"WHOIS INFORMATION: {self.domain}")

        try:
            # Use subprocess to run whois command with proper input validation and shell=False for security
            if not is_valid_domain(self.domain):
                log("Invalid domain format for WHOIS lookup", "error")
                return

            process = subprocess.Popen(
                ["whois", self.domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,  # Explicitly set shell=False for security
            )
            stdout, stderr = process.communicate(timeout=self.config.timeout)

            if stderr:
                error_msg = stderr.decode()
                if error_msg:
                    log(f"Error running WHOIS: {error_msg}", "error")
                    return

            whois_output = stdout.decode()

            # Extract important information
            registrar_pattern = re.compile(r"Registrar:?\s*(.+)", re.IGNORECASE)
            creation_date_pattern = re.compile(r"Creation Date:?\s*(.+)", re.IGNORECASE)
            updated_date_pattern = re.compile(r"Updated Date:?\s*(.+)", re.IGNORECASE)
            expiry_date_pattern = re.compile(
                r"Registry Expiry Date:?\s*(.+)", re.IGNORECASE
            )
            nameserver_pattern = re.compile(r"Name Server:?\s*(.+)", re.IGNORECASE)

            registrar_match = registrar_pattern.search(whois_output)
            creation_date_match = creation_date_pattern.search(whois_output)
            updated_date_match = updated_date_pattern.search(whois_output)
            expiry_date_match = expiry_date_pattern.search(whois_output)

            # Extract and store nameservers
            nameserver_matches = nameserver_pattern.findall(whois_output)
            nameservers = [ns.strip().lower() for ns in nameserver_matches]

            # Store extracted information
            self.results["whois_info"] = {
                "registrar": (
                    registrar_match.group(1).strip() if registrar_match else "Unknown"
                ),
                "creation_date": (
                    creation_date_match.group(1).strip()
                    if creation_date_match
                    else "Unknown"
                ),
                "updated_date": (
                    updated_date_match.group(1).strip()
                    if updated_date_match
                    else "Unknown"
                ),
                "expiry_date": (
                    expiry_date_match.group(1).strip()
                    if expiry_date_match
                    else "Unknown"
                ),
                "nameservers": nameservers,
            }

            # Log the extracted information
            log("WHOIS Information:")
            log(f"  Registrar: {self.results['whois_info']['registrar']}")
            log(f"  Creation Date: {self.results['whois_info']['creation_date']}")
            log(f"  Updated Date: {self.results['whois_info']['updated_date']}")
            log(f"  Expiry Date: {self.results['whois_info']['expiry_date']}")
            log(
                f"  Nameservers: {', '.join(nameservers) if nameservers else 'None found'}"
            )

            # Check for privacy protection
            privacy_keywords = ["privacy", "protect", "redact", "whoisguard"]
            has_privacy = any(
                keyword in whois_output.lower() for keyword in privacy_keywords
            )

            if has_privacy:
                log("  WHOIS Privacy Protection: Enabled", "info")
                self.results["whois_info"]["privacy_protection"] = True
            else:
                log("  WHOIS Privacy Protection: Not detected", "warning")
                self.results["whois_info"]["privacy_protection"] = False

            # Check for recent creation or updates (potential phishing indicator)
            if creation_date_match:
                try:
                    creation_date_str = creation_date_match.group(1).strip()
                    creation_date = None

                    # Handle common date formats
                    for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y"]:
                        try:
                            creation_date = datetime.strptime(creation_date_str, fmt)
                            break
                        except ValueError:
                            continue

                    if creation_date:
                        age_days = (datetime.now() - creation_date).days

                        if age_days < 30:
                            log(
                                f"  Domain is very new ({age_days} days old)", "warning"
                            )
                            self.results["security_issues"].append(
                                {
                                    "issue": "Very new domain",
                                    "details": f"Domain is only {age_days} days old",
                                    "severity": "Medium",
                                    "source": "WHOIS",
                                }
                            )
                except Exception as e:
                    log(f"Error parsing creation date: {str(e)}", "debug")

        except Exception as e:
            log(f"Error running WHOIS: {str(e)}", "error")

    def run_investigation(self) -> Dict:
        """Run the full domain investigation"""
        import time

        start_time = time.time()

        log(f"Starting investigation for: {self.domain}")

        # Check if the domain is properly formatted
        if not is_valid_domain(self.domain):
            log("Invalid domain format", "error")
            return self.results

        # Step 1: Check if domain is behind Cloudflare
        cloudflare_protected = self.check_main_domain()

        # Run WHOIS lookup
        self.run_whois()

        # URLScan.io check
        self.check_urlscan()

        # Step 2: If behind Cloudflare, try to find the origin
        if cloudflare_protected:
            # Check all DNS records
            self.check_all_dns_records()

            # Check for historical DNS data
            self.check_security_trails_data()

            # Check common subdomains
            self.check_common_subdomains()

            # Check SSL certificate
            self.check_ssl_certificate()

            # Check HTTP headers
            self.check_http_headers()

            # Check website source
            self.check_website_source()

            # Step 3: Verify potential origin IPs
            print_header("ORIGIN IP VERIFICATION")

            if self.potential_origin_ips:
                log(
                    f"Found {len(self.potential_origin_ips)} potential origin IPs to verify"
                )

                verified_origins = []

                for ip in self.potential_origin_ips:
                    verification_data = self.verify_origin_ip(ip)

                    if verification_data["is_origin"]:
                        verified_origins.append(
                            {"ip": ip, "verification_data": verification_data}
                        )

                        # Run additional security checks on confirmed origin IPs
                        if self.config.scan_malware:
                            self.check_malware_hosting(ip)

                # Store confirmed origins
                self.results["confirmed_origins"] = verified_origins

                # Final results
                print_header("INVESTIGATION RESULTS")

                if verified_origins:
                    log(
                        f"Found {len(verified_origins)} confirmed origin server IPs:",
                        "success",
                    )

                    for origin in verified_origins:
                        ip = origin["ip"]
                        server = origin["verification_data"].get(
                            "server_header", "Unknown"
                        )
                        log(f"  Origin IP: {ip}")
                        log(f"  Server: {server}")
                else:
                    log("Could not confirm any origin server IPs", "warning")
            else:
                log("No potential origin IPs found", "warning")
        else:
            # If not behind Cloudflare, the current IPs are the origin servers
            log(
                "Domain is not behind Cloudflare - current IPs are the origin servers",
                "info",
            )

            for ip in self.results["main_ip_addresses"]:
                self.results["confirmed_origins"].append(
                    {
                        "ip": ip,
                        "verification_data": {"is_origin": True, "confidence": "High"},
                    }
                )

                # Check for malware hosting on direct IPs
                if self.config.scan_malware:
                    self.check_malware_hosting(ip)

        # Summary of security issues
        if self.results["security_issues"]:
            print_header("SECURITY ISSUES SUMMARY")

            high_issues = [
                issue
                for issue in self.results["security_issues"]
                if issue["severity"] == "High"
            ]
            medium_issues = [
                issue
                for issue in self.results["security_issues"]
                if issue["severity"] == "Medium"
            ]
            low_issues = [
                issue
                for issue in self.results["security_issues"]
                if issue["severity"] == "Low"
            ]

            if high_issues:
                log(f"High Severity Issues: {len(high_issues)}", "error")
                for issue in high_issues:
                    log(f"  - {issue['issue']}: {issue['details']}")

            if medium_issues:
                log(f"Medium Severity Issues: {len(medium_issues)}", "warning")
                for issue in medium_issues:
                    log(f"  - {issue['issue']}: {issue['details']}")

            if low_issues:
                log(f"Low Severity Issues: {len(low_issues)}")
                for issue in low_issues:
                    log(f"  - {issue['issue']}: {issue['details']}")
        else:
            log("No security issues detected", "success")

        # Save results to file if requested
        if self.output_file:
            try:
                with open(self.output_file, "w") as f:
                    json.dump(self.results, f, indent=2)
                log(f"Results saved to {self.output_file}", "success")
            except Exception as e:
                log(f"Error saving results: {str(e)}", "error")

        end_time = time.time()
        duration = end_time - start_time
        log(f"Investigation completed in {duration:.2f} seconds")

        return self.results


def batch_investigate_domains(
    csv_file: str,
    output_dir: str = "investigation_results",
    timeout: int = 10,
    skip_lines: int = 0,
) -> None:
    """
    Investigate multiple domains from a CSV file.

    Args:
        csv_file: Path to CSV file with domains
        output_dir: Directory to save results
        timeout: Timeout for requests in seconds
        skip_lines: Number of lines to skip from the CSV file
    """
    import os

    import pandas as pd

    from scamrecon.utils.config import Config
    from scamrecon.utils.console import log, print_header

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Load domains
    try:
        df = pd.read_csv(csv_file, skiprows=skip_lines)
        log(
            f"Loaded {len(df)} entries from {csv_file} (skipped {skip_lines} lines)",
            "success",
        )

        # Extract domains
        domains = []
        # Always use the second column (index 1) which should contain domains
        # This handles both with and without headers correctly
        if len(df.columns) >= 2:
            domains = df.iloc[:, 1].tolist()  # Always use the second column for domains
        # Fallback options if second column doesn't exist
        elif "id" in df.columns:
            domains = df["id"].tolist()
        elif "id " in df.columns:
            domains = df["id "].tolist()
        elif "domain" in df.columns:
            domains = df["domain"].tolist()
        elif "domain " in df.columns:
            domains = df["domain "].tolist()
        else:
            domains = df.iloc[:, 0].tolist()  # Last resort: use first column

        # Filter valid domains and strip any trailing spaces
        domains = [d.strip() if isinstance(d, str) else d for d in domains]
        domains = [d for d in domains if isinstance(d, str)]
        log(f"Found {len(domains)} domains to investigate", "info")

        # Setup config
        config = Config.load_default()
        config.timeout = timeout
        config.scan_malware = True

        # Investigate each domain
        all_results = []

        for i, domain in enumerate(domains):
            log(f"Processing domain {i+1}/{len(domains)}: {domain}", "info")

            # Generate output file path
            output_file = f"{output_dir}/{domain}_investigation.json"

            # Run investigation
            investigator = DomainInvestigator(domain, config, output_file=output_file)
            result = investigator.run_investigation()
            all_results.append(result)

            # Create summary every 5 domains or at the end
            if (i + 1) % 5 == 0 or i == len(domains) - 1:
                create_investigation_summary(all_results, output_dir)
                log(f"Processed {i+1}/{len(domains)} domains", "info")

        log("\nInvestigation completed.", "success")
        log(f"Results saved to {output_dir}/", "success")

    except Exception as e:
        log(f"Error processing file: {str(e)}", "error")


def create_investigation_summary(results, output_dir):
    """
    Create summary CSV of all investigation results.

    Args:
        results: List of investigation results
        output_dir: Directory to save summary
    """
    import pandas as pd

    rows = []

    for r in results:
        row = {
            "domain": r.get("domain", ""),
            "scan_time": r.get("scan_time", ""),
            "is_cloudflare_protected": r.get("is_cloudflare_protected", False),
        }

        # Add origin information
        origins = r.get("confirmed_origins", [])
        if origins:
            row["origin_ips"] = ", ".join([o.get("ip", "") for o in origins])
        else:
            row["origin_ips"] = ""

        # Add security issues
        issues = r.get("security_issues", [])
        high_issues = [i for i in issues if i.get("severity") == "High"]
        medium_issues = [i for i in issues if i.get("severity") == "Medium"]

        row["high_severity_issues"] = len(high_issues)
        row["medium_severity_issues"] = len(medium_issues)
        row["total_issues"] = len(issues)

        # Add detected technologies
        if "technology_stack" in r:
            row["technologies"] = ", ".join(r.get("technology_stack", []))

        # Add WHOIS information
        whois = r.get("whois_info", {})
        row["registrar"] = whois.get("registrar", "")
        row["creation_date"] = whois.get("creation_date", "")

        rows.append(row)

    # Create DataFrame and save
    df = pd.DataFrame(rows)
    df.to_csv(f"{output_dir}/summary.csv", index=False)
