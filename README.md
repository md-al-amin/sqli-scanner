# sqli-scanner
A comprehensive, multithreaded SQL injection vulnerability scanner designed for ethical security testing and penetration testing. This tool automatically crawls websites, identifies potential injection points, and tests them with a comprehensive payload database to detect SQL injection vulnerabilities.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ethical Use](https://img.shields.io/badge/Use-Ethical%20Only-green.svg)](https://owasp.org/www-project-code-of-conduct/)

## 🚀 Features

- **100+ Built-in SQL Payloads**: Comprehensive payload database covering all major SQL injection attack vectors
- **Intelligent Web Crawling**: Automatically discovers forms, URLs with parameters, and potential injection points
- **Multiple Detection Methods**: Error-based, time-based, content-based, and status code-based vulnerability detection
- **High-Performance Scanning**: Multithreaded architecture with configurable worker pools
- **Session Management**: Full cookie support with Cookie Editor JSON import capability  
- **Flexible Target Input**: Single URL testing or bulk domain scanning from files
- **Professional Output**: Clean CSV results with detailed vulnerability information
- **Security-First Design**: SSL verification enabled by default, respectful crawling with rate limiting
- **Protocol Detection**: Automatic HTTPS/HTTP detection and smart fallback mechanisms
- **Comprehensive Logging**: Detailed scan logs with configurable verbosity levels

## ⚠️ Important Security Notice

**This tool contains potentially destructive SQL injection payloads in its default set, including:**
- `DROP TABLE` statements that can delete database tables
- `INSERT` statements that can add unauthorized data
- Other destructive database operations

**🔴 CRITICAL**: The default payloads include destructive operations. For safe scanning, create a custom payload file with only detection payloads, or ensure you have full authorization and database backups before testing.

## 🛠️ Installation 

### Prerequisites

- **Python 3.7 or higher** - Check with `python --version`
- **pip package manager** - Usually included with Python
- **Internet connection** - For downloading dependencies

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/md-al-amin/sqli-scanner.git

# Navigate to the project directory  
cd sqli-scanner
```

### Step 2: Install Dependencies

```bash
# Install required Python packages
pip install -r requirements.txt

### Step 3: Verify Installation

```bash
# Test the installation
python sqli_checker.py --help

# You should see the help menu with all available options
```
### Requirements.txt Contents

The tool requires these Python packages:

```text
requests>=2.28.0
beautifulsoup4>=4.11.0
urllib3>=1.26.0
lxml>=4.9.0
chardet>=5.0.0
```
### Basic Usage

```bash
# Scan a single website (uses default payloads - includes destructive ones!)
python sqli_checker.py --url https://example.com --output results.csv

# Safer: Use custom detection-only payloads
python sqli_checker.py --url https://example.com --payloads sqli_payloads.txt --output results.csv
```
### First Scan

```bash
# Run your first safe scan
python sqli_checker.py --url https://example.com --payloads sqli_payloads.txt --output my_first_scan.csv

# Check the results
cat my_first_scan.csv
```
## 🎯 Usage Guide

### Basic Syntax

```bash
python sqli_checker.py [INPUT_OPTIONS] --output OUTPUT_FILE [SCAN_OPTIONS]
```

### Input Methods

You must specify **one** of these input methods:

- `--url URL` - Test a single website
- `--domains FILE` - Test multiple domains from a file

### Required Arguments

- `--output FILE` - CSV file to save scan results

### Optional Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--payloads FILE` | Built-in payloads | Custom payload file (recommended for safety) |
| `--cookies FILE` | None | JSON file with cookies for authentication |
| `--workers N` | 10 | Number of concurrent scanning threads |
| `--depth N` | 3 | Maximum website crawling depth |
| `--max-pages N` | 100 | Maximum pages to crawl per domain |
| `--delay MIN MAX` | 1 3 | Random delay range between requests (seconds) |
| `--timeout N` | 10 | HTTP request timeout (seconds) |
| `--no-verify-ssl` | False | Disable SSL certificate verification |
| `--log FILE` | None | Log file for detailed scan information |
| `--verbose` | False | Enable verbose logging output |

## 📚 Examples

### Single Website Testing

```bash
# Basic scan with safe payloads
python sqli_checker.py --url https://testsite.com --payloads safe_payloads.txt --output results.csv

# Detailed scan with logging
python sqli_checker.py --url https://testsite.com --payloads safe_payloads.txt --output results.csv --log scan.log --verbose

# Fast scan with more workers
python sqli_checker.py --url https://testsite.com --payloads safe_payloads.txt --output results.csv --workers 20 --depth 2
```

### Authenticated Testing

```bash
# Export cookies from your browser using Cookie Editor extension
# Save as cookies.json, then run:
python sqli_checker.py --url https://app.example.com --payloads safe_payloads.txt --cookies cookies.json --output results.csv
```
### Bulk Domain Testing

```bash
# Create domains.txt with your target domains
echo "testsite1.com" > domains.txt
echo "testsite2.com" >> domains.txt
echo "https://testsite3.com" >> domains.txt

# Run bulk scan
python sqli_checker.py --domains domains.txt --payloads safe_payloads.txt --output bulk_results.csv --workers 15
```

### Development/Testing Environment

```bash
# For self-signed certificates or internal testing
python sqli_checker.py --url https://dev-server.local --payloads safe_payloads.txt --output results.csv --no-verify-ssl
```

### Performance Tuning Examples

```bash
# High-speed scanning (use carefully)
python sqli_checker.py --url https://testsite.com --payloads safe_payloads.txt --output results.csv --workers 25 --delay 0.5 1

# Respectful/slow scanning
python sqli_checker.py --url https://testsite.com --payloads safe_payloads.txt --output results.csv --workers 3 --delay 3 6

# Deep crawling
python sqli_checker.py --url https://testsite.com --payloads safe_payloads.txt --output results.csv --depth 5 --max-pages 500

# Quick assessment
python sqli_checker.py --url https://testsite.com --payloads safe_payloads.txt --output results.csv --depth 1 --max-pages 20
```

## 📄 File Formats

### Domain List File (`domains.txt`)

One domain per line, with or without protocol:

```text
example1.com
https://example2.com  
http://test.example3.com
subdomain.example4.com
192.168.1.100
```

### Custom Payload File (`payloads.txt`)

One SQL injection payload per line:

```text
# Comments start with # and are ignored
'
"
' OR '1'='1
" OR "1"="1
' UNION SELECT NULL--
' AND SLEEP(5)--
' OR 1=1 /*
" OR 1=1 /*
```

### Cookie File (`cookies.json`) - Cookie Editor Format

Export from Cookie Editor browser extension:

```json
[
  {
    "name": "sessionid",
    "value": "abc123def456ghi789",
    "domain": "example.com",
    "path": "/",
    "secure": true,
    "httpOnly": true
  },
  {
    "name": "csrftoken", 
    "value": "xyz789uvw123rst456",
    "domain": "example.com",
    "path": "/"
  }
]
```

Alternative simple format:
```json
{
  "sessionid": "abc123def456ghi789",
  "csrftoken": "xyz789uvw123rst456"
}
```

## 📊 Output Format

Results are saved in CSV format with these columns:

| Column | Description | Example |
|--------|-------------|---------|
| `url` | The tested URL | `https://example.com/search` |
| `parameter` | Parameter name tested | `q` |
| `payload` | SQL injection payload used | `' OR '1'='1` |
| `vulnerable` | Vulnerability found (True/False) | `True` |
| `detection_method` | How vulnerability was detected | `Error-based SQL injection detected` |
| `status_code` | HTTP response status | `500` |
| `response_time` | Response time in seconds | `0.342` |

### Sample Output

```csv
url,parameter,payload,vulnerable,detection_method,status_code,response_time
https://example.com/search,q,',True,Error-based SQL injection detected,500,0.34
https://example.com/login,user,' OR '1'='1,True,Content-based SQL injection detected,200,0.52
https://example.com/products,id,1,False,No SQL injection detected,200,0.28
https://example.com/news,search,' UNION SELECT NULL--,True,Error-based SQL injection detected,500,0.41
```

### Analyzing Results

```bash
# Count total vulnerabilities found
grep "True" results.csv | wc -l

# Find all vulnerable URLs
grep "True" results.csv | cut -d, -f1 | sort -u

# Find specific detection methods
grep "Error-based" results.csv
```

## 🎯 Payload Information

### Default Payload Categories (⚠️ Includes Destructive)

The built-in payload set includes **100+ payloads** across these categories:

#### Safe Detection Payloads
- **Basic quotes**: `'`, `"`
- **Authentication bypass**: `' OR '1'='1`, `" OR "1"="1`
- **Union injection**: `' UNION SELECT NULL--`
- **Time-based blind**: `' AND SLEEP(5)--`, `'; WAITFOR DELAY '00:00:05'--`
- **Boolean blind**: `' AND 1=1--`, `' AND 1=2--`
- **Error-based**: `' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--`

#### ⚠️ Destructive Payloads (In Defaults)
- **Table deletion**: `'; DROP TABLE users--`
- **Data insertion**: `'; INSERT INTO users VALUES('hacker','password')--`
- **Data modification**: `'; UPDATE users SET password='hacked'--`
- **System commands**: Various xp_cmdshell attempts

#### Database-Specific Payloads
- **MySQL**: `@@version`, `information_schema` queries
- **PostgreSQL**: `version()`, `current_database()`
- **Oracle**: `v$version`, `dual` table queries
- **SQLite**: `sqlite_version()`
- **SQL Server**: `@@SERVERNAME`, system function calls

### Recommended Safe Payload Set

For production scanning, use only detection payloads:

```bash
# Create safe_payloads.txt
cat > safe_payloads.txt << 'EOF'
# Basic detection payloads - SAFE FOR PRODUCTION
'
"
' OR '1'='1
" OR "1"="1
' OR '1'='1' --
" OR "1"="1" --
' OR 1=1--
" OR 1=1--
' UNION SELECT NULL--
" UNION SELECT NULL--
' UNION SELECT NULL,NULL--
" UNION SELECT NULL,NULL--
' AND 1=1--
" AND 1=1--
' AND 1=2--
" AND 1=2--
' AND SLEEP(1)--
" AND SLEEP(1)--
' AND pg_sleep(1)--
" AND pg_sleep(1)--
'; WAITFOR DELAY '00:00:01'--
"; WAITFOR DELAY '00:00:01'--
' AND (SELECT * FROM (SELECT(SLEEP(1)))a)--
" AND (SELECT * FROM (SELECT(SLEEP(1)))a)--
EOF
```
## 🔍 Detection Methods

The scanner uses multiple sophisticated detection techniques:

### 1. Error-Based Detection

Identifies SQL database errors in HTTP responses:

**MySQL Errors Detected:**
- `SQL syntax.*MySQL`
- `Warning.*mysql_.*`
- `MySQLSyntaxErrorException`

**PostgreSQL Errors:**
- `PostgreSQL.*ERROR`
- `Warning.*pg_.*`
- `valid PostgreSQL result`

**Oracle Errors:**
- `ORA-[0-9][0-9][0-9][0-9][0-9]`
- `Oracle error`
- `Oracle.*Driver`

**SQL Server Errors:**
- `Microsoft OLE DB Provider`
- `Incorrect syntax near`
- `Unclosed quotation mark`

### 2. Time-Based Detection

Measures response time delays:
- Detects `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()` functions
- Configurable time thresholds (default: 5 seconds)
- Statistical analysis of response patterns

### 3. Content-Based Detection

Analyzes response content differences:
- Content length variations (>10% difference)
- HTML structure changes
- Response pattern analysis
- Boolean-based injection detection

### 4. Status Code Detection

Monitors HTTP response codes:
- 500 Internal Server Error (common with syntax errors)
- 400 Bad Request responses  
- Unexpected status code changes
- Error page detection

## 🔒 Security Features

### Built-in Protection Mechanisms

- **SSL Verification**: Enabled by default (`--no-verify-ssl` to disable)
- **Rate Limiting**: Random delays between requests (1-3 seconds default)
- **Robots.txt Compliance**: Respects website crawling restrictions
- **Session Management**: Maintains cookies and session state
- **Timeout Protection**: Prevents hanging requests (10 second default)
- **Error Handling**: Graceful failure recovery and logging

### Respectful Scanning Features

- **User-Agent**: Professional browser user-agent string
- **Request Headers**: Proper HTTP headers for legitimate appearance
- **Crawl Depth Limits**: Prevents excessive website traversal
- **Page Limits**: Configurable maximum pages per domain
- **Thread Limits**: Reasonable default concurrent connections

## 📝 Logging and Debugging

### Enable Logging

```bash
# Basic logging to file
python sqli_checker.py --url example.com --payloads safe_payloads.txt --output results.csv --log scan.log

# Verbose logging with console output
python sqli_checker.py --url example.com --payloads safe_payloads.txt --output results.csv --log scan.log --verbose
```

### Log Information Includes

- **Scan Progress**: URLs being tested, payloads tried
- **Detection Results**: How vulnerabilities were identified  
- **Error Messages**: Connection failures, timeouts, parsing errors
- **Performance Metrics**: Response times, thread utilization
- **Security Warnings**: SSL verification status, destructive payloads

### Sample Log Output

```
2024-01-15 10:30:15 - INFO - Starting SQL injection test for: https://example.com
2024-01-15 10:30:15 - WARNING - ⚠️  Using default payloads which include destructive operations
2024-01-15 10:30:16 - INFO - Crawling: https://example.com (depth: 0)
2024-01-15 10:30:17 - INFO - Found 5 potential test targets
2024-01-15 10:30:17 - INFO - Starting 50 SQL injection tests...
2024-01-15 10:30:20 - INFO - Vulnerability found: https://example.com/search?q=' - Error-based detection
2024-01-15 10:30:25 - INFO - Completed testing https://example.com. Found 3 vulnerabilities
```
## 🚨 Legal Notice

### ⚠️ CRITICAL: Authorized Use Only

**This tool is designed for ethical security testing and must only be used on systems you own or have explicit written permission to test.**

### Legal Requirements

✅ **Authorized Uses:**
- Testing your own websites and applications
- Penetration testing with signed contracts and legal authorization
- Security research on systems you control
- Educational purposes on designated test environments

❌ **Prohibited Uses:**
- Testing websites without explicit written permission
- Unauthorized penetration testing or vulnerability research
- Malicious exploitation of discovered vulnerabilities
- Any activity that violates computer fraud and abuse laws

### Legal Disclaimer

- Users are **solely responsible** for ensuring legal compliance
- Authors assume **no liability** for misuse of this software
- This tool may trigger security alerts and monitoring systems
- Some jurisdictions have strict laws regarding security testing tools
- **Consult legal counsel** before use in enterprise environments

#### Installation Problems

**Issue**: `pip install` fails with permission errors
```bash
# Solution: Use virtual environment or user install
python -m pip install --user -r requirements.txt
```

**Issue**: Python version incompatibility
```bash
# Check Python version
python --version
# Must be 3.7 or higher
```

#### Connection Issues

**Issue**: SSL certificate verification fails
```bash
# For testing environments only
python sqli_checker.py --url https://test-site.local --output results.csv --no-verify-ssl
```

**Issue**: Connection timeouts
```bash
# Increase timeout and reduce workers
python sqli_checker.py --url example.com --output results.csv --timeout 30 --workers 3
```

#### Performance Issues

**Issue**: Scanning too slow
```bash
# Increase workers and reduce delays
python sqli_checker.py --url example.com --output results.csv --workers 20 --delay 0.5 1
```

**Issue**: Getting blocked by rate limiting
```bash
# Reduce workers and increase delays
python sqli_checker.py --url example.com --output results.csv --workers 3 --delay 5 10
```

#### Output Issues

**Issue**: No vulnerabilities found in known vulnerable app
```bash
# Check if you need authentication
python sqli_checker.py --url example.com --cookies cookies.json --output results.csv

# Try verbose logging to see what's happening
python sqli_checker.py --url example.com --output results.csv --log debug.log --verbose
```

### Getting Help

1. **Check the logs**: Use `--log` and `--verbose` for detailed information
2. **Verify connectivity**: Ensure you can access the target manually
3. **Test authentication**: Verify cookies are valid and properly exported
4. **Review payloads**: Make sure your payload file format is correct
5. **Check permissions**: Ensure you have authorization to test the target

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for full details.

### MIT License Summary

✅ **Permissions:**
- Commercial use
- Modification and distribution
- Private use
- Patent use

❌ **Limitations:**
- No liability
- No warranty

