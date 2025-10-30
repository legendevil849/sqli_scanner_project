# Evil SQLi Scanner

## A basic sqli scanner which can detect the type of injection
* -Boolean-based
* -Time-based
* -Error-based
* -Union- based

## It can also do DBMS detection based on signatures 
* -MySQL
* -MSSQL
* -PostgreSQL
* -Oracle
* -SQLite

## DVWA Lab Integration
* It comes with dvwa (Damn Vulnerable Web Apps) logging for testing porposes

## Exploitation
* -Version Extraction
* -User Extraction

## Installation
Step I <br>
```bash
git clone https://github.com/legendevil849/sqli_scanner_project.git
```
Step II <br><br>
Go to the Sqli Scanner Directory <br><br>
Step III <br>
```bash
python -m pip install -r requirements.txt
```

# Use case and Info
```bash
python Evil_SQLi.py --help
```

# Disclaimer
This tool is intended for educational and ethical penetration testing purposes only.
The author is not responsible for any misuse of this tool against systems without prior authorization.
Use responsibly.
