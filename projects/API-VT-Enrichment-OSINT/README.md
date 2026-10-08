# VirusTotal IOC Lookup

A small Python utility for quickly querying the **VirusTotal API** for an Indicator of Compromise (IOC) and displaying its detection results.

## What It Does

The script accepts an IOC as a command-line argument and automatically determines whether it is:

* IP address
* Domain
* File hash (MD5, SHA-1, or SHA-256)

It then queries VirusTotal and displays the latest analysis statistics.

### Example Output

```text
Detection Summary

Malicious: 3
Suspicious: 1
Harmless: 65
Undetected: 12
```

## Requirements

* Python 3
* VirusTotal API key
* `requests`
* `python-dotenv`

Install dependencies:

```bash
pip install requests python-dotenv
```

## API Key Setup

Create a `.env` file in the same directory as the script:

```text
VT_API_key=YOUR_VIRUSTOTAL_API_KEY
```

The API key is loaded from the environment and sent to VirusTotal through the `x-apikey` HTTP header.

**Do not commit your `.env` file to GitHub.**

Add this to `.gitignore`:

```text
.env
```

## Usage

Run the script with an IOC as the first argument:

```bash
python script.py 8.8.8.8
```

Domain:

```bash
python script.py example.com
```

SHA-256:

```bash
python script.py <SHA256_HASH>
```

## How It Works

```text
IOC
 │
 ▼
Detect IOC Type
 │
 ├── IP
 ├── Domain
 └── Hash
      │
      ▼
Build VirusTotal API URL
      │
      ▼
Send API Request
      │
      ▼
Parse Analysis Statistics
      │
      ▼
Display Detection Summary
```

## Purpose

This project was built as a lightweight threat-intelligence automation example for quickly checking IOCs against VirusTotal.

It demonstrates:

* Python API integration
* Environment variable/API key management
* IOC type detection
* REST API requests
* JSON response parsing
* Basic threat-intelligence automation

## Disclaimer

This project is intended for authorized security research and defensive security use.
