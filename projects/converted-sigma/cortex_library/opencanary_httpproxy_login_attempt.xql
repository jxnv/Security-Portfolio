// Title: OpenCanary - HTTPPROXY Login Attempt
// ID: 5498fc09-adc6-4804-b9d9-5cca1f0b8760
// Status: test
// Level: high
// Author: Security Onion Solutions
// Date: 2024-03-08
// Tags: attack.initial-access, attack.command-and-control, attack.t1090
// Description: Detects instances where an HTTPPROXY service on an OpenCanary node has had an attempt to proxy another page.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (logtype = 7001)
