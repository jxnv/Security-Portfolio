// Title: Certificate Request Export to Exchange Webserver
// ID: b7bc7038-638b-4ffd-880c-292c692209ef
// Status: test
// Level: critical
// Author: Max Altgelt (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.persistence, attack.t1505.003
// Description: Detects a write of an Exchange CSR to an untypical directory or with aspx name suffix which can be used to place a webshell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((( = "New-ExchangeCertificate" and  = " -GenerateRequest" and  = " -BinaryEncoded" and  = " -RequestFile")) and ("\\\\\\\\localhost\\\\C$" or "\\\\\\\\127.0.0.1\\\\C$" or "C:\\\\inetpub" or ".aspx"))
