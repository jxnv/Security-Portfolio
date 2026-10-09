// Title: Suspicious User-Agents Related To Recon Tools
// ID: 19aa4f58-94ca-45ff-bc34-92e533c0994a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
// Date: 2022-07-19
// Tags: attack.initial-access, attack.t1190
// Description: Detects known suspicious (default) user-agents related to scanning/recon tools
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((cs-user-agent contains "commix/" or cs-user-agent contains "feroxbuster/" or cs-user-agent contains "Fuzz Faster U Fool" or cs-user-agent contains "GIS - AppSec Team - Project Vision" or cs-user-agent contains "gobuster/" or cs-user-agent contains "Nikto/" or cs-user-agent contains "Nmap Scripting Engine" or cs-user-agent contains "Recon-ng/v" or cs-user-agent contains "sqlmap/" or cs-user-agent contains "WhatWeb/" or cs-user-agent contains "Wfuzz/" or cs-user-agent contains "WPScan v" or cs-user-agent contains "zgrab/"))
