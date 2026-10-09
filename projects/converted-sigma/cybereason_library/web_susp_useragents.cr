// Title: Suspicious User-Agents Related To Recon Tools
// ID: 19aa4f58-94ca-45ff-bc34-92e533c0994a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
// Date: 2022-07-19
// Tags: attack.initial-access, attack.t1190
// Description: Detects known suspicious (default) user-agents related to scanning/recon tools
// Converted by: Sigma Universal SIEM/EDR CLI

((cs-user-agent contains "commix/" OR cs-user-agent contains "feroxbuster/" OR cs-user-agent contains "Fuzz Faster U Fool" OR cs-user-agent contains "GIS - AppSec Team - Project Vision" OR cs-user-agent contains "gobuster/" OR cs-user-agent contains "Nikto/" OR cs-user-agent contains "Nmap Scripting Engine" OR cs-user-agent contains "Recon-ng/v" OR cs-user-agent contains "sqlmap/" OR cs-user-agent contains "WhatWeb/" OR cs-user-agent contains "Wfuzz/" OR cs-user-agent contains "WPScan v" OR cs-user-agent contains "zgrab/"))
