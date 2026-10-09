// Title: Root Certificate Installed From Susp Locations
// ID: 5f6a601c-2ecb-498b-9c33-660362323afa
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.defense-impairment, attack.t1553.004
// Description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "Import-Certificate" AND CommandLine contains " -FilePath " AND CommandLine contains "Cert:\\LocalMachine\\Root") AND (CommandLine contains "\\AppData\\Local\\Temp\\" OR CommandLine contains ":\\Windows\\TEMP\\" OR CommandLine contains "\\Desktop\\" OR CommandLine contains "\\Downloads\\" OR CommandLine contains "\\Perflogs\\" OR CommandLine contains ":\\Users\\Public\\"))
