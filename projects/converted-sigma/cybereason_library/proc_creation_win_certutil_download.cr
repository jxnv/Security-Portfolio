// Title: Suspicious Download Via Certutil.EXE
// ID: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-15
// Tags: attack.stealth, attack.t1027, attack.command-and-control, attack.t1105
// Description: Detects the execution of certutil with certain flags that allow the utility to download files.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "urlcache " OR CommandLine contains "verifyctl " OR CommandLine contains "URL ")) AND (CommandLine contains "http") AND ((Image="*\\certutil.exe") OR (OriginalFileName == "CertUtil.exe")))
