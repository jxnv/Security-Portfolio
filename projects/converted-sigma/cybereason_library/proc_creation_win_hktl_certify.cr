// Title: HackTool - Certify Execution
// ID: 762f2482-ff21-4970-8939-0aa317a886bb
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.discovery, attack.credential-access, attack.t1649
// Description: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\Certify.exe") OR (OriginalFileName == "Certify.exe") OR (Description contains "Certify")) OR (((CommandLine contains ".exe cas " OR CommandLine contains ".exe find " OR CommandLine contains ".exe pkiobjects " OR CommandLine contains ".exe request " OR CommandLine contains ".exe download ")) AND ((CommandLine contains " /vulnerable" OR CommandLine contains " /template:" OR CommandLine contains " /altname:" OR CommandLine contains " /domain:" OR CommandLine contains " /path:" OR CommandLine contains " /ca:"))))
