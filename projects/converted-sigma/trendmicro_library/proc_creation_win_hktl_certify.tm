// Title: HackTool - Certify Execution
// ID: 762f2482-ff21-4970-8939-0aa317a886bb
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.discovery, attack.credential-access, attack.t1649
// Description: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\Certify.exe") OR (OriginalFileName: "Certify.exe") OR (Description: "*Certify*")) OR (((CommandLine: "*.exe cas *" OR CommandLine: "*.exe find *" OR CommandLine: "*.exe pkiobjects *" OR CommandLine: "*.exe request *" OR CommandLine: "*.exe download *")) AND ((CommandLine: "* /vulnerable*" OR CommandLine: "* /template:*" OR CommandLine: "* /altname:*" OR CommandLine: "* /domain:*" OR CommandLine: "* /path:*" OR CommandLine: "* /ca:*"))))
