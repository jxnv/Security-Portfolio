// Title: File Encoded To Base64 Via Certutil.EXE
// ID: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-02-24
// Tags: attack.stealth, attack.t1027
// Description: Detects the execution of certutil with the "encode" flag to encode a file to base64. This can be abused by threat actors and attackers for data exfiltration
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "-encode" OR CommandLine contains "/encode")) AND ((Image="*\\certutil.exe") OR (OriginalFileName == "CertUtil.exe")))
