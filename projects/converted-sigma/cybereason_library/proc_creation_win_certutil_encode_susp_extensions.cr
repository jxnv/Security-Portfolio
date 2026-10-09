// Title: Suspicious File Encoded To Base64 Via Certutil.EXE
// ID: ea0cdc3e-2239-4f26-a947-4e8f8224e464
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-15
// Tags: attack.stealth, attack.t1027
// Description: Detects the execution of certutil with the "encode" flag to encode a file to base64 where the extensions of the file is suspicious
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "-encode" OR CommandLine contains "/encode")) AND ((CommandLine contains ".acl" OR CommandLine contains ".bat" OR CommandLine contains ".doc" OR CommandLine contains ".gif" OR CommandLine contains ".jpeg" OR CommandLine contains ".jpg" OR CommandLine contains ".mp3" OR CommandLine contains ".pdf" OR CommandLine contains ".png" OR CommandLine contains ".ppt" OR CommandLine contains ".tmp" OR CommandLine contains ".xls" OR CommandLine contains ".xml")) AND ((Image="*\\certutil.exe") OR (OriginalFileName == "CertUtil.exe")))
