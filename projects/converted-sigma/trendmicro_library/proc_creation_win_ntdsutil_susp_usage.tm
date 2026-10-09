// Title: Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe)
// ID: a58353df-af43-4753-bad0-cd83ef35eef5
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-14
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects execution of ntdsutil.exe to perform different actions such as restoring snapshots...etc.
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine: "*snapshot*" AND CommandLine: "*mount *")) OR ((CommandLine: "*ac*" AND CommandLine: "* i*" AND CommandLine: "* ntds*"))) AND ((Image="*\\ntdsutil.exe") OR (OriginalFileName: "ntdsutil.exe")))
