// Title: Credential Dumping Attempt Via Svchost
// ID: 174afcfa-6e40-4ae9-af64-496546389294
// Status: test
// Level: high
// Author: Florent Labouyrie
// Date: 2021-04-30
// Tags: attack.privilege-escalation, attack.t1548
// Description: Detects when a process tries to access the memory of svchost to potentially dump credentials.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetImage endswith "\\svchost.exe" and GrantedAccess = "0x143a") and not (((SourceImage endswith "\\services.exe" or SourceImage endswith "\\msiexec.exe"))))
