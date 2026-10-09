// Title: UAC Bypass Tools Using ComputerDefaults
// ID: 3c05e90d-7eba-4324-9972-5d7f711a60a8
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-31
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects tools such as UACMe used to bypass UAC with computerdefaults.exe (UACMe 59)
// Converted by: Sigma Universal SIEM/EDR CLI

(((IntegrityLevel == "High" OR IntegrityLevel == "System" OR IntegrityLevel == "S-1-16-16384" OR IntegrityLevel == "S-1-16-12288") AND Image == "C:\\Windows\\System32\\ComputerDefaults.exe") AND NOT (((ParentImage contains ":\\Windows\\System32" OR ParentImage contains ":\\Program Files"))))
