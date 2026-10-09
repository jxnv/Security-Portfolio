// Title: UAC Bypass Using Consent and Comctl32 - Process
// ID: 1ca6bd18-0ba0-44ca-851c-92ed89a61085
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
// Converted by: Sigma Universal SIEM/EDR CLI

(ParentImage="*\\consent.exe" AND Image="*\\werfault.exe" AND (IntegrityLevel == "High" OR IntegrityLevel == "System" OR IntegrityLevel == "S-1-16-16384" OR IntegrityLevel == "S-1-16-12288"))
