// Title: UAC Bypass Using NTFS Reparse Point - Process
// ID: 39ed3c80-e6a1-431b-9df3-911ac53d08a7
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-30
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine="\"C:\\Windows\\system32\\wusa.exe\"  /quiet C:\\Users\\*" AND CommandLine="*\\AppData\\Local\\Temp\\update.msu" AND (IntegrityLevel == "High" OR IntegrityLevel == "System" OR IntegrityLevel == "S-1-16-16384" OR IntegrityLevel == "S-1-16-12288")) OR (ParentCommandLine == "\"C:\\Windows\\system32\\dism.exe\" /online /quiet /norestart /add-package /packagepath:\"C:\\Windows\\system32\\pe386\" /ignorecheck" AND (IntegrityLevel == "High" OR IntegrityLevel == "System") AND (CommandLine contains "C:\\Users\\" AND CommandLine contains "\\AppData\\Local\\Temp\\" AND CommandLine contains "\\dismhost.exe {") AND Image="*\\DismHost.exe"))
