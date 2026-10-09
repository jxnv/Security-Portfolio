// Title: Unauthorized System Time Modification
// ID: faa031b5-21ed-4e02-8881-2591f98d82ed
// Status: test
// Level: low
// Author: @neu5ron
// Date: 2019-02-05
// Tags: attack.stealth, attack.t1070.006
// Description: Detect scenarios where a potentially unauthorized application or user is modifying the system time.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4616) and not ((ProcessName = "C:\\Windows\\System32\\svchost.exe" and SubjectUserSid = "S-1-5-19")) and not (((ProcessName = "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" or ProcessName = "C:\\Program Files (x86)\\VMware\\VMware Tools\\vmtoolsd.exe" or ProcessName = "C:\\Windows\\System32\\VBoxService.exe" or ProcessName = "C:\\Windows\\System32\\oobe\\msoobe.exe"))))
