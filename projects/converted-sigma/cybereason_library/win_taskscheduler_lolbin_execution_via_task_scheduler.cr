// Title: Scheduled Task Executed Uncommon LOLBIN
// ID: f0767f15-0fb3-44b9-851e-e8d9a6d0005d
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-05
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005
// Description: Detects the execution of Scheduled Tasks where the program being run is located in a suspicious location or where it is an unusual program to be run from a Scheduled Task
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID == "129" AND (Path="*\\calc.exe" OR Path="*\\cscript.exe" OR Path="*\\mshta.exe" OR Path="*\\mspaint.exe" OR Path="*\\notepad.exe" OR Path="*\\regsvr32.exe" OR Path="*\\wscript.exe"))
