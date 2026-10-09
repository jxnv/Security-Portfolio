// Title: Suspicious Service Installation Script
// ID: 70f00d10-60b2-4f34-b9a0-dc3df3fe762a
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2022-03-18
// Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
// Description: Detects suspicious service installation scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImagePath contains "cscript" or ImagePath contains "mshta" or ImagePath contains "powershell" or ImagePath contains "pwsh" or ImagePath contains "regsvr32" or ImagePath contains "rundll32" or ImagePath contains "wscript")) and ((ImagePath contains " -c " or ImagePath contains " -r " or ImagePath contains " -k ")) and (Provider_Name = "Service Control Manager" and EventID = 7045))
