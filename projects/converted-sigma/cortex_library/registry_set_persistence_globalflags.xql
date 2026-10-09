// Title: Potential Persistence Via GlobalFlags
// ID: 36803969-5421-41ec-b92f-8500f79c23b0
// Status: test
// Level: high
// Author: Karneades, Jonhnathan Ribeiro, Florian Roth
// Date: 2018-04-11
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.012, car.2013-01-002
// Description: Detects registry persistence technique using the GlobalFlags and SilentProcessExit keys
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\Microsoft\\Windows NT\\CurrentVersion\\" and TargetObject contains "\\Image File Execution Options\\" and TargetObject contains "\\GlobalFlag")) or ((TargetObject contains "\\Microsoft\\Windows NT\\CurrentVersion\\" and TargetObject contains "\\SilentProcessExit\\") and (TargetObject contains "\\ReportingMode" or TargetObject contains "\\MonitorProcess")))
