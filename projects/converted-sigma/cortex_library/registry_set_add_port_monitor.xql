// Title: Add Port Monitor Persistence in Registry
// ID: 944e8941-f6f6-4ee8-ac05-1c224e923c0e
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-30
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.010
// Description: Adversaries may use port monitors to run an attacker supplied DLL during system boot for persistence or privilege escalation.
// A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Control\\Print\\Monitors\\" and Details endswith ".dll") and not (((action_process_image_path = "C:\\Windows\\System32\\spoolsv.exe" and TargetObject contains "\\Control\\Print\\Monitors\\CutePDF Writer Monitor v4.0\\Driver" and Details = "cpwmon64_v40.dll" and (action_process_username contains "AUTHORI" or action_process_username contains "AUTORI")) or (TargetObject contains "\\Control\\Print\\Monitors\\MONVNC\\Driver") or ((TargetObject contains "Control\\Print\\Environments\\" and TargetObject contains "\\Drivers\\" and TargetObject contains "\\VNC Printer")))))
