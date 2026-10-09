// Title: Suspicious Printer Driver Empty Manufacturer
// ID: e0813366-0407-449a-9869-a2db1119dc41
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2020-07-01
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574, cve.2021-1675
// Description: Detects a suspicious printer driver installation with an empty Manufacturer value
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\Control\\Print\\Environments\\Windows x64\\Drivers" and TargetObject contains "\\Manufacturer") and Details = "(Empty)") and not (((TargetObject contains "\\CutePDF Writer v4.0\\") or (TargetObject contains "\\Version-3\\PDF24\\") or ((TargetObject contains "\\VNC Printer (PS)\\" or TargetObject contains "\\VNC Printer (UD)\\")))))
