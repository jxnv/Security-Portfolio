// Title: Change User Account Associated with the FAX Service
// ID: e3fdf743-f05b-4051-990a-b66919be1743
// Status: test
// Level: high
// Author: frack113
// Date: 2022-07-17
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detect change of the user account associated with the FAX service to avoid the escalation problem.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject == "HKLM\\System\\CurrentControlSet\\Services\\Fax\\ObjectName") AND NOT ((Details contains "NetworkService")))
