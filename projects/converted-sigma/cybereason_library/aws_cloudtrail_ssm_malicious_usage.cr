// Title: Potential Malicious Usage of CloudTrail System Manager
// ID: 38e7f511-3f74-41d4-836e-f57dfa18eead
// Status: test
// Level: high
// Author: jamesc-grafana
// Date: 2024-07-11
// Tags: attack.privilege-escalation, attack.initial-access, attack.t1566, attack.t1566.002
// Description: Detect when System Manager successfully executes commands against an instance.
// Converted by: Sigma Universal SIEM/EDR CLI

((eventName == "SendCommand" AND eventSource == "ssm.amazonaws.com") AND ((NOT errorCode=*) OR (errorCode == "Success")))
