// Title: Potential CobaltStrike Service Installations - Registry
// ID: 61a7697c-cb79-42a8-a2ff-5f0cdfae0130
// Status: test
// Level: high
// Author: Wojciech Lesicki
// Date: 2021-06-29
// Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.lateral-movement, attack.t1021.002, attack.t1543.003, attack.t1569.002
// Description: Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.
// Converted by: Sigma Universal SIEM/EDR CLI

((((Details: "*ADMIN$*" AND Details: "*.exe*")) OR ((Details: "*%COMSPEC%*" AND Details: "*start*" AND Details: "*powershell*"))) AND ((TargetObject: "*\\System\\CurrentControlSet\\Services*") OR ((TargetObject: "*\\System\\ControlSet*" AND TargetObject: "*\\Services*"))))
