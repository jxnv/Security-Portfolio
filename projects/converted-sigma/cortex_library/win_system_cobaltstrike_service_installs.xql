// Title: CobaltStrike Service Installations - System
// ID: 5a105d34-05fc-401e-8553-272b45c1522d
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems), Wojciech Lesicki
// Date: 2021-05-26
// Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.lateral-movement, attack.t1021.002, attack.t1543.003, attack.t1569.002
// Description: Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Provider_Name = "Service Control Manager" and EventID = 7045) and (((ImagePath contains "ADMIN$" and ImagePath contains ".exe")) or ((ImagePath contains "%COMSPEC%" and ImagePath contains "start" and ImagePath contains "powershell")) or (ImagePath contains "powershell -nop -w hidden -encodedcommand") or ((ImagePath contains "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTI3LjAuMC4xO" or ImagePath contains "lFWCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzEyNy4wLjAuMT" or ImagePath contains "JRVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xMjcuMC4wLjE6"))))
