// Title: CobaltStrike Service Installations - Security
// ID: d7a95147-145f-4678-b85d-d1ff4a3bb3f6
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Wojciech Lesicki
// Date: 2021-05-26
// Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.lateral-movement, attack.t1021.002, attack.t1543.003, attack.t1569.002
// Description: Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID == "4697") AND (((ServiceFileName contains "ADMIN$" AND ServiceFileName contains ".exe")) OR ((ServiceFileName contains "%COMSPEC%" AND ServiceFileName contains "start" AND ServiceFileName contains "powershell")) OR (ServiceFileName contains "powershell -nop -w hidden -encodedcommand") OR ((ServiceFileName contains "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTI3LjAuMC4xO" OR ServiceFileName contains "lFWCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzEyNy4wLjAuMT" OR ServiceFileName contains "JRVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xMjcuMC4wLjE6"))))
