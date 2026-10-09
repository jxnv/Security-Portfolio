// Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security
// ID: 4c54ba8f-73d2-4d40-8890-d9cf1dca3d30
// Status: test
// Level: high
// Author: Timur Zinniatullin, oscd.community
// Date: 2020-10-13
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 4697 and (ServiceFileName contains "&&set" and ServiceFileName contains "cmd" and ServiceFileName contains "/c" and ServiceFileName contains "-f") and (ServiceFileName contains "{0}" or ServiceFileName contains "{1}" or ServiceFileName contains "{2}" or ServiceFileName contains "{3}" or ServiceFileName contains "{4}" or ServiceFileName contains "{5}"))
