// Title: Credential Dumping Tools Service Execution - Security
// ID: f0d1feba-4344-4ca9-8121-a6c97bd6df52
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
// Date: 2017-03-05
// Tags: attack.credential-access, attack.execution, attack.t1003.001, attack.t1003.002, attack.t1003.004, attack.t1003.005, attack.t1003.006, attack.t1569.002, attack.s0005
// Description: Detects well-known credential dumping tools execution via service execution events
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 4697 and (ServiceFileName contains "cachedump" or ServiceFileName contains "dumpsvc" or ServiceFileName contains "fgexec" or ServiceFileName contains "gsecdump" or ServiceFileName contains "mimidrv" or ServiceFileName contains "pwdump" or ServiceFileName contains "servpw"))
