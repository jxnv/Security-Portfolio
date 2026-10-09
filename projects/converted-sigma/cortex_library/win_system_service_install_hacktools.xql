// Title: HackTool Service Registration or Execution
// ID: d26ce60c-2151-403c-9a42-49420d87b5e4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-21
// Tags: attack.execution, attack.t1569.002, attack.s0029
// Description: Detects installation or execution of services
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Provider_Name = "Service Control Manager" and (EventID = 7045 or EventID = 7036)) and ((ImagePath contains "bypass") or ((ServiceName contains "cachedump" or ServiceName contains "DumpSvc" or ServiceName contains "gsecdump" or ServiceName contains "pwdump" or ServiceName contains "UACBypassedService" or ServiceName contains "WCE SERVICE" or ServiceName contains "WCESERVICE" or ServiceName contains "winexesvc"))))
