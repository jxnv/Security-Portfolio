// Title: PsExec Tool Execution From Suspicious Locations - PipeName
// ID: 41504465-5e3a-4a5b-a5b4-2a0baadd4463
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-04
// Tags: attack.execution, attack.t1569.002, attack.s0029
// Description: Detects PsExec default pipe creation where the image executed is located in a suspicious location. Which could indicate that the tool is being used in an attack
// Converted by: Sigma Universal SIEM/EDR CLI

(PipeName: "\\PSEXESVC" AND (Image: "*:\\Users\\Public\\*" OR Image: "*:\\Windows\\Temp\\*" OR Image: "*\\AppData\\Local\\Temp\\*" OR Image: "*\\Desktop\\*" OR Image: "*\\Downloads\\*"))
