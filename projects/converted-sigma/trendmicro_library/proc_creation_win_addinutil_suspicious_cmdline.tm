// Title: Suspicious AddinUtil.EXE CommandLine Execution
// ID: 631b22a4-70f4-4e2f-9ea8-42f84d9df6d8
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
// Date: 2023-09-18
// Tags: attack.stealth, attack.t1218
// Description: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) with suspicious Addinroot or Pipelineroot paths. An adversary may execute AddinUtil.exe with uncommon Addinroot/Pipelineroot paths that point to the adversaries Addins.Store payload.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\addinutil.exe") OR (OriginalFileName: "AddInUtil.exe")) AND ((((CommandLine: "*-AddInRoot:*" OR CommandLine: "*-PipelineRoot:*")) AND ((CommandLine: "*\\AppData\\Local\\Temp\\*" OR CommandLine: "*\\Desktop\\*" OR CommandLine: "*\\Downloads\\*" OR CommandLine: "*\\Users\\Public\\*" OR CommandLine: "*\\Windows\\Temp\\*"))) OR ((CommandLine: "*-AddInRoot:.*" OR CommandLine: "*-AddInRoot:\".\"*" OR CommandLine: "*-PipelineRoot:.*" OR CommandLine: "*-PipelineRoot:\".\"*") AND (CurrentDirectory: "*\\AppData\\Local\\Temp\\*" OR CurrentDirectory: "*\\Desktop\\*" OR CurrentDirectory: "*\\Downloads\\*" OR CurrentDirectory: "*\\Users\\Public\\*" OR CurrentDirectory: "*\\Windows\\Temp\\*"))))
