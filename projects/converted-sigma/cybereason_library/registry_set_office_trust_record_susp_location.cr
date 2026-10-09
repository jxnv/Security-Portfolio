// Title: Macro Enabled In A Potentially Suspicious Document
// ID: a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-21
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects registry changes to Office trust records where the path is located in a potentially suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetObject contains "/AppData/Local/Microsoft/Windows/INetCache/" OR TargetObject contains "/AppData/Local/Temp/" OR TargetObject contains "/PerfLogs/" OR TargetObject contains "C:/Users/Public/" OR TargetObject contains "file:///D:/" OR TargetObject contains "file:///E:/")) AND (TargetObject contains "\\Security\\Trusted Documents\\TrustRecords"))
