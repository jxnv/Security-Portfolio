// Title: New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application
// ID: 9e2575e7-2cb9-4da1-adc8-ed94221dca5e
// Status: test
// Level: high
// Author: frack113
// Date: 2023-02-26
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Detects the addition of a new rule to the Windows Firewall exception list for an application located in a potentially suspicious location.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((EventID = 2004 or EventID = 2071 or EventID = 2097) and (ApplicationPath contains ":\\PerfLogs\\" or ApplicationPath contains ":\\Temp\\" or ApplicationPath contains ":\\Tmp\\" or ApplicationPath contains ":\\Users\\Public\\" or ApplicationPath contains ":\\Windows\\Tasks\\" or ApplicationPath contains ":\\Windows\\Temp\\" or ApplicationPath contains "\\AppData\\Local\\Temp\\")) and not ((Action = 2)))
