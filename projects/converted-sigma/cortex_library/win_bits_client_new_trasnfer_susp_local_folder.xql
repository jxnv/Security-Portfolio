// Title: BITS Transfer Job Download To Potential Suspicious Folder
// ID: f8a56cb7-a363-44ed-a82f-5926bb44cd05
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-28
// Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
// Description: Detects new BITS transfer job where the LocalName/Saved file is stored in a potentially suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 16403 and (LocalName contains "\\Desktop\\" or LocalName contains "C:\\Users\\Public\\" or LocalName contains "C:\\PerfLogs\\"))
