// Title: Dump Ntds.dit To Suspicious Location
// ID: 94dc4390-6b7c-4784-8ffc-335334404650
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-14
// Tags: attack.execution
// Description: Detects potential abuse of ntdsutil to dump ntds.dit database to a suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

(((Data contains ":\\ntds.dit" OR Data contains "\\Appdata\\" OR Data contains "\\Desktop\\" OR Data contains "\\Downloads\\" OR Data contains "\\Perflogs\\" OR Data contains "\\Temp\\" OR Data contains "\\Users\\Public\\")) AND (Provider_Name == "ESENT" AND EventID == "325" AND Data contains "ntds.dit"))
