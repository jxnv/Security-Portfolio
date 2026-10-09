// Title: Suspicious Scheduled Task Update
// ID: 614cf376-6651-47c4-9dcc-6b9527f749f4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-05
// Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
// Description: Detects update to a scheduled task event that contain suspicious keywords.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TaskContentNew contains "regsvr32" or TaskContentNew contains "rundll32" or TaskContentNew contains "cmd.exe</Command>" or TaskContentNew contains "cmd</Command>" or TaskContentNew contains "<Arguments>/c " or TaskContentNew contains "<Arguments>/k " or TaskContentNew contains "<Arguments>/r " or TaskContentNew contains "powershell" or TaskContentNew contains "pwsh" or TaskContentNew contains "mshta" or TaskContentNew contains "wscript" or TaskContentNew contains "cscript" or TaskContentNew contains "certutil" or TaskContentNew contains "bitsadmin" or TaskContentNew contains "bash.exe" or TaskContentNew contains "bash " or TaskContentNew contains "scrcons" or TaskContentNew contains "wmic " or TaskContentNew contains "wmic.exe" or TaskContentNew contains "forfiles" or TaskContentNew contains "scriptrunner" or TaskContentNew contains "hh.exe")) and (EventID = 4702) and ((TaskContentNew contains "\\AppData\\Local\\Temp\\" or TaskContentNew contains "\\AppData\\Roaming\\" or TaskContentNew contains "\\Users\\Public\\" or TaskContentNew contains "\\WINDOWS\\Temp\\" or TaskContentNew contains "C:\\Temp\\" or TaskContentNew contains "\\Desktop\\" or TaskContentNew contains "\\Downloads\\" or TaskContentNew contains "\\Temporary Internet" or TaskContentNew contains "C:\\ProgramData\\" or TaskContentNew contains "C:\\Perflogs\\")))
