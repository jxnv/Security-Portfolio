// Title: Suspicious Scheduled Task Creation
// ID: 3a734d25-df5c-4b99-8034-af1ddb5883a4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-05
// Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
// Description: Detects suspicious scheduled task creation events. Based on attributes such as paths, commands line flags, etc.
// Converted by: Sigma Universal SIEM/EDR CLI

(((TaskContent contains "regsvr32" OR TaskContent contains "rundll32" OR TaskContent contains "cmd.exe</Command>" OR TaskContent contains "cmd</Command>" OR TaskContent contains "<Arguments>/c " OR TaskContent contains "<Arguments>/k " OR TaskContent contains "<Arguments>/r " OR TaskContent contains "powershell" OR TaskContent contains "pwsh" OR TaskContent contains "mshta" OR TaskContent contains "wscript" OR TaskContent contains "cscript" OR TaskContent contains "certutil" OR TaskContent contains "bitsadmin" OR TaskContent contains "bash.exe" OR TaskContent contains "bash " OR TaskContent contains "scrcons" OR TaskContent contains "wmic " OR TaskContent contains "wmic.exe" OR TaskContent contains "forfiles" OR TaskContent contains "scriptrunner" OR TaskContent contains "hh.exe")) AND (EventID == "4698") AND ((TaskContent contains "\\AppData\\Local\\Temp\\" OR TaskContent contains "\\AppData\\Roaming\\" OR TaskContent contains "\\Users\\Public\\" OR TaskContent contains "\\WINDOWS\\Temp\\" OR TaskContent contains "C:\\Temp\\" OR TaskContent contains "\\Desktop\\" OR TaskContent contains "\\Downloads\\" OR TaskContent contains "\\Temporary Internet" OR TaskContent contains "C:\\ProgramData\\" OR TaskContent contains "C:\\Perflogs\\")))
