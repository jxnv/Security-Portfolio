// Title: Regsvr32 Execution From Highly Suspicious Location
// ID: 327ff235-94eb-4f06-b9de-aaee571324be
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-26
// Tags: attack.stealth, attack.t1218.010
// Description: Detects execution of regsvr32 where the DLL is located in a highly suspicious locations
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\regsvr32.exe") OR (OriginalFileName == "REGSVR32.EXE")) AND (((CommandLine contains ":\\PerfLogs\\" OR CommandLine contains ":\\Temp\\" OR CommandLine contains "\\Windows\\Registration\\CRMLog" OR CommandLine contains "\\Windows\\System32\\com\\dmp\\" OR CommandLine contains "\\Windows\\System32\\FxsTmp\\" OR CommandLine contains "\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\" OR CommandLine contains "\\Windows\\System32\\spool\\drivers\\color\\" OR CommandLine contains "\\Windows\\System32\\spool\\PRINTERS\\" OR CommandLine contains "\\Windows\\System32\\spool\\SERVERS\\" OR CommandLine contains "\\Windows\\System32\\Tasks_Migrated\\" OR CommandLine contains "\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\" OR CommandLine contains "\\Windows\\SysWOW64\\com\\dmp\\" OR CommandLine contains "\\Windows\\SysWOW64\\FxsTmp\\" OR CommandLine contains "\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\" OR CommandLine contains "\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\" OR CommandLine contains "\\Windows\\Tasks\\" OR CommandLine contains "\\Windows\\Tracing\\")) OR (((CommandLine contains " \"C:\\" OR CommandLine contains " C:\\" OR CommandLine contains " 'C:\\" OR CommandLine contains "D:\\")) AND NOT (((CommandLine contains "C:\\Program Files (x86)\\" OR CommandLine contains "C:\\Program Files\\" OR CommandLine contains "C:\\ProgramData\\" OR CommandLine contains "C:\\Users\\" OR CommandLine contains " C:\\Windows\\" OR CommandLine contains " \"C:\\Windows\\" OR CommandLine contains " 'C:\\Windows\\"))))) AND NOT (((CommandLine == "") OR (NOT CommandLine=*))))
