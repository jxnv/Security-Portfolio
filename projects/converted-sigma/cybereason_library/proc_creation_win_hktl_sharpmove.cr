// Title: HackTool - SharpMove Tool Execution
// ID: 055fb54c-a8f4-4aee-bd44-f74cf30a0d9d
// Status: test
// Level: high
// Author: Luca Di Bartolomeo (CrimpSec)
// Date: 2024-01-29
// Tags: attack.lateral-movement, attack.t1021.002
// Description: Detects the execution of SharpMove, a .NET utility performing multiple tasks such as "Task Creation", "SCM" query, VBScript execution using WMI via its PE metadata and command line options.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\SharpMove.exe") OR (OriginalFileName == "SharpMove.exe")) OR (((CommandLine contains "action=create" OR CommandLine contains "action=dcom" OR CommandLine contains "action=executevbs" OR CommandLine contains "action=hijackdcom" OR CommandLine contains "action=modschtask" OR CommandLine contains "action=modsvc" OR CommandLine contains "action=query" OR CommandLine contains "action=scm" OR CommandLine contains "action=startservice" OR CommandLine contains "action=taskscheduler")) AND (CommandLine contains "computername=")))
