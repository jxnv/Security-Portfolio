-- Title: HackTool - SharpMove Tool Execution
-- ID: 055fb54c-a8f4-4aee-bd44-f74cf30a0d9d
-- Status: test
-- Level: high
-- Author: Luca Di Bartolomeo (CrimpSec)
-- Date: 2024-01-29
-- Tags: attack.lateral-movement, attack.t1021.002
-- Description: Detects the execution of SharpMove, a .NET utility performing multiple tasks such as "Task Creation", "SCM" query, VBScript execution using WMI via its PE metadata and command line options.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\SharpMove.exe") OR (OriginalFileName = 'SharpMove.exe')) OR (((CommandLine LIKE '%action=create%' OR CommandLine LIKE '%action=dcom%' OR CommandLine LIKE '%action=executevbs%' OR CommandLine LIKE '%action=hijackdcom%' OR CommandLine LIKE '%action=modschtask%' OR CommandLine LIKE '%action=modsvc%' OR CommandLine LIKE '%action=query%' OR CommandLine LIKE '%action=scm%' OR CommandLine LIKE '%action=startservice%' OR CommandLine LIKE '%action=taskscheduler%')) AND (CommandLine LIKE '%computername=%')))
