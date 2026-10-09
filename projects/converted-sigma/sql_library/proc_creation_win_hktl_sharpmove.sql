-- Title: HackTool - SharpMove Tool Execution
-- ID: 055fb54c-a8f4-4aee-bd44-f74cf30a0d9d
-- Status: test
-- Level: high
-- Author: Luca Di Bartolomeo (CrimpSec)
-- Date: 2024-01-29
-- Tags: attack.lateral-movement, attack.t1021.002
-- Description: Detects the execution of SharpMove, a .NET utility performing multiple tasks such as "Task Creation", "SCM" query, VBScript execution using WMI via its PE metadata and command line options.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\SharpMove.exe') OR (OriginalFileName = 'SharpMove.exe')) OR (((CommandLine ILIKE '%action=create%' OR CommandLine ILIKE '%action=dcom%' OR CommandLine ILIKE '%action=executevbs%' OR CommandLine ILIKE '%action=hijackdcom%' OR CommandLine ILIKE '%action=modschtask%' OR CommandLine ILIKE '%action=modsvc%' OR CommandLine ILIKE '%action=query%' OR CommandLine ILIKE '%action=scm%' OR CommandLine ILIKE '%action=startservice%' OR CommandLine ILIKE '%action=taskscheduler%')) AND (CommandLine ILIKE '%computername=%')))
