-- Title: Suspicious Debugger Registration Cmdline
-- ID: ae215552-081e-44c7-805f-be16f975c8a2
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
-- Date: 2019-09-06
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.008
-- Description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%\\CurrentVersion\\Image File Execution Options\\%') AND ((CommandLine ILIKE '%sethc.exe%' OR CommandLine ILIKE '%utilman.exe%' OR CommandLine ILIKE '%osk.exe%' OR CommandLine ILIKE '%magnify.exe%' OR CommandLine ILIKE '%narrator.exe%' OR CommandLine ILIKE '%displayswitch.exe%' OR CommandLine ILIKE '%atbroker.exe%' OR CommandLine ILIKE '%HelpPane.exe%')))
