-- Title: Suspicious Child Process of Notepad++ Updater - GUP.Exe
-- ID: bb0e87ce-c89f-4857-84fa-095e4483e9cb
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-02-03
-- Tags: attack.collection, attack.credential-access, attack.t1195.002, attack.initial-access, attack.t1557
-- Description: Detects suspicious child process creation by the Notepad++ updater process (gup.exe).
-- This could indicate potential exploitation of the updater component to deliver unwanted malware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\gup.exe") AND (((CommandLine LIKE '%bitsadmin%' OR CommandLine LIKE '%certutil%' OR CommandLine LIKE '%curl%' OR CommandLine LIKE '%finger%' OR CommandLine LIKE '%forfiles%' OR CommandLine LIKE '%regsvr32%' OR CommandLine LIKE '%rundll32%' OR CommandLine LIKE '%wget%')) OR ((Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe"))))
