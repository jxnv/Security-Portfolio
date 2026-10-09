-- Title: Indirect Inline Command Execution Via Bash.EXE
-- ID: 5edc2273-c26f-406c-83f3-f4d948e740dd
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-11-24
-- Tags: attack.stealth, attack.t1202
-- Description: Detects execution of Microsoft bash launcher with the "-c" flag.
-- This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '% -c %') AND (((Image="*:\\Windows\\System32\\bash.exe" OR Image="*:\\Windows\\SysWOW64\\bash.exe")) OR (OriginalFileName = 'Bash.exe')))
