-- Title: Cmd Launched with Hidden Start Flags to Suspicious Targets
-- ID: 5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d
-- Status: experimental
-- Level: medium
-- Author: Vladan Sekulic, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-01-24
-- Tags: attack.stealth, attack.t1564.003
-- Description: Detects cmd.exe executing commands with the "start" utility using "/b" (no window) or "/min" (minimized) flags.
-- To reduce false positives from standard background tasks, detection is restricted to scenarios where the target is a known script extension or located in suspicious temporary/public directories.
-- This technique was observed in Chaos, DarkSide, and Emotet malware campaigns.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%start %' OR CommandLine LIKE '%start/b%' OR CommandLine LIKE '%start/min%')) AND ((CommandLine LIKE '%/b %' OR CommandLine LIKE '%-b %' OR CommandLine LIKE '%/b\"%' OR CommandLine LIKE '%-b\"%' OR CommandLine LIKE '%/min %' OR CommandLine LIKE '%-min %' OR CommandLine LIKE '%/min\"%' OR CommandLine LIKE '%-min\"%')) AND ((Image="*\\cmd.exe") OR (OriginalFileName = 'Cmd.Exe'))) AND (((CommandLine LIKE '%.bat%' OR CommandLine LIKE '%.cmd%' OR CommandLine LIKE '%.cpl%' OR CommandLine LIKE '%.hta%' OR CommandLine LIKE '%.js%' OR CommandLine LIKE '%.ps1%' OR CommandLine LIKE '%.scr%' OR CommandLine LIKE '%.vbe%' OR CommandLine LIKE '%.vbs%')) OR ((CommandLine LIKE '% -nop %' OR CommandLine LIKE '% -sta %' OR CommandLine LIKE '%.downloadfile(%' OR CommandLine LIKE '%.downloadstring(%' OR CommandLine LIKE '%-noni %' OR CommandLine LIKE '%-w hidden %')) OR ((CommandLine LIKE '%:\\Perflogs\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Users\\Default\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\%' OR CommandLine LIKE '%\\Contacts\\%' OR CommandLine LIKE '%\\Documents\\%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Favorites\\%' OR CommandLine LIKE '%\\Favourites\\%' OR CommandLine LIKE '%\\inetpub\\%' OR CommandLine LIKE '%\\Music\\%' OR CommandLine LIKE '%\\Photos\\%' OR CommandLine LIKE '%\\Temporary Internet\\%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%\\Videos\\%'))))
