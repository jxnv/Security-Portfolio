-- Title: WSL Child Process Anomaly
-- ID: 2267fe65-0681-42ad-9a6d-46553d3f3480
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-23
-- Tags: attack.execution, attack.stealth, attack.t1218, attack.t1202
-- Description: Detects uncommon or suspicious child processes spawning from a WSL process. This could indicate an attempt to evade parent/child relationship detections or persistence attempts via cron using WSL
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentImage="*\\wsl.exe" OR ParentImage="*\\wslhost.exe")) AND (((Image="*\\calc.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wscript.exe")) OR ((Image LIKE '%\\AppData\\Local\\Temp\\%' OR Image LIKE '%C:\\Users\\Public\\%' OR Image LIKE '%C:\\Windows\\Temp\\%' OR Image LIKE '%C:\\Temp\\%' OR Image LIKE '%\\Downloads\\%' OR Image LIKE '%\\Desktop\\%'))))
