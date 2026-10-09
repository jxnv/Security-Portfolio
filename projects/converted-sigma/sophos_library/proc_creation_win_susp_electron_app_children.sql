-- Title: Suspicious Electron Application Child Processes
-- ID: f26eb764-fd89-464b-85e2-dc4a8e6e77b8
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-21
-- Tags: attack.execution
-- Description: Detects suspicious child processes of electron apps (teams, discord, slack, etc.). This could be a potential sign of ".asar" file tampering (See reference section for more information) or binary execution proxy through specific CLI arguments (see related rule)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%\\chrome.exe' OR ParentImage ILIKE '%\\discord.exe' OR ParentImage ILIKE '%\\GitHubDesktop.exe' OR ParentImage ILIKE '%\\keybase.exe' OR ParentImage ILIKE '%\\msedge.exe' OR ParentImage ILIKE '%\\msedgewebview2.exe' OR ParentImage ILIKE '%\\msteams.exe' OR ParentImage ILIKE '%\\slack.exe' OR ParentImage ILIKE '%\\teams.exe')) AND (((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\whoami.exe' OR Image ILIKE '%\\wscript.exe')) OR ((Image ILIKE '%:\\ProgramData\\%' OR Image ILIKE '%:\\Temp\\%' OR Image ILIKE '%\\AppData\\Local\\Temp\\%' OR Image ILIKE '%\\Users\\Public\\%' OR Image ILIKE '%\\Windows\\Temp\\%'))) AND NOT ((ParentImage ILIKE '%\\Discord.exe' AND Image ILIKE '%\\cmd.exe' AND CommandLine ILIKE '%\\NVSMI\\nvidia-smi.exe%')))
