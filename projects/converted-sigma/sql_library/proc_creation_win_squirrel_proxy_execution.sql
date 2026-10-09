-- Title: Process Proxy Execution Via Squirrel.EXE
-- ID: 45239e6a-b035-4aaf-b339-8ad379fcb67e
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community
-- Date: 2022-06-09
-- Tags: attack.execution, attack.stealth, attack.t1218
-- Description: Detects the usage of the "Squirrel.exe" binary to execute arbitrary processes. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%--processStart%' OR CommandLine ILIKE '%--processStartAndWait%' OR CommandLine ILIKE '%--createShortcut%')) AND ((Image ILIKE '%\\squirrel.exe' OR Image ILIKE '%\\update.exe'))) AND NOT ((((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\Discord\\Update.exe%' AND CommandLine ILIKE '%Discord.exe%') AND (CommandLine ILIKE '%--createShortcut%' OR CommandLine ILIKE '%--processStart%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\GitHubDesktop\\Update.exe%' AND CommandLine ILIKE '%GitHubDesktop.exe%') AND (CommandLine ILIKE '%--createShortcut%' OR CommandLine ILIKE '%--processStartAndWait%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\Microsoft\\Teams\\Update.exe%' AND CommandLine ILIKE '%Teams.exe%') AND (CommandLine ILIKE '%--processStart%' OR CommandLine ILIKE '%--createShortcut%')) OR ((CommandLine ILIKE '%:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\yammerdesktop\\Update.exe%' AND CommandLine ILIKE '%Yammer.exe%') AND (CommandLine ILIKE '%--processStart%' OR CommandLine ILIKE '%--createShortcut%')))))
