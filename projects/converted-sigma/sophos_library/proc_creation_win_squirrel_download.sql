-- Title: Arbitrary File Download Via Squirrel.EXE
-- ID: 1e75c1cc-c5d4-42aa-ac3d-91b0b68b3b4c
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community
-- Date: 2022-06-09
-- Tags: attack.execution, attack.stealth, attack.t1218
-- Description: Detects the usage of the "Squirrel.exe" to download arbitrary files. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% --download %' OR CommandLine ILIKE '% --update %' OR CommandLine ILIKE '% --updateRollback=%')) AND (CommandLine ILIKE '%http%') AND ((Image ILIKE '%\\squirrel.exe' OR Image ILIKE '%\\update.exe')))
