-- Title: Always Install Elevated MSI Spawned Cmd And Powershell
-- ID: 1e53dd56-8d83-4eb4-a43e-b790a05510aa
-- Status: test
-- Level: medium
-- Author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
-- Date: 2020-10-13
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects Windows Installer service (msiexec.exe) spawning "cmd" or "powershell"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'Cmd.Exe' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((ParentImage ILIKE '%\\Windows\\Installer\\%' AND ParentImage ILIKE '%msi%') AND ParentImage ILIKE '%tmp'))
