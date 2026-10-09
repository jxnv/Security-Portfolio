-- Title: Suspicious Use of CSharp Interactive Console
-- ID: a9e416a8-e613-4f8b-88b8-a7d1d1af2f61
-- Status: test
-- Level: high
-- Author: Michael R. (@nahamike01)
-- Date: 2020-03-08
-- Tags: attack.execution, attack.stealth, attack.t1127
-- Description: Detects the execution of CSharp interactive console by PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\csi.exe' AND (ParentImage ILIKE '%\\powershell.exe' OR ParentImage ILIKE '%\\pwsh.exe' OR ParentImage ILIKE '%\\powershell_ise.exe') AND OriginalFileName = 'csi.exe')
