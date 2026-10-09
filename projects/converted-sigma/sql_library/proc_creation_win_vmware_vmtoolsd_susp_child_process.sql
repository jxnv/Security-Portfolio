-- Title: VMToolsd Suspicious Child Process
-- ID: 5687f942-867b-4578-ade7-1e341c46e99a
-- Status: test
-- Level: high
-- Author: bohops, Bhabesh Raj
-- Date: 2021-10-08
-- Tags: attack.execution, attack.persistence, attack.t1059
-- Description: Detects suspicious child process creations of VMware Tools process which may indicate persistence setup
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((((Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\wscript.exe')) OR ((OriginalFileName = 'Cmd.Exe' OR OriginalFileName = 'cscript.exe' OR OriginalFileName = 'MSHTA.EXE' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'REGSVR32.EXE' OR OriginalFileName = 'RUNDLL32.EXE' OR OriginalFileName = 'wscript.exe'))) AND (ParentImage ILIKE '%\\vmtoolsd.exe')) AND NOT (((Image ILIKE '%\\cmd.exe' AND CommandLine = '') OR (Image ILIKE '%\\cmd.exe' AND CommandLine IS NULL) OR (Image ILIKE '%\\cmd.exe' AND (CommandLine ILIKE '%\\VMware\\VMware Tools\\poweron-vm-default.bat%' OR CommandLine ILIKE '%\\VMware\\VMware Tools\\poweroff-vm-default.bat%' OR CommandLine ILIKE '%\\VMware\\VMware Tools\\resume-vm-default.bat%' OR CommandLine ILIKE '%\\VMware\\VMware Tools\\suspend-vm-default.bat%')))))
