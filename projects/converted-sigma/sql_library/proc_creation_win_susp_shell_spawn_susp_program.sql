-- Title: Windows Shell/Scripting Processes Spawning Suspicious Programs
-- ID: 3a6586ad-127a-4d3b-a677-1e6eacdf8fde
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Tim Shelton
-- Date: 2018-04-06
-- Tags: attack.execution, attack.stealth, attack.t1059.005, attack.t1059.001, attack.t1218
-- Description: Detects suspicious child processes of a Windows shell and scripting processes such as wscript, rundll32, powershell, mshta...etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ParentImage ILIKE '%\\mshta.exe' OR ParentImage ILIKE '%\\powershell.exe' OR ParentImage ILIKE '%\\pwsh.exe' OR ParentImage ILIKE '%\\rundll32.exe' OR ParentImage ILIKE '%\\cscript.exe' OR ParentImage ILIKE '%\\wscript.exe' OR ParentImage ILIKE '%\\wmiprvse.exe' OR ParentImage ILIKE '%\\regsvr32.exe') AND (Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\nslookup.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\mshta.exe')) AND NOT ((((ParentCommandLine ILIKE '%\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\setup-scheduledtask.ps1%' OR ParentCommandLine ILIKE '%\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\set-selfhealing.ps1%' OR ParentCommandLine ILIKE '%\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\check-workspacehealth.ps1%' OR ParentCommandLine ILIKE '%\\nessus_%')) OR (CurrentDirectory ILIKE '%\\ccmcache\\%') OR (CommandLine ILIKE '%\\nessus_%') OR (ParentImage ILIKE '%\\mshta.exe' AND Image ILIKE '%\\mshta.exe' AND (ParentCommandLine ILIKE '%C:\\MEM_Configmgr_%' AND ParentCommandLine ILIKE '%\\splash.hta%' AND ParentCommandLine ILIKE '%{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}%') AND (CommandLine ILIKE '%C:\\MEM_Configmgr_%' AND CommandLine ILIKE '%\\SMSSETUP\\BIN\\%' AND CommandLine ILIKE '%\\autorun.hta%' AND CommandLine ILIKE '%{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}%')))))
