-- Title: Suspicious ShellExec_RunDLL Call Via Ordinal
-- ID: 8823e85d-31d8-473e-b7f4-92da070f0fc6
-- Status: test
-- Level: high
-- Author: Swachchhanda Shrawan Poudel
-- Date: 2024-12-01
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects suspicious call to the "ShellExec_RunDLL" exported function of SHELL32.DLL through the ordinal number to launch other commands.
-- Adversary might only use the ordinal number in order to bypass existing detection that alert on usage of ShellExec_RunDLL on CommandLine.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentCommandLine LIKE '%SHELL32.DLL%') AND ((ParentCommandLine LIKE '%#568%' OR ParentCommandLine LIKE '%#570%' OR ParentCommandLine LIKE '%#572%' OR ParentCommandLine LIKE '%#576%'))) AND (((Image="*\\bash.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\curl.exe" OR Image="*\\mshta.exe" OR Image="*\\msiexec.exe" OR Image="*\\msxsl.exe" OR Image="*\\odbcconf.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\regsvr32.exe" OR Image="*\\schtasks.exe" OR Image="*\\wmic.exe" OR Image="*\\wscript.exe")) OR (((ParentCommandLine LIKE '%comspec%' OR ParentCommandLine LIKE '%iex%' OR ParentCommandLine LIKE '%Invoke-%' OR ParentCommandLine LIKE '%msiexec%' OR ParentCommandLine LIKE '%odbcconf%' OR ParentCommandLine LIKE '%regsvr32%')) OR ((ParentCommandLine LIKE '%\\Desktop\\%' OR ParentCommandLine LIKE '%\\ProgramData\\%' OR ParentCommandLine LIKE '%\\Temp\\%' OR ParentCommandLine LIKE '%\\Users\\Public\\%')))))
