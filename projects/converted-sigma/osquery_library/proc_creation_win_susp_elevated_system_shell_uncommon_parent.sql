-- Title: Elevated System Shell Spawned From Uncommon Parent Location
-- ID: 178e615d-e666-498b-9630-9ed363038101
-- Status: test
-- Level: medium
-- Author: frack113, Tim Shelton (update fp)
-- Date: 2022-12-05
-- Tags: attack.privilege-escalation, attack.execution, attack.t1059
-- Description: Detects when a shell program such as the Windows command prompt or PowerShell is launched with system privileges from a uncommon parent location.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'powershell_ise.EXE' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'Cmd.Exe'))) AND ((User LIKE '%AUTHORI%' OR User LIKE '%AUTORI%') AND LogonId = '0x3e7')) AND NOT ((((ParentImage LIKE '%:\\Program Files (x86)\\%' OR ParentImage LIKE '%:\\Program Files\\%' OR ParentImage LIKE '%:\\ProgramData\\%' OR ParentImage LIKE '%:\\Windows\\System32\\%' OR ParentImage LIKE '%:\\Windows\\SysWOW64\\%' OR ParentImage LIKE '%:\\Windows\\Temp\\%' OR ParentImage LIKE '%:\\Windows\\WinSxS\\%')) OR ((ParentImage = '' OR ParentImage = '-')) OR (NOT ParentImage=*))) AND NOT (((CommandLine LIKE '%:\\WINDOWS\\system32\\cmd.exe /c \"%' AND CurrentDirectory LIKE '%:\\WINDOWS\\Temp\\asgard2-agent\\%') OR (ParentImage LIKE '%:\\IBM\\SpectrumProtect\\webserver\\scripts\\%' AND CommandLine LIKE '%:\\IBM\\SpectrumProtect\\webserver\\scripts\\%') OR (ParentImage="*:\\ManageEngine\\ADManager Plus\\pgsql\\bin\\postgres.exe" AND Image="*\\cmd.exe"))))
