-- Title: Change PowerShell Policies to an Insecure Level
-- ID: 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-11-01
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects changing the PowerShell script execution policy to a potentially insecure level using the "-ExecutionPolicy" flag.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((((OriginalFileName = 'powershell_ise.exe' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')) OR ((Image ILIKE '%\\powershell_ise.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe'))) AND ((CommandLine ILIKE '%Bypass%' OR CommandLine ILIKE '%Unrestricted%')) AND ((CommandLine ILIKE '%-executionpolicy %' OR CommandLine ILIKE '% -ep %' OR CommandLine ILIKE '% -exec %'))) AND NOT (((ParentImage = 'C:\\Windows\\SysWOW64\\msiexec.exe' OR ParentImage = 'C:\\Windows\\System32\\msiexec.exe') AND (CommandLine ILIKE '%-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files\\PowerShell\\7\\%' OR CommandLine ILIKE '%-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files (x86)\\PowerShell\\7\\%'))) AND NOT (((ParentImage ILIKE '%C:\\Program Files\\Avast Software\\Avast\\%' OR ParentImage ILIKE '%C:\\Program Files (x86)\\Avast Software\\Avast\\%' OR ParentImage ILIKE '%\\instup.exe%') AND (CommandLine ILIKE '%-ExecutionPolicy ByPass -File \"C:\\Program Files\\Avast Software\\Avast%' OR CommandLine ILIKE '%-ExecutionPolicy ByPass -File \"C:\\Program Files (x86)\\Avast Software\\Avast\\%'))))
