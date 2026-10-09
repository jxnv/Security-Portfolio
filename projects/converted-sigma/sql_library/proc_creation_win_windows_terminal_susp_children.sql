-- Title: Suspicious WindowsTerminal Child Processes
-- ID: 8de89e52-f6e1-4b5b-afd1-41ecfa300d48
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-25
-- Tags: attack.execution, attack.persistence
-- Description: Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((ParentImage ILIKE '%\\WindowsTerminal.exe' OR ParentImage ILIKE '%\\wt.exe')) AND (((Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\csc.exe')) OR ((Image ILIKE '%C:\\Users\\Public\\%' OR Image ILIKE '%\\Downloads\\%' OR Image ILIKE '%\\Desktop\\%' OR Image ILIKE '%\\AppData\\Local\\Temp\\%' OR Image ILIKE '%\\Windows\\TEMP\\%')) OR ((CommandLine ILIKE '% iex %' OR CommandLine ILIKE '% icm%' OR CommandLine ILIKE '%Invoke-%' OR CommandLine ILIKE '%Import-Module %' OR CommandLine ILIKE '%ipmo %' OR CommandLine ILIKE '%DownloadString(%' OR CommandLine ILIKE '% /c %' OR CommandLine ILIKE '% /k %' OR CommandLine ILIKE '% /r %')))) AND NOT ((((CommandLine ILIKE '%Import-Module%' AND CommandLine ILIKE '%Microsoft.VisualStudio.DevShell.dll%' AND CommandLine ILIKE '%Enter-VsDevShell%')) OR ((CommandLine ILIKE '%\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal_%' AND CommandLine ILIKE '%\\LocalState\\settings.json%')) OR ((CommandLine ILIKE '%C:\\Program Files\\Microsoft Visual Studio\\%' AND CommandLine ILIKE '%\\Common7\\Tools\\VsDevCmd.bat%')))))
