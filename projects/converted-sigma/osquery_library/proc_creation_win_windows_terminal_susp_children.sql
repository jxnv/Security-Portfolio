-- Title: Suspicious WindowsTerminal Child Processes
-- ID: 8de89e52-f6e1-4b5b-afd1-41ecfa300d48
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-25
-- Tags: attack.execution, attack.persistence
-- Description: Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((ParentImage="*\\WindowsTerminal.exe" OR ParentImage="*\\wt.exe")) AND (((Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\certutil.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe" OR Image="*\\csc.exe")) OR ((Image LIKE '%C:\\Users\\Public\\%' OR Image LIKE '%\\Downloads\\%' OR Image LIKE '%\\Desktop\\%' OR Image LIKE '%\\AppData\\Local\\Temp\\%' OR Image LIKE '%\\Windows\\TEMP\\%')) OR ((CommandLine LIKE '% iex %' OR CommandLine LIKE '% icm%' OR CommandLine LIKE '%Invoke-%' OR CommandLine LIKE '%Import-Module %' OR CommandLine LIKE '%ipmo %' OR CommandLine LIKE '%DownloadString(%' OR CommandLine LIKE '% /c %' OR CommandLine LIKE '% /k %' OR CommandLine LIKE '% /r %')))) AND NOT ((((CommandLine LIKE '%Import-Module%' AND CommandLine LIKE '%Microsoft.VisualStudio.DevShell.dll%' AND CommandLine LIKE '%Enter-VsDevShell%')) OR ((CommandLine LIKE '%\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal_%' AND CommandLine LIKE '%\\LocalState\\settings.json%')) OR ((CommandLine LIKE '%C:\\Program Files\\Microsoft Visual Studio\\%' AND CommandLine LIKE '%\\Common7\\Tools\\VsDevCmd.bat%')))))
