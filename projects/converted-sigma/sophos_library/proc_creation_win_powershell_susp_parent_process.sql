-- Title: Suspicious PowerShell Parent Process
-- ID: 754ed792-634f-40ae-b3bc-e0448d33f695
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, Harish Segar
-- Date: 2020-03-20
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects a suspicious or uncommon parent processes of PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%tomcat%') OR ((ParentImage ILIKE '%\\amigo.exe' OR ParentImage ILIKE '%\\browser.exe' OR ParentImage ILIKE '%\\chrome.exe' OR ParentImage ILIKE '%\\firefox.exe' OR ParentImage ILIKE '%\\httpd.exe' OR ParentImage ILIKE '%\\iexplore.exe' OR ParentImage ILIKE '%\\jbosssvc.exe' OR ParentImage ILIKE '%\\microsoftedge.exe' OR ParentImage ILIKE '%\\microsoftedgecp.exe' OR ParentImage ILIKE '%\\MicrosoftEdgeSH.exe' OR ParentImage ILIKE '%\\mshta.exe' OR ParentImage ILIKE '%\\nginx.exe' OR ParentImage ILIKE '%\\outlook.exe' OR ParentImage ILIKE '%\\php-cgi.exe' OR ParentImage ILIKE '%\\regsvr32.exe' OR ParentImage ILIKE '%\\rundll32.exe' OR ParentImage ILIKE '%\\safari.exe' OR ParentImage ILIKE '%\\services.exe' OR ParentImage ILIKE '%\\sqlagent.exe' OR ParentImage ILIKE '%\\sqlserver.exe' OR ParentImage ILIKE '%\\sqlservr.exe' OR ParentImage ILIKE '%\\vivaldi.exe' OR ParentImage ILIKE '%\\w3wp.exe'))) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((CommandLine ILIKE '%/c powershell%' OR CommandLine ILIKE '%/c pwsh%')) OR (Description = 'Windows PowerShell') OR (Product = 'PowerShell Core 6') OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
