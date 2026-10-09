-- Title: Suspicious AddinUtil.EXE CommandLine Execution
-- ID: 631b22a4-70f4-4e2f-9ea8-42f84d9df6d8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
-- Date: 2023-09-18
-- Tags: attack.stealth, attack.t1218
-- Description: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) with suspicious Addinroot or Pipelineroot paths. An adversary may execute AddinUtil.exe with uncommon Addinroot/Pipelineroot paths that point to the adversaries Addins.Store payload.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\addinutil.exe") OR (OriginalFileName = 'AddInUtil.exe')) AND ((((CommandLine LIKE '%-AddInRoot:%' OR CommandLine LIKE '%-PipelineRoot:%')) AND ((CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Downloads\\%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%\\Windows\\Temp\\%'))) OR ((CommandLine LIKE '%-AddInRoot:.%' OR CommandLine LIKE '%-AddInRoot:\".\"%' OR CommandLine LIKE '%-PipelineRoot:.%' OR CommandLine LIKE '%-PipelineRoot:\".\"%') AND (CurrentDirectory LIKE '%\\AppData\\Local\\Temp\\%' OR CurrentDirectory LIKE '%\\Desktop\\%' OR CurrentDirectory LIKE '%\\Downloads\\%' OR CurrentDirectory LIKE '%\\Users\\Public\\%' OR CurrentDirectory LIKE '%\\Windows\\Temp\\%'))))
