-- Title: Suspicious AddinUtil.EXE CommandLine Execution
-- ID: 631b22a4-70f4-4e2f-9ea8-42f84d9df6d8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
-- Date: 2023-09-18
-- Tags: attack.stealth, attack.t1218
-- Description: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) with suspicious Addinroot or Pipelineroot paths. An adversary may execute AddinUtil.exe with uncommon Addinroot/Pipelineroot paths that point to the adversaries Addins.Store payload.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\addinutil.exe') OR (OriginalFileName = 'AddInUtil.exe')) AND ((((CommandLine ILIKE '%-AddInRoot:%' OR CommandLine ILIKE '%-PipelineRoot:%')) AND ((CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine ILIKE '%\\Desktop\\%' OR CommandLine ILIKE '%\\Downloads\\%' OR CommandLine ILIKE '%\\Users\\Public\\%' OR CommandLine ILIKE '%\\Windows\\Temp\\%'))) OR ((CommandLine ILIKE '%-AddInRoot:.%' OR CommandLine ILIKE '%-AddInRoot:\".\"%' OR CommandLine ILIKE '%-PipelineRoot:.%' OR CommandLine ILIKE '%-PipelineRoot:\".\"%') AND (CurrentDirectory ILIKE '%\\AppData\\Local\\Temp\\%' OR CurrentDirectory ILIKE '%\\Desktop\\%' OR CurrentDirectory ILIKE '%\\Downloads\\%' OR CurrentDirectory ILIKE '%\\Users\\Public\\%' OR CurrentDirectory ILIKE '%\\Windows\\Temp\\%'))))
