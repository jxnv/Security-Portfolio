-- Title: Uncommon AddinUtil.EXE CommandLine Execution
-- ID: 4f2cd9b6-4a17-440f-bb2a-687abb65993a
-- Status: test
-- Level: medium
-- Author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
-- Date: 2023-09-18
-- Tags: attack.stealth, attack.t1218
-- Description: Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) with uncommon Addinroot or Pipelineroot paths. An adversary may execute AddinUtil.exe with uncommon Addinroot/Pipelineroot paths that point to the adversaries Addins.Store payload.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%-AddInRoot:%' OR CommandLine LIKE '%-PipelineRoot:%')) AND ((Image="*\\addinutil.exe") OR (OriginalFileName = 'AddInUtil.exe'))) AND NOT (((CommandLine LIKE '%-AddInRoot:\"C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VSTA%' OR CommandLine LIKE '%-AddInRoot:C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VSTA%' OR CommandLine LIKE '%-PipelineRoot:\"C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VSTA%' OR CommandLine LIKE '%-PipelineRoot:C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VSTA%'))))
