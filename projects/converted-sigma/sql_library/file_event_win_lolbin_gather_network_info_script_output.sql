-- Title: GatherNetworkInfo.VBS Reconnaissance Script Output
-- ID: f92a6f1e-a512-4a15-9735-da09e78d7273
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-08
-- Tags: attack.discovery
-- Description: Detects creation of files which are the results of executing the built-in reconnaissance script "C:\Windows\System32\gatherNetworkInfo.vbs".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetFilename ILIKE 'C:\\Windows\\System32\\config%' AND (TargetFilename ILIKE '%\\Hotfixinfo.txt' OR TargetFilename ILIKE '%\\netiostate.txt' OR TargetFilename ILIKE '%\\sysportslog.txt' OR TargetFilename ILIKE '%\\VmSwitchLog.evtx'))
