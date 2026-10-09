-- Title: ADSI-Cache File Creation By Uncommon Tool
-- ID: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb
-- Status: test
-- Level: medium
-- Author: xknow @xknow_infosec, Tim Shelton
-- Date: 2019-03-24
-- Tags: attack.t1001.003, attack.command-and-control
-- Description: Detects the creation of an "Active Directory Schema Cache File" (.sch) file by an uncommon tool.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%\\Local\\Microsoft\\Windows\\SchCache\\%' AND TargetFilename ILIKE '%.sch') AND NOT (((((Image ILIKE '%:\\Program Files\\Cylance\\Desktop\\CylanceSvc.exe' OR Image ILIKE '%:\\Windows\\CCM\\CcmExec.exe' OR Image ILIKE '%:\\windows\\system32\\dllhost.exe' OR Image ILIKE '%:\\Windows\\system32\\dsac.exe' OR Image ILIKE '%:\\Windows\\system32\\efsui.exe' OR Image ILIKE '%:\\windows\\system32\\mmc.exe' OR Image ILIKE '%:\\windows\\system32\\svchost.exe' OR Image ILIKE '%:\\Windows\\System32\\wbem\\WmiPrvSE.exe' OR Image ILIKE '%:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe')) OR ((Image ILIKE '%:\\Windows\\ccmsetup\\autoupgrade\\ccmsetup%' OR Image ILIKE '%:\\Program Files\\SentinelOne\\Sentinel Agent%'))) OR ((Image ILIKE '%:\\Program Files\\%' AND Image ILIKE '%\\Microsoft Office%') AND Image ILIKE '%\\OUTLOOK.EXE'))) AND NOT (((Image ILIKE '%:\\Program Files\\Citrix\\Receiver StoreFront\\Services\\DefaultDomainServices\\Citrix.DeliveryServices.DomainServices.ServiceHost.exe') OR (Image ILIKE '%\\LANDesk\\LDCLient\\ldapwhoami.exe'))))
