// Title: ADSI-Cache File Creation By Uncommon Tool
// ID: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb
// Status: test
// Level: medium
// Author: xknow @xknow_infosec, Tim Shelton
// Date: 2019-03-24
// Tags: attack.t1001.003, attack.command-and-control
// Description: Detects the creation of an "Active Directory Schema Cache File" (.sch) file by an uncommon tool.
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetFilename: "*\\Local\\Microsoft\\Windows\\SchCache\\*" AND TargetFilename="*.sch") AND NOT (((((Image="*:\\Program Files\\Cylance\\Desktop\\CylanceSvc.exe" OR Image="*:\\Windows\\CCM\\CcmExec.exe" OR Image="*:\\windows\\system32\\dllhost.exe" OR Image="*:\\Windows\\system32\\dsac.exe" OR Image="*:\\Windows\\system32\\efsui.exe" OR Image="*:\\windows\\system32\\mmc.exe" OR Image="*:\\windows\\system32\\svchost.exe" OR Image="*:\\Windows\\System32\\wbem\\WmiPrvSE.exe" OR Image="*:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe")) OR ((Image: "*:\\Windows\\ccmsetup\\autoupgrade\\ccmsetup*" OR Image: "*:\\Program Files\\SentinelOne\\Sentinel Agent*"))) OR ((Image: "*:\\Program Files\\*" AND Image: "*\\Microsoft Office*") AND Image="*\\OUTLOOK.EXE"))) AND NOT (((Image="*:\\Program Files\\Citrix\\Receiver StoreFront\\Services\\DefaultDomainServices\\Citrix.DeliveryServices.DomainServices.ServiceHost.exe") OR (Image="*\\LANDesk\\LDCLient\\ldapwhoami.exe"))))
