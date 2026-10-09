// Title: HackTool - RemoteKrbRelay Execution
// ID: a7664b14-75fb-4a50-a223-cb9bc0afbacf
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-06-27
// Tags: attack.credential-access, attack.t1558.003
// Description: Detects the use of RemoteKrbRelay, a Kerberos relaying tool via CommandLine flags and PE metadata.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\RemoteKrbRelay.exe") OR (OriginalFileName == "RemoteKrbRelay.exe")) OR ((CommandLine contains " -clsid " AND CommandLine contains " -target " AND CommandLine contains " -victim ")) OR ((CommandLine contains "-rbcd ") AND ((CommandLine contains "-cn " OR CommandLine contains "--computername "))) OR (CommandLine contains "-chp " AND (CommandLine contains "-chpPass " AND CommandLine contains "-chpUser ")) OR ((CommandLine contains "-addgroupmember " AND CommandLine contains "-group " AND CommandLine contains "-groupuser ")) OR ((CommandLine contains "-smb " AND CommandLine contains "--smbkeyword ") AND (CommandLine contains "interactive" OR CommandLine contains "secrets" OR CommandLine contains "service-add")))
