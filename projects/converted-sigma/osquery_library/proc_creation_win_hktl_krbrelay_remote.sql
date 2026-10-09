-- Title: HackTool - RemoteKrbRelay Execution
-- ID: a7664b14-75fb-4a50-a223-cb9bc0afbacf
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-06-27
-- Tags: attack.credential-access, attack.t1558.003
-- Description: Detects the use of RemoteKrbRelay, a Kerberos relaying tool via CommandLine flags and PE metadata.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\RemoteKrbRelay.exe") OR (OriginalFileName = 'RemoteKrbRelay.exe')) OR ((CommandLine LIKE '% -clsid %' AND CommandLine LIKE '% -target %' AND CommandLine LIKE '% -victim %')) OR ((CommandLine LIKE '%-rbcd %') AND ((CommandLine LIKE '%-cn %' OR CommandLine LIKE '%--computername %'))) OR (CommandLine LIKE '%-chp %' AND (CommandLine LIKE '%-chpPass %' AND CommandLine LIKE '%-chpUser %')) OR ((CommandLine LIKE '%-addgroupmember %' AND CommandLine LIKE '%-group %' AND CommandLine LIKE '%-groupuser %')) OR ((CommandLine LIKE '%-smb %' AND CommandLine LIKE '%--smbkeyword %') AND (CommandLine LIKE '%interactive%' OR CommandLine LIKE '%secrets%' OR CommandLine LIKE '%service-add%')))
