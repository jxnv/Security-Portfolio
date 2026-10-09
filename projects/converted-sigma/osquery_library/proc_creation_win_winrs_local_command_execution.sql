-- Title: Winrs Local Command Execution
-- ID: bcfece3d-56fe-4545-9931-3b8e92927db1
-- Status: experimental
-- Level: high
-- Author: Liran Ravich, Nasreddine Bencherchali
-- Date: 2025-10-22
-- Tags: attack.lateral-movement, attack.stealth, attack.t1021.006, attack.t1218
-- Description: Detects the execution of Winrs.exe where it is used to execute commands locally.
-- Commands executed this way are launched under Winrshost.exe and can represent proxy execution used for defense evasion or lateral movement.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\winrs.exe") OR (OriginalFileName = 'winrs.exe')) AND ((CommandLine LIKE '%/r:localhost%' OR CommandLine LIKE '%-r:localhost%' OR CommandLine LIKE '%/r:127.0.0.1%' OR CommandLine LIKE '%-r:127.0.0.1%' OR CommandLine LIKE '%/r:[::1]%' OR CommandLine LIKE '%-r:[::1]%' OR CommandLine LIKE '%/remote:localhost%' OR CommandLine LIKE '%-remote:localhost%' OR CommandLine LIKE '%/remote:127.0.0.1%' OR CommandLine LIKE '%-remote:127.0.0.1%' OR CommandLine LIKE '%/remote:[::1]%' OR CommandLine LIKE '%-remote:[::1]%'))) OR (((Image="*\\winrs.exe") OR (OriginalFileName = 'winrs.exe')) AND NOT (((CommandLine LIKE '%/r:%' OR CommandLine LIKE '%-r:%' OR CommandLine LIKE '%/remote:%' OR CommandLine LIKE '%-remote:%')))))
