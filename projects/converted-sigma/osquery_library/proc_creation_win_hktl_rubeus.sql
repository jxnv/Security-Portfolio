-- Title: HackTool - Rubeus Execution
-- ID: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
-- Status: stable
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-12-19
-- Tags: attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003
-- Description: Detects the execution of the hacktool Rubeus via PE information of command line parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\Rubeus.exe") OR (OriginalFileName = 'Rubeus.exe') OR (Description = 'Rubeus') OR ((CommandLine LIKE '%asreproast %' OR CommandLine LIKE '%dump /service:krbtgt %' OR CommandLine LIKE '%dump /luid:0x%' OR CommandLine LIKE '%kerberoast %' OR CommandLine LIKE '%createnetonly /program:%' OR CommandLine LIKE '%ptt /ticket:%' OR CommandLine LIKE '%/impersonateuser:%' OR CommandLine LIKE '%renew /ticket:%' OR CommandLine LIKE '%asktgt /user:%' OR CommandLine LIKE '%harvest /interval:%' OR CommandLine LIKE '%s4u /user:%' OR CommandLine LIKE '%s4u /ticket:%' OR CommandLine LIKE '%hash /password:%' OR CommandLine LIKE '%golden /aes256:%' OR CommandLine LIKE '%silver /user:%')))
