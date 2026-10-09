-- Title: HackTool - Rubeus Execution
-- ID: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
-- Status: stable
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-12-19
-- Tags: attack.credential-access, attack.t1003, attack.t1558.003, attack.lateral-movement, attack.t1550.003
-- Description: Detects the execution of the hacktool Rubeus via PE information of command line parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\Rubeus.exe') OR (OriginalFileName = 'Rubeus.exe') OR (Description = 'Rubeus') OR ((CommandLine ILIKE '%asreproast %' OR CommandLine ILIKE '%dump /service:krbtgt %' OR CommandLine ILIKE '%dump /luid:0x%' OR CommandLine ILIKE '%kerberoast %' OR CommandLine ILIKE '%createnetonly /program:%' OR CommandLine ILIKE '%ptt /ticket:%' OR CommandLine ILIKE '%/impersonateuser:%' OR CommandLine ILIKE '%renew /ticket:%' OR CommandLine ILIKE '%asktgt /user:%' OR CommandLine ILIKE '%harvest /interval:%' OR CommandLine ILIKE '%s4u /user:%' OR CommandLine ILIKE '%s4u /ticket:%' OR CommandLine ILIKE '%hash /password:%' OR CommandLine ILIKE '%golden /aes256:%' OR CommandLine ILIKE '%silver /user:%')))
