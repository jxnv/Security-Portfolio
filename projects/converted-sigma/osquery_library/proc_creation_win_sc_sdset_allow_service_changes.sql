-- Title: Allow Service Access Using Security Descriptor Tampering Via Sc.EXE
-- ID: 6c8fbee5-dee8-49bc-851d-c3142d02aa47
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-28
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
-- Description: Detects suspicious DACL modifications to allow access to a service from a suspicious trustee. This can be used to override access restrictions set by previous ACLs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\sc.exe") OR (OriginalFileName = 'sc.exe')) AND ((CommandLine LIKE '%sdset%' AND CommandLine LIKE '%A;%')) AND ((CommandLine LIKE '%;IU%' OR CommandLine LIKE '%;SU%' OR CommandLine LIKE '%;BA%' OR CommandLine LIKE '%;SY%' OR CommandLine LIKE '%;WD%'))) AND NOT ((ParentImage = 'C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe')))
