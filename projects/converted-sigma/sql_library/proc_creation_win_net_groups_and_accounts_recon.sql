-- Title: Suspicious Group And Account Reconnaissance Activity Using Net.EXE
-- ID: d95de845-b83c-4a9a-8a6a-4fc802ebf6c0
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), omkar72, @svch0st, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2019-01-16
-- Tags: attack.discovery, attack.t1087.001, attack.t1087.002
-- Description: Detects suspicious reconnaissance command line activity on Windows systems using Net.EXE
-- Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe')) OR ((OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe'))) AND (((((CommandLine ILIKE '%domain admins%' OR CommandLine ILIKE '% administrator%' OR CommandLine ILIKE '% administrateur%' OR CommandLine ILIKE '%enterprise admins%' OR CommandLine ILIKE '%Exchange Trusted Subsystem%' OR CommandLine ILIKE '%Remote Desktop Users%' OR CommandLine ILIKE '%Utilisateurs du Bureau à distance%' OR CommandLine ILIKE '%Usuarios de escritorio remoto%' OR CommandLine ILIKE '% /do%')) AND ((CommandLine ILIKE '% group %' OR CommandLine ILIKE '% localgroup %'))) AND NOT ((CommandLine ILIKE '% /add%'))) OR ((CommandLine ILIKE '% /do%') AND (CommandLine ILIKE '% accounts %'))))
