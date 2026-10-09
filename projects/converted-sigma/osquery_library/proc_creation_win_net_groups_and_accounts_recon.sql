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

SELECT * FROM processes WHERE ((((Image="*\\net.exe" OR Image="*\\net1.exe")) OR ((OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe'))) AND (((((CommandLine LIKE '%domain admins%' OR CommandLine LIKE '% administrator%' OR CommandLine LIKE '% administrateur%' OR CommandLine LIKE '%enterprise admins%' OR CommandLine LIKE '%Exchange Trusted Subsystem%' OR CommandLine LIKE '%Remote Desktop Users%' OR CommandLine LIKE '%Utilisateurs du Bureau à distance%' OR CommandLine LIKE '%Usuarios de escritorio remoto%' OR CommandLine LIKE '% /do%')) AND ((CommandLine LIKE '% group %' OR CommandLine LIKE '% localgroup %'))) AND NOT ((CommandLine LIKE '% /add%'))) OR ((CommandLine LIKE '% /do%') AND (CommandLine LIKE '% accounts %'))))
