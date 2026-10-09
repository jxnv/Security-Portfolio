-- Title: Suspicious File Downloaded From Direct IP Via Certutil.EXE
-- ID: 13e6fe51-d478-4c7e-b0f2-6da9b400a829
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-15
-- Tags: attack.stealth, attack.t1027, attack.command-and-control, attack.t1105
-- Description: Detects the execution of certutil with certain flags that allow the utility to download files from direct IPs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%urlcache %' OR CommandLine LIKE '%verifyctl %' OR CommandLine LIKE '%URL %')) AND ((CommandLine LIKE '%://1%' OR CommandLine LIKE '%://2%' OR CommandLine LIKE '%://3%' OR CommandLine LIKE '%://4%' OR CommandLine LIKE '%://5%' OR CommandLine LIKE '%://6%' OR CommandLine LIKE '%://7%' OR CommandLine LIKE '%://8%' OR CommandLine LIKE '%://9%')) AND ((Image="*\\certutil.exe") OR (OriginalFileName = 'CertUtil.exe'))) AND NOT ((CommandLine LIKE '%://7-%')))
