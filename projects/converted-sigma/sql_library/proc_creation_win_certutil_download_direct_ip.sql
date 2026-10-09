-- Title: Suspicious File Downloaded From Direct IP Via Certutil.EXE
-- ID: 13e6fe51-d478-4c7e-b0f2-6da9b400a829
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-15
-- Tags: attack.stealth, attack.t1027, attack.command-and-control, attack.t1105
-- Description: Detects the execution of certutil with certain flags that allow the utility to download files from direct IPs.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%urlcache %' OR CommandLine ILIKE '%verifyctl %' OR CommandLine ILIKE '%URL %')) AND ((CommandLine ILIKE '%://1%' OR CommandLine ILIKE '%://2%' OR CommandLine ILIKE '%://3%' OR CommandLine ILIKE '%://4%' OR CommandLine ILIKE '%://5%' OR CommandLine ILIKE '%://6%' OR CommandLine ILIKE '%://7%' OR CommandLine ILIKE '%://8%' OR CommandLine ILIKE '%://9%')) AND ((Image ILIKE '%\\certutil.exe') OR (OriginalFileName = 'CertUtil.exe'))) AND NOT ((CommandLine ILIKE '%://7-%')))
