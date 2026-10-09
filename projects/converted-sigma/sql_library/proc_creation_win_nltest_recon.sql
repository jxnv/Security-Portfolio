-- Title: Potential Recon Activity Via Nltest.EXE
-- ID: 5cc90652-4cbd-4241-aa3b-4b462fa5a248
-- Status: test
-- Level: medium
-- Author: Craig Young, oscd.community, Georg Lauenstein
-- Date: 2021-07-24
-- Tags: attack.discovery, attack.t1016, attack.t1482
-- Description: Detects nltest commands that can be used for information discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\nltest.exe') OR (OriginalFileName = 'nltestrk.exe')) AND (((CommandLine ILIKE '%server%' AND CommandLine ILIKE '%query%')) OR ((CommandLine ILIKE '%/user%' OR CommandLine ILIKE '%all_trusts%' OR CommandLine ILIKE '%dclist:%' OR CommandLine ILIKE '%dnsgetdc:%' OR CommandLine ILIKE '%domain_trusts%' OR CommandLine ILIKE '%dsgetdc:%' OR CommandLine ILIKE '%parentdomain%' OR CommandLine ILIKE '%trusted_domains%'))))
