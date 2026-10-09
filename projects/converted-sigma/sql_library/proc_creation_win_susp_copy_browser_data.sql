-- Title: Potential Browser Data Stealing
-- ID: 47147b5b-9e17-4d76-b8d2-7bac24c5ce1b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-23
-- Tags: attack.credential-access, attack.t1555.003
-- Description: Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
-- Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.
-- Web browsers typically store the credentials in an encrypted format within a credential store.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%copy-item%' OR CommandLine ILIKE '%copy %' OR CommandLine ILIKE '%cpi %' OR CommandLine ILIKE '% cp %' OR CommandLine ILIKE '%move %' OR CommandLine ILIKE '%move-item%' OR CommandLine ILIKE '% mi %' OR CommandLine ILIKE '% mv %')) OR ((Image ILIKE '%\\esentutl.exe' OR Image ILIKE '%\\xcopy.exe' OR Image ILIKE '%\\robocopy.exe')) OR ((OriginalFileName = 'esentutl.exe' OR OriginalFileName = 'XCOPY.EXE' OR OriginalFileName = 'robocopy.exe'))) AND ((CommandLine ILIKE '%\\Amigo\\User Data%' OR CommandLine ILIKE '%\\BraveSoftware\\Brave-Browser\\User Data%' OR CommandLine ILIKE '%\\CentBrowser\\User Data%' OR CommandLine ILIKE '%\\Chromium\\User Data%' OR CommandLine ILIKE '%\\CocCoc\\Browser\\User Data%' OR CommandLine ILIKE '%\\Comodo\\Dragon\\User Data%' OR CommandLine ILIKE '%\\Elements Browser\\User Data%' OR CommandLine ILIKE '%\\Epic Privacy Browser\\User Data%' OR CommandLine ILIKE '%\\Google\\Chrome Beta\\User Data%' OR CommandLine ILIKE '%\\Google\\Chrome SxS\\User Data%' OR CommandLine ILIKE '%\\Google\\Chrome\\User Data\\%' OR CommandLine ILIKE '%\\Kometa\\User Data%' OR CommandLine ILIKE '%\\Maxthon5\\Users%' OR CommandLine ILIKE '%\\Microsoft\\Edge\\User Data%' OR CommandLine ILIKE '%\\Mozilla\\Firefox\\Profiles%' OR CommandLine ILIKE '%\\Nichrome\\User Data%' OR CommandLine ILIKE '%\\Opera Software\\Opera GX Stable\\%' OR CommandLine ILIKE '%\\Opera Software\\Opera Neon\\User Data%' OR CommandLine ILIKE '%\\Opera Software\\Opera Stable\\%' OR CommandLine ILIKE '%\\Orbitum\\User Data%' OR CommandLine ILIKE '%\\QIP Surf\\User Data%' OR CommandLine ILIKE '%\\Sputnik\\User Data%' OR CommandLine ILIKE '%\\Torch\\User Data%' OR CommandLine ILIKE '%\\uCozMedia\\Uran\\User Data%' OR CommandLine ILIKE '%\\Vivaldi\\User Data%')))
