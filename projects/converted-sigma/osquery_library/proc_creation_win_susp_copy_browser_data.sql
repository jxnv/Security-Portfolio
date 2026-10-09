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

SELECT * FROM processes WHERE ((((CommandLine LIKE '%copy-item%' OR CommandLine LIKE '%copy %' OR CommandLine LIKE '%cpi %' OR CommandLine LIKE '% cp %' OR CommandLine LIKE '%move %' OR CommandLine LIKE '%move-item%' OR CommandLine LIKE '% mi %' OR CommandLine LIKE '% mv %')) OR ((Image="*\\esentutl.exe" OR Image="*\\xcopy.exe" OR Image="*\\robocopy.exe")) OR ((OriginalFileName = 'esentutl.exe' OR OriginalFileName = 'XCOPY.EXE' OR OriginalFileName = 'robocopy.exe'))) AND ((CommandLine LIKE '%\\Amigo\\User Data%' OR CommandLine LIKE '%\\BraveSoftware\\Brave-Browser\\User Data%' OR CommandLine LIKE '%\\CentBrowser\\User Data%' OR CommandLine LIKE '%\\Chromium\\User Data%' OR CommandLine LIKE '%\\CocCoc\\Browser\\User Data%' OR CommandLine LIKE '%\\Comodo\\Dragon\\User Data%' OR CommandLine LIKE '%\\Elements Browser\\User Data%' OR CommandLine LIKE '%\\Epic Privacy Browser\\User Data%' OR CommandLine LIKE '%\\Google\\Chrome Beta\\User Data%' OR CommandLine LIKE '%\\Google\\Chrome SxS\\User Data%' OR CommandLine LIKE '%\\Google\\Chrome\\User Data\\%' OR CommandLine LIKE '%\\Kometa\\User Data%' OR CommandLine LIKE '%\\Maxthon5\\Users%' OR CommandLine LIKE '%\\Microsoft\\Edge\\User Data%' OR CommandLine LIKE '%\\Mozilla\\Firefox\\Profiles%' OR CommandLine LIKE '%\\Nichrome\\User Data%' OR CommandLine LIKE '%\\Opera Software\\Opera GX Stable\\%' OR CommandLine LIKE '%\\Opera Software\\Opera Neon\\User Data%' OR CommandLine LIKE '%\\Opera Software\\Opera Stable\\%' OR CommandLine LIKE '%\\Orbitum\\User Data%' OR CommandLine LIKE '%\\QIP Surf\\User Data%' OR CommandLine LIKE '%\\Sputnik\\User Data%' OR CommandLine LIKE '%\\Torch\\User Data%' OR CommandLine LIKE '%\\uCozMedia\\Uran\\User Data%' OR CommandLine LIKE '%\\Vivaldi\\User Data%')))
