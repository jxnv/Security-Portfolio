-- Title: File Download Via Bitsadmin To A Suspicious Target Folder
-- ID: 2ddef153-167b-4e89-86b6-757a9e65dcac
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003, attack.command-and-control, attack.t1105
-- Description: Detects usage of bitsadmin downloading a file to a suspicious target folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% /transfer %' OR CommandLine LIKE '% /create %' OR CommandLine LIKE '% /addfile %')) AND ((CommandLine LIKE '%:\\Perflogs%' OR CommandLine LIKE '%:\\ProgramData\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\%' OR CommandLine LIKE '%\\$Recycle.Bin\\%' OR CommandLine LIKE '%\\AppData\\Local\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\%' OR CommandLine LIKE '%\\Contacts\\%' OR CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Favorites\\%' OR CommandLine LIKE '%\\Favourites\\%' OR CommandLine LIKE '%\\inetpub\\wwwroot\\%' OR CommandLine LIKE '%\\Music\\%' OR CommandLine LIKE '%\\Pictures\\%' OR CommandLine LIKE '%\\Start Menu\\Programs\\Startup\\%' OR CommandLine LIKE '%\\Users\\Default\\%' OR CommandLine LIKE '%\\Videos\\%' OR CommandLine LIKE '%%ProgramData%%' OR CommandLine LIKE '%%public%%' OR CommandLine LIKE '%%temp%%' OR CommandLine LIKE '%%tmp%%')) AND ((Image="*\\bitsadmin.exe") OR (OriginalFileName = 'bitsadmin.exe')))
