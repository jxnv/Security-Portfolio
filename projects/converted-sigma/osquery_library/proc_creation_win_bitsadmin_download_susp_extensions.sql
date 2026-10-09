-- Title: File With Suspicious Extension Downloaded Via Bitsadmin
-- ID: 5b80a791-ad9b-4b75-bcc1-ad4e1e89c200
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003, attack.command-and-control, attack.t1105
-- Description: Detects usage of bitsadmin downloading a file with a suspicious extension
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.7z%' OR CommandLine LIKE '%.asax%' OR CommandLine LIKE '%.ashx%' OR CommandLine LIKE '%.asmx%' OR CommandLine LIKE '%.asp%' OR CommandLine LIKE '%.aspx%' OR CommandLine LIKE '%.bat%' OR CommandLine LIKE '%.cfm%' OR CommandLine LIKE '%.cgi%' OR CommandLine LIKE '%.chm%' OR CommandLine LIKE '%.cmd%' OR CommandLine LIKE '%.dll%' OR CommandLine LIKE '%.gif%' OR CommandLine LIKE '%.jpeg%' OR CommandLine LIKE '%.jpg%' OR CommandLine LIKE '%.jsp%' OR CommandLine LIKE '%.jspx%' OR CommandLine LIKE '%.log%' OR CommandLine LIKE '%.png%' OR CommandLine LIKE '%.ps1%' OR CommandLine LIKE '%.psm1%' OR CommandLine LIKE '%.rar%' OR CommandLine LIKE '%.scf%' OR CommandLine LIKE '%.sct%' OR CommandLine LIKE '%.txt%' OR CommandLine LIKE '%.vbe%' OR CommandLine LIKE '%.vbs%' OR CommandLine LIKE '%.war%' OR CommandLine LIKE '%.wsf%' OR CommandLine LIKE '%.wsh%' OR CommandLine LIKE '%.xll%' OR CommandLine LIKE '%.zip%')) AND ((CommandLine LIKE '% /transfer %' OR CommandLine LIKE '% /create %' OR CommandLine LIKE '% /addfile %')) AND ((Image="*\\bitsadmin.exe") OR (OriginalFileName = 'bitsadmin.exe')))
