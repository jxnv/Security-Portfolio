-- Title: Suspicious Download From File-Sharing Website Via Bitsadmin
-- ID: 8518ed3d-f7c9-4601-a26c-f361a4256a0c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003, attack.command-and-control, attack.t1105
-- Description: Detects usage of bitsadmin downloading a file from a suspicious domain
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.githubusercontent.com%' OR CommandLine LIKE '%0x0.st%' OR CommandLine LIKE '%anonfiles.com%' OR CommandLine LIKE '%bashupload.com%' OR CommandLine LIKE '%cdn.discordapp.com%' OR CommandLine LIKE '%chunk.io%' OR CommandLine LIKE '%ddns.net%' OR CommandLine LIKE '%dl.dropboxusercontent.com%' OR CommandLine LIKE '%ghostbin.co%' OR CommandLine LIKE '%github.com%' OR CommandLine LIKE '%glitch.me%' OR CommandLine LIKE '%gofile.io%' OR CommandLine LIKE '%hastebin.com%' OR CommandLine LIKE '%mediafire.com%' OR CommandLine LIKE '%mega.nz%' OR CommandLine LIKE '%onrender.com%' OR CommandLine LIKE '%pages.dev%' OR CommandLine LIKE '%paste.ee%' OR CommandLine LIKE '%pastebin.com%' OR CommandLine LIKE '%pastebin.pl%' OR CommandLine LIKE '%pastetext.net%' OR CommandLine LIKE '%privatlab.com%' OR CommandLine LIKE '%privatlab.net%' OR CommandLine LIKE '%send.exploit.in%' OR CommandLine LIKE '%sendspace.com%' OR CommandLine LIKE '%storage.googleapis.com%' OR CommandLine LIKE '%storjshare.io%' OR CommandLine LIKE '%supabase.co%' OR CommandLine LIKE '%temp.sh%' OR CommandLine LIKE '%transfer.sh%' OR CommandLine LIKE '%trycloudflare.com%' OR CommandLine LIKE '%ufile.io%' OR CommandLine LIKE '%w3spaces.com%' OR CommandLine LIKE '%workers.dev%' OR CommandLine LIKE '%x0.at%')) AND ((CommandLine LIKE '% /transfer %' OR CommandLine LIKE '% /create %' OR CommandLine LIKE '% /addfile %')) AND ((Image="*\\bitsadmin.exe") OR (OriginalFileName = 'bitsadmin.exe')))
