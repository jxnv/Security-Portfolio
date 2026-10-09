-- Title: Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE
-- ID: 42a5f1e7-9603-4f6d-97ae-3f37d130d794
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-15
-- Tags: attack.stealth, attack.t1027, attack.command-and-control, attack.t1105
-- Description: Detects the execution of certutil with certain flags that allow the utility to download files from file-sharing websites.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%urlcache %' OR CommandLine LIKE '%verifyctl %' OR CommandLine LIKE '%URL %')) AND ((CommandLine LIKE '%.githubusercontent.com%' OR CommandLine LIKE '%0x0.st%' OR CommandLine LIKE '%anonfiles.com%' OR CommandLine LIKE '%bashupload.com%' OR CommandLine LIKE '%cdn.discordapp.com%' OR CommandLine LIKE '%chunk.io%' OR CommandLine LIKE '%ddns.net%' OR CommandLine LIKE '%dl.dropboxusercontent.com%' OR CommandLine LIKE '%ghostbin.co%' OR CommandLine LIKE '%github.com%' OR CommandLine LIKE '%glitch.me%' OR CommandLine LIKE '%gofile.io%' OR CommandLine LIKE '%hastebin.com%' OR CommandLine LIKE '%mediafire.com%' OR CommandLine LIKE '%mega.nz%' OR CommandLine LIKE '%onrender.com%' OR CommandLine LIKE '%pages.dev%' OR CommandLine LIKE '%paste.ee%' OR CommandLine LIKE '%pastebin.com%' OR CommandLine LIKE '%pastebin.pl%' OR CommandLine LIKE '%pastetext.net%' OR CommandLine LIKE '%privatlab.com%' OR CommandLine LIKE '%privatlab.net%' OR CommandLine LIKE '%send.exploit.in%' OR CommandLine LIKE '%sendspace.com%' OR CommandLine LIKE '%storage.googleapis.com%' OR CommandLine LIKE '%storjshare.io%' OR CommandLine LIKE '%supabase.co%' OR CommandLine LIKE '%temp.sh%' OR CommandLine LIKE '%transfer.sh%' OR CommandLine LIKE '%trycloudflare.com%' OR CommandLine LIKE '%ufile.io%' OR CommandLine LIKE '%w3spaces.com%' OR CommandLine LIKE '%workers.dev%' OR CommandLine LIKE '%x0.at%')) AND ((Image="*\\certutil.exe") OR (OriginalFileName = 'CertUtil.exe')))
