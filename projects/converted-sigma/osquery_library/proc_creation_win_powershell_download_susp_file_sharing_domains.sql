-- Title: Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE
-- ID: b6e04788-29e1-4557-bb14-77f761848ab8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-02-23
-- Tags: attack.execution
-- Description: Detects potentially suspicious file downloads from file sharing domains using PowerShell.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.DownloadString(%' OR CommandLine LIKE '%.DownloadFile(%' OR CommandLine LIKE '%Invoke-WebRequest %' OR CommandLine LIKE '%iwr %' OR CommandLine LIKE '%wget %')) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine LIKE '%0x0.st%' OR CommandLine LIKE '%anonfiles.com%' OR CommandLine LIKE '%bashupload.com%' OR CommandLine LIKE '%cdn.discordapp.com%' OR CommandLine LIKE '%chunk.io%' OR CommandLine LIKE '%ddns.net%' OR CommandLine LIKE '%dl.dropboxusercontent.com%' OR CommandLine LIKE '%ghostbin.co%' OR CommandLine LIKE '%glitch.me%' OR CommandLine LIKE '%gofile.io%' OR CommandLine LIKE '%hastebin.com%' OR CommandLine LIKE '%mediafire.com%' OR CommandLine LIKE '%mega.nz%' OR CommandLine LIKE '%onrender.com%' OR CommandLine LIKE '%pages.dev%' OR CommandLine LIKE '%paste.ee%' OR CommandLine LIKE '%pastebin.com%' OR CommandLine LIKE '%pastebin.pl%' OR CommandLine LIKE '%pastetext.net%' OR CommandLine LIKE '%pixeldrain.com%' OR CommandLine LIKE '%privatlab.com%' OR CommandLine LIKE '%privatlab.net%' OR CommandLine LIKE '%send.exploit.in%' OR CommandLine LIKE '%sendspace.com%' OR CommandLine LIKE '%storage.googleapis.com%' OR CommandLine LIKE '%storjshare.io%' OR CommandLine LIKE '%supabase.co%' OR CommandLine LIKE '%temp.sh%' OR CommandLine LIKE '%transfer.sh%' OR CommandLine LIKE '%trycloudflare.com%' OR CommandLine LIKE '%ufile.io%' OR CommandLine LIKE '%w3spaces.com%' OR CommandLine LIKE '%workers.dev%' OR CommandLine LIKE '%x0.at%')))
