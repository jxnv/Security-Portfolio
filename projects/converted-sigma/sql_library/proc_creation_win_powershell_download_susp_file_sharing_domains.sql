-- Title: Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE
-- ID: b6e04788-29e1-4557-bb14-77f761848ab8
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-02-23
-- Tags: attack.execution
-- Description: Detects potentially suspicious file downloads from file sharing domains using PowerShell.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.DownloadString(%' OR CommandLine ILIKE '%.DownloadFile(%' OR CommandLine ILIKE '%Invoke-WebRequest %' OR CommandLine ILIKE '%iwr %' OR CommandLine ILIKE '%wget %')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine ILIKE '%0x0.st%' OR CommandLine ILIKE '%anonfiles.com%' OR CommandLine ILIKE '%bashupload.com%' OR CommandLine ILIKE '%cdn.discordapp.com%' OR CommandLine ILIKE '%chunk.io%' OR CommandLine ILIKE '%ddns.net%' OR CommandLine ILIKE '%dl.dropboxusercontent.com%' OR CommandLine ILIKE '%ghostbin.co%' OR CommandLine ILIKE '%glitch.me%' OR CommandLine ILIKE '%gofile.io%' OR CommandLine ILIKE '%hastebin.com%' OR CommandLine ILIKE '%mediafire.com%' OR CommandLine ILIKE '%mega.nz%' OR CommandLine ILIKE '%onrender.com%' OR CommandLine ILIKE '%pages.dev%' OR CommandLine ILIKE '%paste.ee%' OR CommandLine ILIKE '%pastebin.com%' OR CommandLine ILIKE '%pastebin.pl%' OR CommandLine ILIKE '%pastetext.net%' OR CommandLine ILIKE '%pixeldrain.com%' OR CommandLine ILIKE '%privatlab.com%' OR CommandLine ILIKE '%privatlab.net%' OR CommandLine ILIKE '%send.exploit.in%' OR CommandLine ILIKE '%sendspace.com%' OR CommandLine ILIKE '%storage.googleapis.com%' OR CommandLine ILIKE '%storjshare.io%' OR CommandLine ILIKE '%supabase.co%' OR CommandLine ILIKE '%temp.sh%' OR CommandLine ILIKE '%transfer.sh%' OR CommandLine ILIKE '%trycloudflare.com%' OR CommandLine ILIKE '%ufile.io%' OR CommandLine ILIKE '%w3spaces.com%' OR CommandLine ILIKE '%workers.dev%' OR CommandLine ILIKE '%x0.at%')))
