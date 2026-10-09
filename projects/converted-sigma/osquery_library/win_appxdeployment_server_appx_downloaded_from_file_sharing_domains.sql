-- Title: Remote AppX Package Downloaded from File Sharing or CDN Domain
-- ID: 8b48ad89-10d8-4382-a546-50588c410f0d
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-11
-- Tags: attack.stealth
-- Description: Detects an appx package that was added to the pipeline of the "to be processed" packages which was downloaded from a file sharing or CDN domain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (EventID = '854' AND (Path LIKE '%.githubusercontent.com%' OR Path LIKE '%0x0.st%' OR Path LIKE '%anonfiles.com%' OR Path LIKE '%bashupload.com%' OR Path LIKE '%cdn.discordapp.com%' OR Path LIKE '%chunk.io%' OR Path LIKE '%ddns.net%' OR Path LIKE '%dl.dropboxusercontent.com%' OR Path LIKE '%ghostbin.co%' OR Path LIKE '%github.com%' OR Path LIKE '%glitch.me%' OR Path LIKE '%gofile.io%' OR Path LIKE '%hastebin.com%' OR Path LIKE '%mediafire.com%' OR Path LIKE '%mega.nz%' OR Path LIKE '%onrender.com%' OR Path LIKE '%pages.dev%' OR Path LIKE '%paste.ee%' OR Path LIKE '%pastebin.com%' OR Path LIKE '%pastebin.pl%' OR Path LIKE '%pastetext.net%' OR Path LIKE '%privatlab.com%' OR Path LIKE '%privatlab.net%' OR Path LIKE '%send.exploit.in%' OR Path LIKE '%sendspace.com%' OR Path LIKE '%storage.googleapis.com%' OR Path LIKE '%storjshare.io%' OR Path LIKE '%supabase.co%' OR Path LIKE '%temp.sh%' OR Path LIKE '%transfer.sh%' OR Path LIKE '%trycloudflare.com%' OR Path LIKE '%ufile.io%' OR Path LIKE '%w3spaces.com%' OR Path LIKE '%workers.dev%' OR Path LIKE '%x0.at%'))
