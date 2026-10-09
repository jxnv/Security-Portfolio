-- Title: Suspicious File Download From File Sharing Websites -  File Stream
-- ID: 52182dfb-afb7-41db-b4bc-5336cb29b464
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-24
-- Tags: attack.stealth, attack.s0139, attack.t1564.004
-- Description: Detects the download of suspicious file type from a well-known file and paste sharing domain
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((Contents LIKE '%.githubusercontent.com%' OR Contents LIKE '%0x0.st%' OR Contents LIKE '%anonfiles.com%' OR Contents LIKE '%bashupload.com%' OR Contents LIKE '%cdn.discordapp.com%' OR Contents LIKE '%chunk.io%' OR Contents LIKE '%ddns.net%' OR Contents LIKE '%dl.dropboxusercontent.com%' OR Contents LIKE '%ghostbin.co%' OR Contents LIKE '%github.com%' OR Contents LIKE '%glitch.me%' OR Contents LIKE '%gofile.io%' OR Contents LIKE '%hastebin.com%' OR Contents LIKE '%mediafire.com%' OR Contents LIKE '%mega.nz%' OR Contents LIKE '%onrender.com%' OR Contents LIKE '%pages.dev%' OR Contents LIKE '%paste.ee%' OR Contents LIKE '%pastebin.com%' OR Contents LIKE '%pastebin.pl%' OR Contents LIKE '%pastetext.net%' OR Contents LIKE '%pixeldrain.com%' OR Contents LIKE '%privatlab.com%' OR Contents LIKE '%privatlab.net%' OR Contents LIKE '%send.exploit.in%' OR Contents LIKE '%sendspace.com%' OR Contents LIKE '%storage.googleapis.com%' OR Contents LIKE '%storjshare.io%' OR Contents LIKE '%supabase.co%' OR Contents LIKE '%temp.sh%' OR Contents LIKE '%transfer.sh%' OR Contents LIKE '%trycloudflare.com%' OR Contents LIKE '%ufile.io%' OR Contents LIKE '%w3spaces.com%' OR Contents LIKE '%workers.dev%' OR Contents LIKE '%x0.at%')) AND ((TargetFilename LIKE '%.cpl:Zone%' OR TargetFilename LIKE '%.dll:Zone%' OR TargetFilename LIKE '%.exe:Zone%' OR TargetFilename LIKE '%.hta:Zone%' OR TargetFilename LIKE '%.lnk:Zone%' OR TargetFilename LIKE '%.one:Zone%' OR TargetFilename LIKE '%.vbe:Zone%' OR TargetFilename LIKE '%.vbs:Zone%' OR TargetFilename LIKE '%.xll:Zone%')))
