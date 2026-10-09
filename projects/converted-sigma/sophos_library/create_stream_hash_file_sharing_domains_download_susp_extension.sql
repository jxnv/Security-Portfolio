-- Title: Suspicious File Download From File Sharing Websites -  File Stream
-- ID: 52182dfb-afb7-41db-b4bc-5336cb29b464
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-24
-- Tags: attack.stealth, attack.s0139, attack.t1564.004
-- Description: Detects the download of suspicious file type from a well-known file and paste sharing domain
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Contents ILIKE '%.githubusercontent.com%' OR Contents ILIKE '%0x0.st%' OR Contents ILIKE '%anonfiles.com%' OR Contents ILIKE '%bashupload.com%' OR Contents ILIKE '%cdn.discordapp.com%' OR Contents ILIKE '%chunk.io%' OR Contents ILIKE '%ddns.net%' OR Contents ILIKE '%dl.dropboxusercontent.com%' OR Contents ILIKE '%ghostbin.co%' OR Contents ILIKE '%github.com%' OR Contents ILIKE '%glitch.me%' OR Contents ILIKE '%gofile.io%' OR Contents ILIKE '%hastebin.com%' OR Contents ILIKE '%mediafire.com%' OR Contents ILIKE '%mega.nz%' OR Contents ILIKE '%onrender.com%' OR Contents ILIKE '%pages.dev%' OR Contents ILIKE '%paste.ee%' OR Contents ILIKE '%pastebin.com%' OR Contents ILIKE '%pastebin.pl%' OR Contents ILIKE '%pastetext.net%' OR Contents ILIKE '%pixeldrain.com%' OR Contents ILIKE '%privatlab.com%' OR Contents ILIKE '%privatlab.net%' OR Contents ILIKE '%send.exploit.in%' OR Contents ILIKE '%sendspace.com%' OR Contents ILIKE '%storage.googleapis.com%' OR Contents ILIKE '%storjshare.io%' OR Contents ILIKE '%supabase.co%' OR Contents ILIKE '%temp.sh%' OR Contents ILIKE '%transfer.sh%' OR Contents ILIKE '%trycloudflare.com%' OR Contents ILIKE '%ufile.io%' OR Contents ILIKE '%w3spaces.com%' OR Contents ILIKE '%workers.dev%' OR Contents ILIKE '%x0.at%')) AND ((TargetFilename ILIKE '%.cpl:Zone%' OR TargetFilename ILIKE '%.dll:Zone%' OR TargetFilename ILIKE '%.exe:Zone%' OR TargetFilename ILIKE '%.hta:Zone%' OR TargetFilename ILIKE '%.lnk:Zone%' OR TargetFilename ILIKE '%.one:Zone%' OR TargetFilename ILIKE '%.vbe:Zone%' OR TargetFilename ILIKE '%.vbs:Zone%' OR TargetFilename ILIKE '%.xll:Zone%')))
