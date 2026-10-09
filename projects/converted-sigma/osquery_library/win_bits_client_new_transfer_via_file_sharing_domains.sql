-- Title: BITS Transfer Job Download From File Sharing Domains
-- ID: d635249d-86b5-4dad-a8c7-d7272b788586
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
-- Description: Detects BITS transfer job downloading files from a file sharing domain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (EventID = '16403' AND (RemoteName LIKE '%.githubusercontent.com%' OR RemoteName LIKE '%0x0.st%' OR RemoteName LIKE '%anonfiles.com%' OR RemoteName LIKE '%bashupload.com%' OR RemoteName LIKE '%cdn.discordapp.com%' OR RemoteName LIKE '%chunk.io%' OR RemoteName LIKE '%ddns.net%' OR RemoteName LIKE '%dl.dropboxusercontent.com%' OR RemoteName LIKE '%ghostbin.co%' OR RemoteName LIKE '%github.com%' OR RemoteName LIKE '%glitch.me%' OR RemoteName LIKE '%gofile.io%' OR RemoteName LIKE '%hastebin.com%' OR RemoteName LIKE '%mediafire.com%' OR RemoteName LIKE '%mega.nz%' OR RemoteName LIKE '%onrender.com%' OR RemoteName LIKE '%pages.dev%' OR RemoteName LIKE '%paste.ee%' OR RemoteName LIKE '%pastebin.com%' OR RemoteName LIKE '%pastebin.pl%' OR RemoteName LIKE '%pastetext.net%' OR RemoteName LIKE '%pixeldrain.com%' OR RemoteName LIKE '%privatlab.com%' OR RemoteName LIKE '%privatlab.net%' OR RemoteName LIKE '%send.exploit.in%' OR RemoteName LIKE '%sendspace.com%' OR RemoteName LIKE '%storage.googleapis.com%' OR RemoteName LIKE '%storjshare.io%' OR RemoteName LIKE '%supabase.co%' OR RemoteName LIKE '%temp.sh%' OR RemoteName LIKE '%transfer.sh%' OR RemoteName LIKE '%trycloudflare.com%' OR RemoteName LIKE '%ufile.io%' OR RemoteName LIKE '%w3spaces.com%' OR RemoteName LIKE '%workers.dev%' OR RemoteName LIKE '%x0.at%'))
