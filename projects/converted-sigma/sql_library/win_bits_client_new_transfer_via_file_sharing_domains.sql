-- Title: BITS Transfer Job Download From File Sharing Domains
-- ID: d635249d-86b5-4dad-a8c7-d7272b788586
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-28
-- Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
-- Description: Detects BITS transfer job downloading files from a file sharing domain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 16403 AND (RemoteName ILIKE '%.githubusercontent.com%' OR RemoteName ILIKE '%0x0.st%' OR RemoteName ILIKE '%anonfiles.com%' OR RemoteName ILIKE '%bashupload.com%' OR RemoteName ILIKE '%cdn.discordapp.com%' OR RemoteName ILIKE '%chunk.io%' OR RemoteName ILIKE '%ddns.net%' OR RemoteName ILIKE '%dl.dropboxusercontent.com%' OR RemoteName ILIKE '%ghostbin.co%' OR RemoteName ILIKE '%github.com%' OR RemoteName ILIKE '%glitch.me%' OR RemoteName ILIKE '%gofile.io%' OR RemoteName ILIKE '%hastebin.com%' OR RemoteName ILIKE '%mediafire.com%' OR RemoteName ILIKE '%mega.nz%' OR RemoteName ILIKE '%onrender.com%' OR RemoteName ILIKE '%pages.dev%' OR RemoteName ILIKE '%paste.ee%' OR RemoteName ILIKE '%pastebin.com%' OR RemoteName ILIKE '%pastebin.pl%' OR RemoteName ILIKE '%pastetext.net%' OR RemoteName ILIKE '%pixeldrain.com%' OR RemoteName ILIKE '%privatlab.com%' OR RemoteName ILIKE '%privatlab.net%' OR RemoteName ILIKE '%send.exploit.in%' OR RemoteName ILIKE '%sendspace.com%' OR RemoteName ILIKE '%storage.googleapis.com%' OR RemoteName ILIKE '%storjshare.io%' OR RemoteName ILIKE '%supabase.co%' OR RemoteName ILIKE '%temp.sh%' OR RemoteName ILIKE '%transfer.sh%' OR RemoteName ILIKE '%trycloudflare.com%' OR RemoteName ILIKE '%ufile.io%' OR RemoteName ILIKE '%w3spaces.com%' OR RemoteName ILIKE '%workers.dev%' OR RemoteName ILIKE '%x0.at%'))
