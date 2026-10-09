// Title: Suspicious File Download From File Sharing Websites -  File Stream
// ID: 52182dfb-afb7-41db-b4bc-5336cb29b464
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-08-24
// Tags: attack.stealth, attack.s0139, attack.t1564.004
// Description: Detects the download of suspicious file type from a well-known file and paste sharing domain
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Contents contains ".githubusercontent.com" or Contents contains "0x0.st" or Contents contains "anonfiles.com" or Contents contains "bashupload.com" or Contents contains "cdn.discordapp.com" or Contents contains "chunk.io" or Contents contains "ddns.net" or Contents contains "dl.dropboxusercontent.com" or Contents contains "ghostbin.co" or Contents contains "github.com" or Contents contains "glitch.me" or Contents contains "gofile.io" or Contents contains "hastebin.com" or Contents contains "mediafire.com" or Contents contains "mega.nz" or Contents contains "onrender.com" or Contents contains "pages.dev" or Contents contains "paste.ee" or Contents contains "pastebin.com" or Contents contains "pastebin.pl" or Contents contains "pastetext.net" or Contents contains "pixeldrain.com" or Contents contains "privatlab.com" or Contents contains "privatlab.net" or Contents contains "send.exploit.in" or Contents contains "sendspace.com" or Contents contains "storage.googleapis.com" or Contents contains "storjshare.io" or Contents contains "supabase.co" or Contents contains "temp.sh" or Contents contains "transfer.sh" or Contents contains "trycloudflare.com" or Contents contains "ufile.io" or Contents contains "w3spaces.com" or Contents contains "workers.dev" or Contents contains "x0.at")) and ((action_file_path contains ".cpl:Zone" or action_file_path contains ".dll:Zone" or action_file_path contains ".exe:Zone" or action_file_path contains ".hta:Zone" or action_file_path contains ".lnk:Zone" or action_file_path contains ".one:Zone" or action_file_path contains ".vbe:Zone" or action_file_path contains ".vbs:Zone" or action_file_path contains ".xll:Zone")))
