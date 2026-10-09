// Title: Suspicious File Download From File Sharing Websites -  File Stream
// ID: 52182dfb-afb7-41db-b4bc-5336cb29b464
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-08-24
// Tags: attack.stealth, attack.s0139, attack.t1564.004
// Description: Detects the download of suspicious file type from a well-known file and paste sharing domain
// Converted by: Sigma Universal SIEM/EDR CLI

(((Contents contains ".githubusercontent.com" OR Contents contains "0x0.st" OR Contents contains "anonfiles.com" OR Contents contains "bashupload.com" OR Contents contains "cdn.discordapp.com" OR Contents contains "chunk.io" OR Contents contains "ddns.net" OR Contents contains "dl.dropboxusercontent.com" OR Contents contains "ghostbin.co" OR Contents contains "github.com" OR Contents contains "glitch.me" OR Contents contains "gofile.io" OR Contents contains "hastebin.com" OR Contents contains "mediafire.com" OR Contents contains "mega.nz" OR Contents contains "onrender.com" OR Contents contains "pages.dev" OR Contents contains "paste.ee" OR Contents contains "pastebin.com" OR Contents contains "pastebin.pl" OR Contents contains "pastetext.net" OR Contents contains "pixeldrain.com" OR Contents contains "privatlab.com" OR Contents contains "privatlab.net" OR Contents contains "send.exploit.in" OR Contents contains "sendspace.com" OR Contents contains "storage.googleapis.com" OR Contents contains "storjshare.io" OR Contents contains "supabase.co" OR Contents contains "temp.sh" OR Contents contains "transfer.sh" OR Contents contains "trycloudflare.com" OR Contents contains "ufile.io" OR Contents contains "w3spaces.com" OR Contents contains "workers.dev" OR Contents contains "x0.at")) AND ((TargetFilename contains ".cpl:Zone" OR TargetFilename contains ".dll:Zone" OR TargetFilename contains ".exe:Zone" OR TargetFilename contains ".hta:Zone" OR TargetFilename contains ".lnk:Zone" OR TargetFilename contains ".one:Zone" OR TargetFilename contains ".vbe:Zone" OR TargetFilename contains ".vbs:Zone" OR TargetFilename contains ".xll:Zone")))
