// Title: Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE
// ID: b6e04788-29e1-4557-bb14-77f761848ab8
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-02-23
// Tags: attack.execution
// Description: Detects potentially suspicious file downloads from file sharing domains using PowerShell.exe
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains ".DownloadString(" OR CommandLine contains ".DownloadFile(" OR CommandLine contains "Invoke-WebRequest " OR CommandLine contains "iwr " OR CommandLine contains "wget ")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName == "PowerShell.EXE" OR OriginalFileName == "pwsh.dll"))) AND ((CommandLine contains "0x0.st" OR CommandLine contains "anonfiles.com" OR CommandLine contains "bashupload.com" OR CommandLine contains "cdn.discordapp.com" OR CommandLine contains "chunk.io" OR CommandLine contains "ddns.net" OR CommandLine contains "dl.dropboxusercontent.com" OR CommandLine contains "ghostbin.co" OR CommandLine contains "glitch.me" OR CommandLine contains "gofile.io" OR CommandLine contains "hastebin.com" OR CommandLine contains "mediafire.com" OR CommandLine contains "mega.nz" OR CommandLine contains "onrender.com" OR CommandLine contains "pages.dev" OR CommandLine contains "paste.ee" OR CommandLine contains "pastebin.com" OR CommandLine contains "pastebin.pl" OR CommandLine contains "pastetext.net" OR CommandLine contains "pixeldrain.com" OR CommandLine contains "privatlab.com" OR CommandLine contains "privatlab.net" OR CommandLine contains "send.exploit.in" OR CommandLine contains "sendspace.com" OR CommandLine contains "storage.googleapis.com" OR CommandLine contains "storjshare.io" OR CommandLine contains "supabase.co" OR CommandLine contains "temp.sh" OR CommandLine contains "transfer.sh" OR CommandLine contains "trycloudflare.com" OR CommandLine contains "ufile.io" OR CommandLine contains "w3spaces.com" OR CommandLine contains "workers.dev" OR CommandLine contains "x0.at")))
