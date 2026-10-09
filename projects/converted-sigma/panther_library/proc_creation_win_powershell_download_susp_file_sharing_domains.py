# Title: Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE
# ID: b6e04788-29e1-4557-bb14-77f761848ab8
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2024-02-23
# Tags: attack.execution
# Description: Detects potentially suspicious file downloads from file sharing domains using PowerShell.exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*.DownloadString(*" OR CommandLine="*.DownloadFile(*" OR CommandLine="*Invoke-WebRequest *" OR CommandLine="*iwr *" OR CommandLine="*wget *")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll"))) AND ((CommandLine="*0x0.st*" OR CommandLine="*anonfiles.com*" OR CommandLine="*bashupload.com*" OR CommandLine="*cdn.discordapp.com*" OR CommandLine="*chunk.io*" OR CommandLine="*ddns.net*" OR CommandLine="*dl.dropboxusercontent.com*" OR CommandLine="*ghostbin.co*" OR CommandLine="*glitch.me*" OR CommandLine="*gofile.io*" OR CommandLine="*hastebin.com*" OR CommandLine="*mediafire.com*" OR CommandLine="*mega.nz*" OR CommandLine="*onrender.com*" OR CommandLine="*pages.dev*" OR CommandLine="*paste.ee*" OR CommandLine="*pastebin.com*" OR CommandLine="*pastebin.pl*" OR CommandLine="*pastetext.net*" OR CommandLine="*pixeldrain.com*" OR CommandLine="*privatlab.com*" OR CommandLine="*privatlab.net*" OR CommandLine="*send.exploit.in*" OR CommandLine="*sendspace.com*" OR CommandLine="*storage.googleapis.com*" OR CommandLine="*storjshare.io*" OR CommandLine="*supabase.co*" OR CommandLine="*temp.sh*" OR CommandLine="*transfer.sh*" OR CommandLine="*trycloudflare.com*" OR CommandLine="*ufile.io*" OR CommandLine="*w3spaces.com*" OR CommandLine="*workers.dev*" OR CommandLine="*x0.at*")))
    return True

def title(event):
    return "Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE"

