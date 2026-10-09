# Title: Unusual File Download From File Sharing Websites - File Stream
# ID: ae02ed70-11aa-4a22-b397-c0d0e8f6ea99
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2022-08-24
# Tags: attack.stealth, attack.s0139, attack.t1564.004
# Description: Detects the download of suspicious file type from a well-known file and paste sharing domain
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Unusual File Download From File Sharing Websites - File Stream
def rule(event):
    # Detection Logic:
    # (((Contents="*.githubusercontent.com*" OR Contents="*0x0.st*" OR Contents="*anonfiles.com*" OR Contents="*bashupload.com*" OR Contents="*cdn.discordapp.com*" OR Contents="*chunk.io*" OR Contents="*ddns.net*" OR Contents="*dl.dropboxusercontent.com*" OR Contents="*ghostbin.co*" OR Contents="*github.com*" OR Contents="*glitch.me*" OR Contents="*gofile.io*" OR Contents="*hastebin.com*" OR Contents="*mediafire.com*" OR Contents="*mega.nz*" OR Contents="*onrender.com*" OR Contents="*pages.dev*" OR Contents="*paste.ee*" OR Contents="*pastebin.com*" OR Contents="*pastebin.pl*" OR Contents="*pastetext.net*" OR Contents="*pixeldrain.com*" OR Contents="*privatlab.com*" OR Contents="*privatlab.net*" OR Contents="*send.exploit.in*" OR Contents="*sendspace.com*" OR Contents="*storage.googleapis.com*" OR Contents="*storjshare.io*" OR Contents="*supabase.co*" OR Contents="*temp.sh*" OR Contents="*transfer.sh*" OR Contents="*trycloudflare.com*" OR Contents="*ufile.io*" OR Contents="*w3spaces.com*" OR Contents="*workers.dev*" OR Contents="*x0.at*")) AND ((TargetFilename="*.bat:Zone*" OR TargetFilename="*.cmd:Zone*" OR TargetFilename="*.ps1:Zone*")))
    return True

def title(event):
    return "Unusual File Download From File Sharing Websites - File Stream"

