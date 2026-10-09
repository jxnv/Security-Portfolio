# Title: BITS Transfer Job Download From File Sharing Domains
# ID: d635249d-86b5-4dad-a8c7-d7272b788586
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-06-28
# Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
# Description: Detects BITS transfer job downloading files from a file sharing domain.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: BITS Transfer Job Download From File Sharing Domains
def rule(event):
    # Detection Logic:
    # (EventID="16403" AND (RemoteName="*.githubusercontent.com*" OR RemoteName="*0x0.st*" OR RemoteName="*anonfiles.com*" OR RemoteName="*bashupload.com*" OR RemoteName="*cdn.discordapp.com*" OR RemoteName="*chunk.io*" OR RemoteName="*ddns.net*" OR RemoteName="*dl.dropboxusercontent.com*" OR RemoteName="*ghostbin.co*" OR RemoteName="*github.com*" OR RemoteName="*glitch.me*" OR RemoteName="*gofile.io*" OR RemoteName="*hastebin.com*" OR RemoteName="*mediafire.com*" OR RemoteName="*mega.nz*" OR RemoteName="*onrender.com*" OR RemoteName="*pages.dev*" OR RemoteName="*paste.ee*" OR RemoteName="*pastebin.com*" OR RemoteName="*pastebin.pl*" OR RemoteName="*pastetext.net*" OR RemoteName="*pixeldrain.com*" OR RemoteName="*privatlab.com*" OR RemoteName="*privatlab.net*" OR RemoteName="*send.exploit.in*" OR RemoteName="*sendspace.com*" OR RemoteName="*storage.googleapis.com*" OR RemoteName="*storjshare.io*" OR RemoteName="*supabase.co*" OR RemoteName="*temp.sh*" OR RemoteName="*transfer.sh*" OR RemoteName="*trycloudflare.com*" OR RemoteName="*ufile.io*" OR RemoteName="*w3spaces.com*" OR RemoteName="*workers.dev*" OR RemoteName="*x0.at*"))
    return True

def title(event):
    return "BITS Transfer Job Download From File Sharing Domains"

