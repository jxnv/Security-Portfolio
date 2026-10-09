# Title: DNS Query To AzureWebsites.NET By Non-Browser Process
# ID: e043f529-8514-4205-8ab0-7f7d2927b400
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2024-06-24
# Tags: attack.command-and-control, attack.t1219.002
# Description: Detects a DNS query by a non browser process on the system to "azurewebsites.net". The latter was often used by threat actors as a malware hosting and exfiltration site.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DNS Query To AzureWebsites.NET By Non-Browser Process
def rule(event):
    # Detection Logic:
    # ((QueryName="*azurewebsites.net") AND NOT ((((Image="C:\\Program Files (x86)\\Avant Browser\\*" OR Image="C:\\Program Files\\Avant Browser\\*") AND Image="*\\avant.exe") OR (Image="*\\brave.exe" AND Image="C:\\Program Files\\BraveSoftware\\*") OR ((Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" OR Image="C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) OR ((Image="*\\MsMpEng.exe" OR Image="*\\MsSense.exe")) OR ((Image="C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*") OR (Image="*\\WindowsApps\\MicrosoftEdge.exe") OR ((Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" OR Image="C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) OR ((Image="C:\\Program Files (x86)\\Microsoft\\EdgeCore\\*" OR Image="C:\\Program Files\\Microsoft\\EdgeCore\\*") AND (Image="*\\msedge.exe" OR Image="*\\msedgewebview2.exe")) OR ((Image="C:\\Program Files\\Falkon\\*" OR Image="C:\\Program Files (x86)\\Falkon\\*") AND Image="*\\falkon.exe") OR ((Image="C:\\Program Files\\Mozilla Firefox\\firefox.exe" OR Image="C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) OR (Image="*\\AppData\\Local\\Flock\\*" AND Image="*\\Flock.exe") OR ((Image="C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Image="C:\\Program Files\\Internet Explorer\\iexplore.exe")) OR (Image="*\\AppData\\Local\\Maxthon\\*" AND Image="*\\maxthon.exe") OR (Image="*\\AppData\\Local\\Programs\\midori-ng\\*" AND Image="*\\Midori Next Generation.exe") OR (Image="*\\AppData\\Local\\Programs\\Opera\\*" AND Image="*\\opera.exe") OR (Image="*\\AppData\\Local\\Phoebe\\*" AND Image="*\\Phoebe.exe") OR (Image="*\\safari.exe") OR ((Image="C:\\Program Files\\SeaMonkey\\*" OR Image="C:\\Program Files (x86)\\SeaMonkey\\*") AND Image="*\\seamonkey.exe") OR ((Image="C:\\Program Files\\SlimBrowser\\*" OR Image="C:\\Program Files (x86)\\SlimBrowser\\*") AND Image="*\\slimbrowser.exe") OR (Image="*\\Tor Browser\\*") OR (Image="*\\AppData\\Local\\Vivaldi\\*" AND Image="*\\vivaldi.exe") OR ((Image="C:\\Program Files\\Naver\\Naver Whale\\*" OR Image="C:\\Program Files (x86)\\Naver\\Naver Whale\\*") AND Image="*\\whale.exe") OR ((Image="C:\\Program Files\\Waterfox\\*" OR Image="C:\\Program Files (x86)\\Waterfox\\*") AND Image="*\\Waterfox.exe"))))
    return True

def title(event):
    return "DNS Query To AzureWebsites.NET By Non-Browser Process"

