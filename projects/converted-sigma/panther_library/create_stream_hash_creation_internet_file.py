# Title: Creation Of a Suspicious ADS File Outside a Browser Download
# ID: 573df571-a223-43bc-846e-3f98da481eca
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-10-22
# Tags: attack.stealth
# Description: Detects the creation of a suspicious ADS (Alternate Data Stream) file by software other than browsers
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Creation Of a Suspicious ADS File Outside a Browser Download
def rule(event):
    # Detection Logic:
    # ((Contents="[ZoneTransfer]  ZoneId=3*" AND TargetFilename="*:Zone.Identifier" AND (TargetFilename="*.exe*" OR TargetFilename="*.scr*" OR TargetFilename="*.bat*" OR TargetFilename="*.cmd*" OR TargetFilename="*.docx*" OR TargetFilename="*.hta*" OR TargetFilename="*.jse*" OR TargetFilename="*.lnk*" OR TargetFilename="*.pptx*" OR TargetFilename="*.ps*" OR TargetFilename="*.reg*" OR TargetFilename="*.sct*" OR TargetFilename="*.vb*" OR TargetFilename="*.wsc*" OR TargetFilename="*.wsf*" OR TargetFilename="*.xlsx*")) AND NOT (((Image="*\\brave.exe") OR ((Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" OR Image="C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) OR ((Image="C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\*") OR (Image="*\\WindowsApps\\MicrosoftEdge.exe") OR ((Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" OR Image="C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) OR ((Image="C:\\Program Files (x86)\\Microsoft\\EdgeCore\\*" OR Image="C:\\Program Files\\Microsoft\\EdgeCore\\*") AND (Image="*\\msedge.exe" OR Image="*\\msedgewebview2.exe")) OR ((Image="C:\\Program Files\\Mozilla Firefox\\firefox.exe" OR Image="C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) OR ((Image="C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Image="C:\\Program Files\\Internet Explorer\\iexplore.exe")) OR (Image="*\\maxthon.exe") OR (Image="*\\opera.exe") OR (Image="*\\safari.exe") OR (Image="*\\seamonkey.exe") OR (Image="C:\\Program Files\\WindowsApps\\Microsoft.ScreenSketch_*" AND Image="*\\SnippingTool\\SnippingTool.exe" AND TargetFilename="C:\\Users\\*" AND (TargetFilename="*\\AppData\\Local\\Packages\\Microsoft.ScreenSketch_*" AND TargetFilename="*\\TempState\\Screenshot *") AND TargetFilename="*.png:Zone.Identifier") OR (Image="*\\vivaldi.exe") OR (Image="*\\whale.exe"))))
    return True

def title(event):
    return "Creation Of a Suspicious ADS File Outside a Browser Download"

