# Title: Potentially Suspicious Desktop Background Change Using Reg.EXE
# ID: 8cbc9475-8d05-4e27-9c32-df960716c701
# Status: test
# Level: medium
# Author: Stephen Lincoln @slincoln-aiq (AttackIQ)
# Date: 2023-12-21
# Tags: attack.persistence, attack.impact, attack.defense-impairment, attack.t1112, attack.t1491.001
# Description: Detects the execution of "reg.exe" to alter registry keys that would replace the user's desktop background.
# This is a common technique used by malware to change the desktop background to a ransom note or other image.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious Desktop Background Change Using Reg.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*add*") AND ((Image="*\\reg.exe") OR (OriginalFileName="reg.exe"))) AND ((CommandLine="*Control Panel\\Desktop*" OR CommandLine="*CurrentVersion\\Policies\\ActiveDesktop*" OR CommandLine="*CurrentVersion\\Policies\\System*")) AND (((CommandLine="*/v NoChangingWallpaper*" AND CommandLine="*/d 1*")) OR ((CommandLine="*/v Wallpaper*" AND CommandLine="*/t REG_SZ*")) OR ((CommandLine="*/v WallpaperStyle*" AND CommandLine="*/d 2*"))))
    return True

def title(event):
    return "Potentially Suspicious Desktop Background Change Using Reg.EXE"

