# Title: Uncommon File Created by Notepad++ Updater Gup.EXE
# ID: 3b8f4c92-6a51-4d7e-9c3a-8e2d1f5a7b09
# Status: experimental
# Level: high
# Author: Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2026-02-03
# Tags: attack.collection, attack.credential-access, attack.t1195.002, attack.initial-access, attack.t1557
# Description: Detects when the Notepad++ updater (gup.exe) creates files in suspicious or uncommon locations.
# This could indicate potential exploitation of the updater component to deliver unwanted malware or unwarranted files.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Uncommon File Created by Notepad++ Updater Gup.EXE
def rule(event):
    # Detection Logic:
    # ((Image="*\\gup.exe") AND NOT ((((TargetFilename="C:\\Program Files\\Notepad++\\*" OR TargetFilename="C:\\Program Files (x86)\\Notepad++\\*")) OR (((TargetFilename="*\\plugins\\JsonTools\\testfiles\\*" OR TargetFilename="*\\Notepad++\\plugins\\ComparePlugin\\*")) OR ((TargetFilename="*npp.*" AND TargetFilename="*.portable.*" AND TargetFilename="*\\plugins\\*"))) OR (TargetFilename="C:\\$Recycle.Bin\\S-1-5-21*") OR (TargetFilename="C:\\Users\\*" AND (TargetFilename="*\\AppData\\Local\\Temp\\*" AND TargetFilename="*.zip*")) OR (TargetFilename="C:\\Users\\*" AND (TargetFilename="*\\AppData\\Local\\Temp\\*" AND TargetFilename="*npp.*" AND TargetFilename="*.Installer.*" AND TargetFilename="*.exe*")))))
    return True

def title(event):
    return "Uncommon File Created by Notepad++ Updater Gup.EXE"

