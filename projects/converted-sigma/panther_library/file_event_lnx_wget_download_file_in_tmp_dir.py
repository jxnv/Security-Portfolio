# Title: Wget Creating Files in Tmp Directory
# ID: 35a05c60-9012-49b6-a11f-6bab741c9f74
# Status: test
# Level: medium
# Author: Joseliyo Sanchez, @Joseliyo_Jstnk
# Date: 2023-06-02
# Tags: attack.command-and-control, attack.t1105
# Description: Detects the use of wget to download content in a temporary directory such as "/tmp" or "/var/tmp"
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Wget Creating Files in Tmp Directory
def rule(event):
    # Detection Logic:
    # (Image="*/wget" AND (TargetFilename="/tmp/*" OR TargetFilename="/var/tmp/*"))
    return True

def title(event):
    return "Wget Creating Files in Tmp Directory"

