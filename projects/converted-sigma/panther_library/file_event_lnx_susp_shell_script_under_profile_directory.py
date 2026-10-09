# Title: Potentially Suspicious Shell Script Creation in Profile Folder
# ID: 13f08f54-e705-4498-91fd-cce9d9cee9f1
# Status: test
# Level: low
# Author: Joseliyo Sanchez, @Joseliyo_Jstnk
# Date: 2023-06-02
# Tags: attack.persistence
# Description: Detects the creation of shell scripts under the "profile.d" path.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potentially Suspicious Shell Script Creation in Profile Folder
def rule(event):
    # Detection Logic:
    # (TargetFilename="*/etc/profile.d/*" AND (TargetFilename="*.csh" OR TargetFilename="*.sh"))
    return True

def title(event):
    return "Potentially Suspicious Shell Script Creation in Profile Folder"

