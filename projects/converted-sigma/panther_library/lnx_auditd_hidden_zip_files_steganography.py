# Title: Steganography Hide Zip Information in Picture File
# ID: 45810b50-7edc-42ca-813b-bdac02fb946b
# Status: test
# Level: low
# Author: Pawel Mazur
# Date: 2021-09-09
# Tags: attack.stealth, attack.t1027.003
# Description: Detects appending of zip file to image
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Steganography Hide Zip Information in Picture File
def rule(event):
    # Detection Logic:
    # ((type="EXECVE" AND a0="cat") AND ((a1="*.jpg" OR a1="*.png")) AND (a2="*.zip"))
    return True

def title(event):
    return "Steganography Hide Zip Information in Picture File"

