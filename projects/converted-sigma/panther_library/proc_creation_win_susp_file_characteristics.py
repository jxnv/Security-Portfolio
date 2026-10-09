# Title: Suspicious File Characteristics Due to Missing Fields
# ID: 9637e8a5-7131-4f7f-bdc7-2b05d8670c43
# Status: test
# Level: medium
# Author: Markus Neis, Sander Wiebing
# Date: 2018-11-22
# Tags: attack.execution, attack.t1059.006
# Description: Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious File Characteristics Due to Missing Fields
def rule(event):
    # Detection Logic:
    # (((Description="\\?" AND FileVersion="\\?") OR (Description="\\?" AND Product="\\?") OR (Description="\\?" AND Company="\\?")) AND (Image="*\\Downloads\\*"))
    return True

def title(event):
    return "Suspicious File Characteristics Due to Missing Fields"

