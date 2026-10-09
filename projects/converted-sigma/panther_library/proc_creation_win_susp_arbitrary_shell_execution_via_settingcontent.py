# Title: Arbitrary Shell Command Execution Via Settingcontent-Ms
# ID: 24de4f3b-804c-4165-b442-5a06a2302c7e
# Status: test
# Level: medium
# Author: Sreeman
# Date: 2020-03-13
# Tags: attack.t1204, attack.t1566.001, attack.execution, attack.initial-access
# Description: The .SettingContent-ms file type was introduced in Windows 10 and allows a user to create "shortcuts" to various Windows 10 setting pages. These files are simply XML and contain paths to various Windows 10 settings binaries.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Arbitrary Shell Command Execution Via Settingcontent-Ms
def rule(event):
    # Detection Logic:
    # ((CommandLine="*.SettingContent-ms*") AND NOT ((CommandLine="*immersivecontrolpanel*")))
    return True

def title(event):
    return "Arbitrary Shell Command Execution Via Settingcontent-Ms"

