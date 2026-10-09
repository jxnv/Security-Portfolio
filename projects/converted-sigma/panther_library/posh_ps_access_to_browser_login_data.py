# Title: Access to Browser Login Data
# ID: fc028194-969d-4122-8abe-0470d5b8f12f
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-01-30
# Tags: attack.credential-access, attack.t1555.003
# Description: Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
# Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.
# Web browsers typically store the credentials in an encrypted format within a credential store.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Access to Browser Login Data
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*Copy-Item*" AND ScriptBlockText="*-Destination*")) AND ((ScriptBlockText="*\\Opera Software\\Opera Stable\\Login Data*" OR ScriptBlockText="*\\Mozilla\\Firefox\\Profiles*" OR ScriptBlockText="*\\Microsoft\\Edge\\User Data\\Default*" OR ScriptBlockText="*\\Google\\Chrome\\User Data\\Default\\Login Data*" OR ScriptBlockText="*\\Google\\Chrome\\User Data\\Default\\Login Data For Account*")))
    return True

def title(event):
    return "Access to Browser Login Data"

