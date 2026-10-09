# Title: Credentials from Password Stores - Keychain
# ID: b120b587-a4c2-4b94-875d-99c9807d6955
# Status: test
# Level: medium
# Author: Tim Ismilyaev, oscd.community, Florian Roth (Nextron Systems)
# Date: 2020-10-19
# Tags: attack.credential-access, attack.t1555.001
# Description: Detects passwords dumps from Keychain
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Credentials from Password Stores - Keychain
def rule(event):
    # Detection Logic:
    # ((Image="/usr/bin/security" AND (CommandLine="*find-certificate*" OR CommandLine="* export *")) OR ((CommandLine="* dump-keychain *" OR CommandLine="* login-keychain *")))
    return True

def title(event):
    return "Credentials from Password Stores - Keychain"

