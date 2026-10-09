# Title: Payload Decoded and Decrypted via Built-in Utilities
# ID: 234dc5df-40b5-49d1-bf53-0d44ce778eca
# Status: test
# Level: medium
# Author: Tim Rauch (rule), Elastic (idea)
# Date: 2022-10-17
# Tags: attack.stealth, attack.t1059, attack.t1204, attack.execution, attack.t1140, attack.s0482, attack.s0402
# Description: Detects when a built-in utility is used to decode and decrypt a payload after a macOS disk image (DMG) is executed. Malware authors may attempt to evade detection and trick users into executing malicious code by encoding and encrypting their payload and placing it in a disk image file. This behavior is consistent with adware or malware families such as Bundlore and Shlayer.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Payload Decoded and Decrypted via Built-in Utilities
def rule(event):
    # Detection Logic:
    # (Image="*/openssl" AND (CommandLine="*/Volumes/*" AND CommandLine="*enc*" AND CommandLine="*-base64*" AND CommandLine="* -d *"))
    return True

def title(event):
    return "Payload Decoded and Decrypted via Built-in Utilities"

