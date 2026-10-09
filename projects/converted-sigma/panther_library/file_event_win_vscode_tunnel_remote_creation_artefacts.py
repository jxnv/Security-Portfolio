# Title: Visual Studio Code Tunnel Remote File Creation
# ID: 56e05d41-ce99-4ecd-912d-93f019ee0b71
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-10-25
# Tags: attack.command-and-control
# Description: Detects the creation of file by the "node.exe" process in the ".vscode-server" directory. Could be a sign of remote file creation via VsCode tunnel feature
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Visual Studio Code Tunnel Remote File Creation
def rule(event):
    # Detection Logic:
    # (Image="*\\servers\\Stable-*" AND Image="*\\server\\node.exe" AND TargetFilename="*\\.vscode-server\\data\\User\\History\\*")
    return True

def title(event):
    return "Visual Studio Code Tunnel Remote File Creation"

