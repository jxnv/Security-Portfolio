# Title: Gzip Archive Decode Via PowerShell
# ID: 98767d61-b2e8-4d71-b661-e36783ee24c1
# Status: test
# Level: medium
# Author: Hieu Tran
# Date: 2023-03-13
# Tags: attack.command-and-control, attack.t1132.001
# Description: Detects attempts of decoding encoded Gzip archives via PowerShell.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Gzip Archive Decode Via PowerShell
def rule(event):
    # Detection Logic:
    # ((CommandLine="*GZipStream*" AND CommandLine="*::Decompress*"))
    return True

def title(event):
    return "Gzip Archive Decode Via PowerShell"

