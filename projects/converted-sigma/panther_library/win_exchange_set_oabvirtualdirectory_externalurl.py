# Title: Exchange Set OabVirtualDirectory ExternalUrl Property
# ID: 9db37458-4df2-46a5-95ab-307e7f29e675
# Status: test
# Level: high
# Author: Jose Rodriguez @Cyb3rPandaH
# Date: 2021-03-15
# Tags: attack.persistence, attack.t1505.003
# Description: Rule to detect an adversary setting OabVirtualDirectory External URL property to a script in Exchange Management log
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Exchange Set OabVirtualDirectory ExternalUrl Property
def rule(event):
    # Detection Logic:
    # ((="Set-OabVirtualDirectory" AND ="ExternalUrl" AND ="Page_Load" AND ="script"))
    return True

def title(event):
    return "Exchange Set OabVirtualDirectory ExternalUrl Property"

