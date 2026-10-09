# Title: SQLite Firefox Profile Data DB Access
# ID: 4833155a-4053-4c9c-a997-777fcea0baa7
# Status: test
# Level: high
# Author: frack113
# Date: 2022-04-08
# Tags: attack.credential-access, attack.t1539, attack.collection, attack.t1005
# Description: Detect usage of the "sqlite" binary to query databases in Firefox and other Gecko-based browsers for potential data stealing.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: SQLite Firefox Profile Data DB Access
def rule(event):
    # Detection Logic:
    # (((CommandLine="*cookies.sqlite*" OR CommandLine="*places.sqlite*")) AND ((Product="SQLite") OR ((Image="*\\sqlite.exe" OR Image="*\\sqlite3.exe"))))
    return True

def title(event):
    return "SQLite Firefox Profile Data DB Access"

