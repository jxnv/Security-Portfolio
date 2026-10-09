# Title: Tor Client/Browser Execution
# ID: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c
# Status: test
# Level: high
# Author: frack113
# Date: 2022-02-20
# Tags: attack.command-and-control, attack.t1090.003
# Description: Detects the use of Tor or Tor-Browser to connect to onion routing networks
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Tor Client/Browser Execution
def rule(event):
    # Detection Logic:
    # ((Description="Tor Browser") OR (Product="Tor Browser") OR ((Image="*\\tor.exe" OR Image="*\\Tor Browser\\Browser\\firefox.exe")))
    return True

def title(event):
    return "Tor Client/Browser Execution"

