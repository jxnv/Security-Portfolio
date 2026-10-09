# Title: TeamViewer Domain Query By Non-TeamViewer Application
# ID: 778ba9a8-45e4-4b80-8e3e-34a419f0b85e
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2022-01-30
# Tags: attack.command-and-control, attack.t1219.002
# Description: Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: TeamViewer Domain Query By Non-TeamViewer Application
def rule(event):
    # Detection Logic:
    # (((QueryName="taf.teamviewer.com" OR QueryName="udp.ping.teamviewer.com")) AND NOT ((Image="*TeamViewer*")))
    return True

def title(event):
    return "TeamViewer Domain Query By Non-TeamViewer Application"

