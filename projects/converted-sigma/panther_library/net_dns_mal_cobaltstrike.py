# Title: Cobalt Strike DNS Beaconing
# ID: 2975af79-28c4-4d2f-a951-9095f229df29
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2018-05-10
# Tags: attack.command-and-control, attack.t1071.004
# Description: Detects suspicious DNS queries known from Cobalt Strike beacons
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Cobalt Strike DNS Beaconing
def rule(event):
    # Detection Logic:
    # (((query="aaa.stage.*" OR query="post.1*")) OR (query="*.stage.123456.*"))
    return True

def title(event):
    return "Cobalt Strike DNS Beaconing"

