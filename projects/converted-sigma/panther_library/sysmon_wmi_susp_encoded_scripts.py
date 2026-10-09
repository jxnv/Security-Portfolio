# Title: Suspicious Encoded Scripts in a WMI Consumer
# ID: 83844185-1c5b-45bc-bcf3-b5bf3084ca5b
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2021-09-01
# Tags: attack.privilege-escalation, attack.execution, attack.t1047, attack.persistence, attack.t1546.003
# Description: Detects suspicious encoded payloads in WMI Event Consumers
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Encoded Scripts in a WMI Consumer
def rule(event):
    # Detection Logic:
    # ((Destination="*V3JpdGVQcm9jZXNzTWVtb3J5*" OR Destination="*dyaXRlUHJvY2Vzc01lbW9ye*" OR Destination="*Xcml0ZVByb2Nlc3NNZW1vcn*" OR Destination="*VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG*" OR Destination="*RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl*" OR Destination="*UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ*" OR Destination="*VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVyIFdpbjMy*" OR Destination="*RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlciBXaW4zM*" OR Destination="*UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZXIgV2luMz*"))
    return True

def title(event):
    return "Suspicious Encoded Scripts in a WMI Consumer"

