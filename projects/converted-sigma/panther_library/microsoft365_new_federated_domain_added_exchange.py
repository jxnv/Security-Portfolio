# Title: New Federated Domain Added - Exchange
# ID: 42127bdd-9133-474f-a6f1-97b6c08a4339
# Status: test
# Level: medium
# Author: Splunk Threat Research Team (original rule), '@ionsor (rule)'
# Date: 2022-02-08
# Tags: attack.persistence, attack.t1136.003
# Description: Detects the addition of a new Federated Domain.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New Federated Domain Added - Exchange
def rule(event):
    # Detection Logic:
    # (eventSource="Exchange" AND eventName="Add-FederatedDomain" AND status="success")
    return True

def title(event):
    return "New Federated Domain Added - Exchange"

