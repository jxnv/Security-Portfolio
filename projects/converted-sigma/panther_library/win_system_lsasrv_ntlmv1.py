# Title: NTLMv1 Logon Between Client and Server
# ID: e9d4ab66-a532-4ef7-a502-66a9e4a34f5d
# Status: test
# Level: medium
# Author: Tim Shelton, Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-04-26
# Tags: attack.lateral-movement, attack.t1550.002
# Description: Detects the reporting of NTLMv1 being used between a client and server. NTLMv1 is insecure as the underlying encryption algorithms can be brute-forced by modern hardware.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: NTLMv1 Logon Between Client and Server
def rule(event):
    # Detection Logic:
    # (Provider_Name="LsaSrv" AND (EventID="6038" OR EventID="6039"))
    return True

def title(event):
    return "NTLMv1 Logon Between Client and Server"

