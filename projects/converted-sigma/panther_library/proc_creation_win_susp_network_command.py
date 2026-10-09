# Title: Suspicious Network Command
# ID: a29c1813-ab1f-4dde-b489-330b952e91ae
# Status: test
# Level: low
# Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
# Date: 2021-12-07
# Tags: attack.discovery, attack.t1016
# Description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Network Command
def rule(event):
    # Detection Logic:
    # ((CommandLine=regex("ipconfig\\s+/all") OR CommandLine=regex("netsh\\s+interface show interface") OR CommandLine=regex("arp\\s+-a") OR CommandLine=regex("nbtstat\\s+-n") OR CommandLine=regex("net\\s+config") OR CommandLine=regex("route\\s+print")))
    return True

def title(event):
    return "Suspicious Network Command"

