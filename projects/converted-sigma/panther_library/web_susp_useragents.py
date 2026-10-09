# Title: Suspicious User-Agents Related To Recon Tools
# ID: 19aa4f58-94ca-45ff-bc34-92e533c0994a
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), Tim Shelton
# Date: 2022-07-19
# Tags: attack.initial-access, attack.t1190
# Description: Detects known suspicious (default) user-agents related to scanning/recon tools
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious User-Agents Related To Recon Tools
def rule(event):
    # Detection Logic:
    # ((cs-user-agent="*commix/*" OR cs-user-agent="*feroxbuster/*" OR cs-user-agent="*Fuzz Faster U Fool*" OR cs-user-agent="*GIS - AppSec Team - Project Vision*" OR cs-user-agent="*gobuster/*" OR cs-user-agent="*Nikto/*" OR cs-user-agent="*Nmap Scripting Engine*" OR cs-user-agent="*Recon-ng/v*" OR cs-user-agent="*sqlmap/*" OR cs-user-agent="*WhatWeb/*" OR cs-user-agent="*Wfuzz/*" OR cs-user-agent="*WPScan v*" OR cs-user-agent="*zgrab/*"))
    return True

def title(event):
    return "Suspicious User-Agents Related To Recon Tools"

