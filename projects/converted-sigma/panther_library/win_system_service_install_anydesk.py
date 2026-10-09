# Title: Anydesk Remote Access Software Service Installation
# ID: 530a6faa-ff3d-4022-b315-50828e77eef5
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2022-08-11
# Tags: attack.persistence
# Description: Detects the installation of the anydesk software service. Which could be an indication of anydesk abuse if you the software isn't already used.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Anydesk Remote Access Software Service Installation
def rule(event):
    # Detection Logic:
    # ((Provider_Name="Service Control Manager" AND EventID="7045") AND (((ServiceName="*AnyDesk*" AND ServiceName="*Service*")) OR (ImagePath="*AnyDesk*")))
    return True

def title(event):
    return "Anydesk Remote Access Software Service Installation"

