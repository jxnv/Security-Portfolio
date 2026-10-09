# Title: HackTool - SharpView Execution
# ID: b2317cfa-4a47-4ead-b3ff-297438c0bc2d
# Status: test
# Level: high
# Author: frack113
# Date: 2021-12-10
# Tags: attack.discovery, attack.t1049, attack.t1069.002, attack.t1482, attack.t1135, attack.t1033
# Description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - SharpView Execution
def rule(event):
    # Detection Logic:
    # ((OriginalFileName="SharpView.exe") OR (Image="*\\SharpView.exe") OR ((CommandLine="*Add-RemoteConnection*" OR CommandLine="*Convert-ADName*" OR CommandLine="*ConvertFrom-SID*" OR CommandLine="*ConvertFrom-UACValue*" OR CommandLine="*Convert-SidToName*" OR CommandLine="*Export-PowerViewCSV*" OR CommandLine="*Find-DomainObjectPropertyOutlier*" OR CommandLine="*Find-DomainProcess*" OR CommandLine="*Find-DomainShare*" OR CommandLine="*Find-DomainUserEvent*" OR CommandLine="*Find-DomainUserLocation*" OR CommandLine="*Find-ForeignGroup*" OR CommandLine="*Find-ForeignUser*" OR CommandLine="*Find-GPOComputerAdmin*" OR CommandLine="*Find-GPOLocation*" OR CommandLine="*Find-Interesting*" OR CommandLine="*Find-LocalAdminAccess*" OR CommandLine="*Find-ManagedSecurityGroups*" OR CommandLine="*Get-CachedRDPConnection*" OR CommandLine="*Get-DFSshare*" OR CommandLine="*Get-DomainComputer*" OR CommandLine="*Get-DomainController*" OR CommandLine="*Get-DomainDFSShare*" OR CommandLine="*Get-DomainDNSRecord*" OR CommandLine="*Get-DomainFileServer*" OR CommandLine="*Get-DomainForeign*" OR CommandLine="*Get-DomainGPO*" OR CommandLine="*Get-DomainGroup*" OR CommandLine="*Get-DomainGUIDMap*" OR CommandLine="*Get-DomainManagedSecurityGroup*" OR CommandLine="*Get-DomainObject*" OR CommandLine="*Get-DomainOU*" OR CommandLine="*Get-DomainPolicy*" OR CommandLine="*Get-DomainSID*" OR CommandLine="*Get-DomainSite*" OR CommandLine="*Get-DomainSPNTicket*" OR CommandLine="*Get-DomainSubnet*" OR CommandLine="*Get-DomainTrust*" OR CommandLine="*Get-DomainUserEvent*" OR CommandLine="*Get-ForestDomain*" OR CommandLine="*Get-ForestGlobalCatalog*" OR CommandLine="*Get-ForestTrust*" OR CommandLine="*Get-GptTmpl*" OR CommandLine="*Get-GroupsXML*" OR CommandLine="*Get-LastLoggedOn*" OR CommandLine="*Get-LoggedOnLocal*" OR CommandLine="*Get-NetComputer*" OR CommandLine="*Get-NetDomain*" OR CommandLine="*Get-NetFileServer*" OR CommandLine="*Get-NetForest*" OR CommandLine="*Get-NetGPO*" OR CommandLine="*Get-NetGroupMember*" OR CommandLine="*Get-NetLocalGroup*" OR CommandLine="*Get-NetLoggedon*" OR CommandLine="*Get-NetOU*" OR CommandLine="*Get-NetProcess*" OR CommandLine="*Get-NetRDPSession*" OR CommandLine="*Get-NetSession*" OR CommandLine="*Get-NetShare*" OR CommandLine="*Get-NetSite*" OR CommandLine="*Get-NetSubnet*" OR CommandLine="*Get-NetUser*" OR CommandLine="*Get-PathAcl*" OR CommandLine="*Get-PrincipalContext*" OR CommandLine="*Get-RegistryMountedDrive*" OR CommandLine="*Get-RegLoggedOn*" OR CommandLine="*Get-WMIRegCachedRDPConnection*" OR CommandLine="*Get-WMIRegLastLoggedOn*" OR CommandLine="*Get-WMIRegMountedDrive*" OR CommandLine="*Get-WMIRegProxy*" OR CommandLine="*Invoke-ACLScanner*" OR CommandLine="*Invoke-CheckLocalAdminAccess*" OR CommandLine="*Invoke-Kerberoast*" OR CommandLine="*Invoke-MapDomainTrust*" OR CommandLine="*Invoke-RevertToSelf*" OR CommandLine="*Invoke-Sharefinder*" OR CommandLine="*Invoke-UserImpersonation*" OR CommandLine="*Remove-DomainObjectAcl*" OR CommandLine="*Remove-RemoteConnection*" OR CommandLine="*Request-SPNTicket*" OR CommandLine="*Set-DomainObject*" OR CommandLine="*Test-AdminAccess*")))
    return True

def title(event):
    return "HackTool - SharpView Execution"

