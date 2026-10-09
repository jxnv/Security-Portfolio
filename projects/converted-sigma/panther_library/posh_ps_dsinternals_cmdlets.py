# Title: DSInternals Suspicious PowerShell Cmdlets - ScriptBlock
# ID: 846c7a87-8e14-4569-9d49-ecfd4276a01c
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2024-06-26
# Tags: attack.execution, attack.t1059.001
# Description: Detects execution and usage of the DSInternals PowerShell module. Which can be used to perform what might be considered as suspicious activity such as dumping DPAPI backup keys or manipulating NTDS.DIT files.
# The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory. These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DSInternals Suspicious PowerShell Cmdlets - ScriptBlock
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*Add-ADDBSidHistory*" OR ScriptBlockText="*Add-ADNgcKey*" OR ScriptBlockText="*Add-ADReplNgcKey*" OR ScriptBlockText="*ConvertFrom-ADManagedPasswordBlob*" OR ScriptBlockText="*ConvertFrom-GPPrefPassword*" OR ScriptBlockText="*ConvertFrom-ManagedPasswordBlob*" OR ScriptBlockText="*ConvertFrom-UnattendXmlPassword*" OR ScriptBlockText="*ConvertFrom-UnicodePassword*" OR ScriptBlockText="*ConvertTo-AADHash*" OR ScriptBlockText="*ConvertTo-GPPrefPassword*" OR ScriptBlockText="*ConvertTo-KerberosKey*" OR ScriptBlockText="*ConvertTo-LMHash*" OR ScriptBlockText="*ConvertTo-MsoPasswordHash*" OR ScriptBlockText="*ConvertTo-NTHash*" OR ScriptBlockText="*ConvertTo-OrgIdHash*" OR ScriptBlockText="*ConvertTo-UnicodePassword*" OR ScriptBlockText="*Disable-ADDBAccount*" OR ScriptBlockText="*Enable-ADDBAccount*" OR ScriptBlockText="*Get-ADDBAccount*" OR ScriptBlockText="*Get-ADDBBackupKey*" OR ScriptBlockText="*Get-ADDBDomainController*" OR ScriptBlockText="*Get-ADDBGroupManagedServiceAccount*" OR ScriptBlockText="*Get-ADDBKdsRootKey*" OR ScriptBlockText="*Get-ADDBSchemaAttribute*" OR ScriptBlockText="*Get-ADDBServiceAccount*" OR ScriptBlockText="*Get-ADDefaultPasswordPolicy*" OR ScriptBlockText="*Get-ADKeyCredential*" OR ScriptBlockText="*Get-ADPasswordPolicy*" OR ScriptBlockText="*Get-ADReplAccount*" OR ScriptBlockText="*Get-ADReplBackupKey*" OR ScriptBlockText="*Get-ADReplicationAccount*" OR ScriptBlockText="*Get-ADSIAccount*" OR ScriptBlockText="*Get-AzureADUserEx*" OR ScriptBlockText="*Get-BootKey*" OR ScriptBlockText="*Get-KeyCredential*" OR ScriptBlockText="*Get-LsaBackupKey*" OR ScriptBlockText="*Get-LsaPolicy*" OR ScriptBlockText="*Get-SamPasswordPolicy*" OR ScriptBlockText="*Get-SysKey*" OR ScriptBlockText="*Get-SystemKey*" OR ScriptBlockText="*New-ADDBRestoreFromMediaScript*" OR ScriptBlockText="*New-ADKeyCredential*" OR ScriptBlockText="*New-ADNgcKey*" OR ScriptBlockText="*New-NTHashSet*" OR ScriptBlockText="*Remove-ADDBObject*" OR ScriptBlockText="*Save-DPAPIBlob*" OR ScriptBlockText="*Set-ADAccountPasswordHash*" OR ScriptBlockText="*Set-ADDBAccountPassword*" OR ScriptBlockText="*Set-ADDBBootKey*" OR ScriptBlockText="*Set-ADDBDomainController*" OR ScriptBlockText="*Set-ADDBPrimaryGroup*" OR ScriptBlockText="*Set-ADDBSysKey*" OR ScriptBlockText="*Set-AzureADUserEx*" OR ScriptBlockText="*Set-LsaPolicy*" OR ScriptBlockText="*Set-SamAccountPasswordHash*" OR ScriptBlockText="*Set-WinUserPasswordHash*" OR ScriptBlockText="*Test-ADDBPasswordQuality*" OR ScriptBlockText="*Test-ADPasswordQuality*" OR ScriptBlockText="*Test-ADReplPasswordQuality*" OR ScriptBlockText="*Test-PasswordQuality*" OR ScriptBlockText="*Unlock-ADDBAccount*" OR ScriptBlockText="*Write-ADNgcKey*" OR ScriptBlockText="*Write-ADReplNgcKey*"))
    return True

def title(event):
    return "DSInternals Suspicious PowerShell Cmdlets - ScriptBlock"

