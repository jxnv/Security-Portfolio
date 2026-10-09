-- Title: Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet
-- ID: c8a180d6-47a3-4345-a609-53f9c3d834fc
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-10
-- Tags: attack.discovery, attack.t1087.001
-- Description: Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%Get-LocalGroupMember %') AND ((CommandLine LIKE '%domain admins%' OR CommandLine LIKE '% administrator%' OR CommandLine LIKE '% administrateur%' OR CommandLine LIKE '%enterprise admins%' OR CommandLine LIKE '%Exchange Trusted Subsystem%' OR CommandLine LIKE '%Remote Desktop Users%' OR CommandLine LIKE '%Utilisateurs du Bureau à distance%' OR CommandLine LIKE '%Usuarios de escritorio remoto%')))
