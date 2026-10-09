-- Title: Potential Credential Dumping Attempt Using New NetworkProvider - REG
-- ID: 0442defa-b4a2-41c9-ae2c-ea7042fc4701
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-23
-- Tags: attack.credential-access, attack.t1003
-- Description: Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%\\System\\CurrentControlSet\\Services\\%' AND TargetObject LIKE '%\\NetworkProvider%')) AND NOT ((((TargetObject LIKE '%\\System\\CurrentControlSet\\Services\\WebClient\\NetworkProvider%' OR TargetObject LIKE '%\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\NetworkProvider%' OR TargetObject LIKE '%\\System\\CurrentControlSet\\Services\\RDPNP\\NetworkProvider%')) OR (Image = 'C:\\Windows\\System32\\poqexec.exe'))))
