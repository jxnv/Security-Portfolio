-- Title: Potential RDP Tunneling Via SSH
-- ID: f7d7ebd5-a016-46e2-9c54-f9932f2d386d
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-12
-- Tags: attack.command-and-control, attack.t1572
-- Description: Execution of ssh.exe to perform data exfiltration and tunneling through RDP
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*\\ssh.exe" AND CommandLine LIKE '%:3389%')
