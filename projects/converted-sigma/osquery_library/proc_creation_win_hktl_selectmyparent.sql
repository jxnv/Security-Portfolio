-- Title: HackTool - PPID Spoofing SelectMyParent Tool Execution
-- ID: 52ff7941-8211-46f9-84f8-9903efb7077d
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-07-23
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1134.004
-- Description: Detects the use of parent process ID spoofing tools like Didier Stevens tool SelectMyParent
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\SelectMyParent.exe") OR ((CommandLine LIKE '%PPID-spoof%' OR CommandLine LIKE '%ppid_spoof%' OR CommandLine LIKE '%spoof-ppid%' OR CommandLine LIKE '%spoof_ppid%' OR CommandLine LIKE '%ppidspoof%' OR CommandLine LIKE '%spoofppid%' OR CommandLine LIKE '%spoofedppid%' OR CommandLine LIKE '% -spawnto %')) OR ((OriginalFileName LIKE '%PPID-spoof%' OR OriginalFileName LIKE '%ppid_spoof%' OR OriginalFileName LIKE '%spoof-ppid%' OR OriginalFileName LIKE '%spoof_ppid%' OR OriginalFileName LIKE '%ppidspoof%' OR OriginalFileName LIKE '%spoofppid%' OR OriginalFileName LIKE '%spoofedppid%')) OR (Description = 'SelectMyParent') OR ((Hashes LIKE '%IMPHASH=04D974875BD225F00902B4CAD9AF3FBC%' OR Hashes LIKE '%IMPHASH=A782AF154C9E743DDF3F3EB2B8F3D16E%' OR Hashes LIKE '%IMPHASH=89059503D7FBF470E68F7E63313DA3AD%' OR Hashes LIKE '%IMPHASH=CA28337632625C8281AB8A130B3D6BAD%')))
