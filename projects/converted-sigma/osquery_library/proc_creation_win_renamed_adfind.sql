-- Title: Renamed AdFind Execution
-- ID: df55196f-f105-44d3-a675-e9dfb6cc2f2b
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-21
-- Tags: attack.discovery, attack.t1018, attack.t1087.002, attack.t1482, attack.t1069.002
-- Description: Detects the use of a renamed Adfind.exe. AdFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%domainlist%' OR CommandLine LIKE '%trustdmp%' OR CommandLine LIKE '%dcmodes%' OR CommandLine LIKE '%adinfo%' OR CommandLine LIKE '% dclist %' OR CommandLine LIKE '%computer_pwdnotreqd%' OR CommandLine LIKE '%objectcategory=%' OR CommandLine LIKE '%-subnets -f%' OR CommandLine LIKE '%name=\"Domain Admins\"%' OR CommandLine LIKE '%-sc u:%' OR CommandLine LIKE '%domainncs%' OR CommandLine LIKE '%dompol%' OR CommandLine LIKE '% oudmp %' OR CommandLine LIKE '%subnetdmp%' OR CommandLine LIKE '%gpodmp%' OR CommandLine LIKE '%fspdmp%' OR CommandLine LIKE '%users_noexpire%' OR CommandLine LIKE '%computers_active%' OR CommandLine LIKE '%computers_pwdnotreqd%')) OR ((Hashes LIKE '%IMPHASH=BCA5675746D13A1F246E2DA3C2217492%' OR Hashes LIKE '%IMPHASH=53E117A96057EAF19C41380D0E87F1C2%' OR Hashes LIKE '%IMPHASH=d144de8117df2beceaba2201ad304764%' OR Hashes LIKE '%IMPHASH=12ce1c0f3f5837ecc18a3782408fa975%' OR Hashes LIKE '%IMPHASH=4fbf3f084fbbb2470b80b2013134df35%' OR Hashes LIKE '%IMPHASH=49b639b4acbecc49d72a01f357aa4930%' OR Hashes LIKE '%IMPHASH=680dad9e300346e05a85023965867201%' OR Hashes LIKE '%IMPHASH=21aa085d54992511b9f115355e468782%')) OR (OriginalFileName = 'AdFind.exe')) AND NOT ((Image="*\\AdFind.exe")))
