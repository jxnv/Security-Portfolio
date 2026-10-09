-- Title: Renamed AdFind Execution
-- ID: df55196f-f105-44d3-a675-e9dfb6cc2f2b
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-21
-- Tags: attack.discovery, attack.t1018, attack.t1087.002, attack.t1482, attack.t1069.002
-- Description: Detects the use of a renamed Adfind.exe. AdFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%domainlist%' OR CommandLine ILIKE '%trustdmp%' OR CommandLine ILIKE '%dcmodes%' OR CommandLine ILIKE '%adinfo%' OR CommandLine ILIKE '% dclist %' OR CommandLine ILIKE '%computer_pwdnotreqd%' OR CommandLine ILIKE '%objectcategory=%' OR CommandLine ILIKE '%-subnets -f%' OR CommandLine ILIKE '%name=\"Domain Admins\"%' OR CommandLine ILIKE '%-sc u:%' OR CommandLine ILIKE '%domainncs%' OR CommandLine ILIKE '%dompol%' OR CommandLine ILIKE '% oudmp %' OR CommandLine ILIKE '%subnetdmp%' OR CommandLine ILIKE '%gpodmp%' OR CommandLine ILIKE '%fspdmp%' OR CommandLine ILIKE '%users_noexpire%' OR CommandLine ILIKE '%computers_active%' OR CommandLine ILIKE '%computers_pwdnotreqd%')) OR ((Hashes ILIKE '%IMPHASH=BCA5675746D13A1F246E2DA3C2217492%' OR Hashes ILIKE '%IMPHASH=53E117A96057EAF19C41380D0E87F1C2%' OR Hashes ILIKE '%IMPHASH=d144de8117df2beceaba2201ad304764%' OR Hashes ILIKE '%IMPHASH=12ce1c0f3f5837ecc18a3782408fa975%' OR Hashes ILIKE '%IMPHASH=4fbf3f084fbbb2470b80b2013134df35%' OR Hashes ILIKE '%IMPHASH=49b639b4acbecc49d72a01f357aa4930%' OR Hashes ILIKE '%IMPHASH=680dad9e300346e05a85023965867201%' OR Hashes ILIKE '%IMPHASH=21aa085d54992511b9f115355e468782%')) OR (OriginalFileName = 'AdFind.exe')) AND NOT ((Image ILIKE '%\\AdFind.exe')))
