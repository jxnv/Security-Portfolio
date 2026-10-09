-- Title: PUA - AdFind Suspicious Execution
-- ID: 9a132afa-654e-11eb-ae93-0242ac130002
-- Status: test
-- Level: high
-- Author: Janantha Marasinghe (https://github.com/blueteam0ps), FPT.EagleEye Team, omkar72, oscd.community
-- Date: 2021-02-02
-- Tags: attack.discovery, attack.t1018, attack.t1087.002, attack.t1482, attack.t1069.002, stp.1u
-- Description: Detects AdFind execution with common flags seen used during attacks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%domainlist%' OR CommandLine LIKE '%trustdmp%' OR CommandLine LIKE '%dcmodes%' OR CommandLine LIKE '%adinfo%' OR CommandLine LIKE '%-sc dclist%' OR CommandLine LIKE '%computer_pwdnotreqd%' OR CommandLine LIKE '%objectcategory=%' OR CommandLine LIKE '%-subnets -f%' OR CommandLine LIKE '%name=\"Domain Admins\"%' OR CommandLine LIKE '%-sc u:%' OR CommandLine LIKE '%domainncs%' OR CommandLine LIKE '%dompol%' OR CommandLine LIKE '% oudmp %' OR CommandLine LIKE '%subnetdmp%' OR CommandLine LIKE '%gpodmp%' OR CommandLine LIKE '%fspdmp%' OR CommandLine LIKE '%users_noexpire%' OR CommandLine LIKE '%computers_active%' OR CommandLine LIKE '%computers_pwdnotreqd%'))
