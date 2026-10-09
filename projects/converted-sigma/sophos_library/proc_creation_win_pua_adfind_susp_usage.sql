-- Title: PUA - AdFind Suspicious Execution
-- ID: 9a132afa-654e-11eb-ae93-0242ac130002
-- Status: test
-- Level: high
-- Author: Janantha Marasinghe (https://github.com/blueteam0ps), FPT.EagleEye Team, omkar72, oscd.community
-- Date: 2021-02-02
-- Tags: attack.discovery, attack.t1018, attack.t1087.002, attack.t1482, attack.t1069.002, stp.1u
-- Description: Detects AdFind execution with common flags seen used during attacks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%domainlist%' OR CommandLine ILIKE '%trustdmp%' OR CommandLine ILIKE '%dcmodes%' OR CommandLine ILIKE '%adinfo%' OR CommandLine ILIKE '%-sc dclist%' OR CommandLine ILIKE '%computer_pwdnotreqd%' OR CommandLine ILIKE '%objectcategory=%' OR CommandLine ILIKE '%-subnets -f%' OR CommandLine ILIKE '%name=\"Domain Admins\"%' OR CommandLine ILIKE '%-sc u:%' OR CommandLine ILIKE '%domainncs%' OR CommandLine ILIKE '%dompol%' OR CommandLine ILIKE '% oudmp %' OR CommandLine ILIKE '%subnetdmp%' OR CommandLine ILIKE '%gpodmp%' OR CommandLine ILIKE '%fspdmp%' OR CommandLine ILIKE '%users_noexpire%' OR CommandLine ILIKE '%computers_active%' OR CommandLine ILIKE '%computers_pwdnotreqd%'))
