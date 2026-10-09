-- Title: Non-privileged Usage of Reg or Powershell
-- ID: 8f02c935-effe-45b3-8fc9-ef8696a9e41d
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community
-- Date: 2020-10-05
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%reg %' AND CommandLine LIKE '%add%')) OR ((CommandLine LIKE '%powershell%' OR CommandLine LIKE '%set-itemproperty%' OR CommandLine LIKE '% sp %' OR CommandLine LIKE '%new-itemproperty%'))) AND ((IntegrityLevel = 'Medium' OR IntegrityLevel = 'S-1-16-8192') AND (CommandLine LIKE '%ControlSet%' AND CommandLine LIKE '%Services%') AND (CommandLine LIKE '%ImagePath%' OR CommandLine LIKE '%FailureCommand%' OR CommandLine LIKE '%ServiceDLL%')))
