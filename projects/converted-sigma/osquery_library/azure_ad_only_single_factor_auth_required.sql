-- Title: Azure AD Only Single Factor Authentication Required
-- ID: 28eea407-28d7-4e42-b0be-575d5ba60b2c
-- Status: test
-- Level: low
-- Author: MikeDuddington, '@dudders1'
-- Date: 2022-07-27
-- Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.credential-access, attack.stealth, attack.defense-impairment, attack.t1078.004, attack.t1556.006
-- Description: Detect when users are authenticating without MFA being required.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Status = 'Success' AND AuthenticationRequirement = 'singleFactorAuthentication')
