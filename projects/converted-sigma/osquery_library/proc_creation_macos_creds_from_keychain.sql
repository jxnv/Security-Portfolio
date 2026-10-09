-- Title: Credentials from Password Stores - Keychain
-- ID: b120b587-a4c2-4b94-875d-99c9807d6955
-- Status: test
-- Level: medium
-- Author: Tim Ismilyaev, oscd.community, Florian Roth (Nextron Systems)
-- Date: 2020-10-19
-- Tags: attack.credential-access, attack.t1555.001
-- Description: Detects passwords dumps from Keychain
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image = '/usr/bin/security' AND (CommandLine LIKE '%find-certificate%' OR CommandLine LIKE '% export %')) OR ((CommandLine LIKE '% dump-keychain %' OR CommandLine LIKE '% login-keychain %')))
