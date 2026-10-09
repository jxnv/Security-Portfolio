-- Title: Linux Keylogging with Pam.d
-- ID: 49aae26c-450e-448b-911d-b3c13d178dfc
-- Status: test
-- Level: high
-- Author: Pawel Mazur
-- Date: 2021-05-24
-- Tags: attack.collection, attack.credential-access, attack.t1003, attack.t1056.001
-- Description: Detect attempt to enable auditing of TTY input
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((type = 'PATH' AND (name = '/etc/pam.d/system-auth' OR name = '/etc/pam.d/password-auth')) OR ((type = 'TTY' OR type = 'USER_TTY')))
