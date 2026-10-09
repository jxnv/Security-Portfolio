-- Title: Auditing Configuration Changes on Linux Host
-- ID: 977ef627-4539-4875-adf4-ed8f780c4922
-- Status: test
-- Level: high
-- Author: Mikhail Larin, oscd.community
-- Date: 2019-10-25
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detect changes in auditd configuration files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (type = 'PATH' AND (name = '/etc/audit/*' OR name = '/etc/libaudit.conf' OR name = '/etc/audisp/*'))
