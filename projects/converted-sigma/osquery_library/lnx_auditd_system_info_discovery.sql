-- Title: System Information Discovery - Auditd
-- ID: f34047d9-20d3-4e8b-8672-0a35cc50dc71
-- Status: test
-- Level: low
-- Author: Pawel Mazur
-- Date: 2021-09-03
-- Tags: attack.discovery, attack.t1082
-- Description: Detects System Information Discovery commands
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((type = 'PATH' AND (name = '/etc/lsb-release' OR name = '/etc/redhat-release' OR name = '/etc/issue')) OR (type = 'EXECVE' AND (a0 = 'uname' OR a0 = 'uptime' OR a0 = 'lsmod' OR a0 = 'hostname' OR a0 = 'env')) OR (type = 'EXECVE' AND a0 = 'grep' AND (a1 LIKE '%vbox%' OR a1 LIKE '%vm%' OR a1 LIKE '%xen%' OR a1 LIKE '%virtio%' OR a1 LIKE '%hv%')) OR (type = 'EXECVE' AND a0 = 'kmod' AND a1 = 'list'))
