-- Title: BPFDoor Abnormal Process ID or Lock File Accessed
-- ID: 808146b2-9332-4d78-9416-d7e47012d83d
-- Status: test
-- Level: high
-- Author: Rafal Piasecki
-- Date: 2022-08-10
-- Tags: attack.execution, attack.t1106, attack.t1059
-- Description: detects BPFDoor .lock and .pid files access in temporary file storage facility
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (type = 'PATH' AND (name = '/var/run/aepmonend.pid' OR name = '/var/run/auditd.lock' OR name = '/var/run/cma.lock' OR name = '/var/run/console-kit.pid' OR name = '/var/run/consolekit.pid' OR name = '/var/run/daemon.pid' OR name = '/var/run/hald-addon.pid' OR name = '/var/run/hald-smartd.pid' OR name = '/var/run/haldrund.pid' OR name = '/var/run/hp-health.pid' OR name = '/var/run/hpasmlit.lock' OR name = '/var/run/hpasmlited.pid' OR name = '/var/run/kdevrund.pid' OR name = '/var/run/lldpad.lock' OR name = '/var/run/mcelog.pid' OR name = '/var/run/system.pid' OR name = '/var/run/uvp-srv.pid' OR name = '/var/run/vmtoolagt.pid' OR name = '/var/run/xinetd.lock'))
