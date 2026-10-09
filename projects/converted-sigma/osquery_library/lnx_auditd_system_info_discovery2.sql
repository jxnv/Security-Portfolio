-- Title: System and Hardware Information Discovery
-- ID: 1f358e2e-cb63-43c3-b575-dfb072a6814f
-- Status: stable
-- Level: informational
-- Author: Ömer Günal, oscd.community
-- Date: 2020-10-08
-- Tags: attack.discovery, attack.t1082
-- Description: Detects system information discovery commands
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (type = 'PATH' AND (name = '/sys/class/dmi/id/bios_version' OR name = '/sys/class/dmi/id/product_name' OR name = '/sys/class/dmi/id/chassis_vendor' OR name = '/proc/scsi/scsi' OR name = '/proc/ide/hd0/model' OR name = '/proc/version' OR name = '/etc/*version' OR name = '/etc/*release' OR name = '/etc/issue'))
