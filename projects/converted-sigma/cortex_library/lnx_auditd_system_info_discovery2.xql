// Title: System and Hardware Information Discovery
// ID: 1f358e2e-cb63-43c3-b575-dfb072a6814f
// Status: stable
// Level: informational
// Author: Ömer Günal, oscd.community
// Date: 2020-10-08
// Tags: attack.discovery, attack.t1082
// Description: Detects system information discovery commands
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (type = "PATH" and (name = "/sys/class/dmi/id/bios_version" or name = "/sys/class/dmi/id/product_name" or name = "/sys/class/dmi/id/chassis_vendor" or name = "/proc/scsi/scsi" or name = "/proc/ide/hd0/model" or name = "/proc/version" or name = "/etc/*version" or name = "/etc/*release" or name = "/etc/issue"))
