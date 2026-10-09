-- Title: Chmod Targeting Sensitive Directories
-- ID: 6419afd1-3742-47a5-a7e6-b50386cd15f8
-- Status: test
-- Level: medium
-- Author: Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
-- Date: 2022-06-03
-- Tags: attack.defense-impairment, attack.t1222.002
-- Description: Detects chmod targeting files in sensitive directory paths on Linux systems.
-- Attackers may use chmod to change permissions of files in these directories to maintain persistence, escalate privileges, or disrupt system operations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%/chmod' AND (CommandLine ILIKE '%/tmp/%' OR CommandLine ILIKE '%/.Library/%' OR CommandLine ILIKE '%/etc/%' OR CommandLine ILIKE '%/opt/%')) AND NOT (((CommandLine ILIKE 'chmod 700 /tmp/apt-key-gpghome.%') OR (CommandLine = 'chmod 0775 /etc/landscape/') OR (CommandLine ILIKE 'chmod 755 /var/tmp/mkinitramfs%') OR (CommandLine ILIKE '%/etc/%' AND (ParentCommandLine ILIKE '%/var/lib/dpkg/info/%' AND ParentCommandLine ILIKE '%.postinst configure%')) OR (CommandLine = 'chmod 644 /etc/apparmor.d/tunables/home.d/ubuntu') OR (CommandLine ILIKE '%chmod --reference=/etc/shells%' AND ParentCommandLine ILIKE '%/update-shells'))))
