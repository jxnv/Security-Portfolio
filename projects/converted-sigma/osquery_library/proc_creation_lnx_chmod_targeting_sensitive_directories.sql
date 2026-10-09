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

SELECT * FROM processes WHERE ((Image="*/chmod" AND (CommandLine LIKE '%/tmp/%' OR CommandLine LIKE '%/.Library/%' OR CommandLine LIKE '%/etc/%' OR CommandLine LIKE '%/opt/%')) AND NOT (((CommandLine="chmod 700 /tmp/apt-key-gpghome.*") OR (CommandLine = 'chmod 0775 /etc/landscape/') OR (CommandLine="chmod 755 /var/tmp/mkinitramfs*") OR (CommandLine LIKE '%/etc/%' AND (ParentCommandLine LIKE '%/var/lib/dpkg/info/%' AND ParentCommandLine LIKE '%.postinst configure%')) OR (CommandLine = 'chmod 644 /etc/apparmor.d/tunables/home.d/ubuntu') OR (CommandLine LIKE '%chmod --reference=/etc/shells%' AND ParentCommandLine="*/update-shells"))))
