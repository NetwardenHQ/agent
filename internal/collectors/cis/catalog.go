package cis

// CIS Red Hat Enterprise Linux 9 Benchmark — check catalog, Levels 1 and 2.
//
// Checks are table data, not functions. Several hundred rules stay reviewable
// that way, and every probe target below is a compile-time constant, which is
// what makes the trust model in the package doc hold.
//
// Rules for editing this file:
//
//   - Never change or reuse a shipped ID. Profiles reference ids, findings
//     dedupe on them, and history is keyed on them. Superseded checks get a
//     new id; the old one is deleted outright rather than repurposed.
//   - Expected values here are the benchmark's defaults. Operators override
//     them per-profile in the UI, so encode what CIS says even where it is
//     inconvenient (net.ipv4.ip_forward=0 is correct here even though routers
//     legitimately override it).
//   - Rationale is shown to a human next to a failure. Write what an operator
//     needs in order to decide, not a restatement of the title.

// Benchmark identifies the benchmark this catalog implements. Reported with
// results so the platform can flag a host whose OS does not match.
const Benchmark = "cis-rhel9"

// -----------------------------------------------------------------------------
// TABLE CONSTRUCTORS
// -----------------------------------------------------------------------------

// modDisabled: the kernel module must be neither loaded nor loadable.
func modDisabled(id, section, title string, level int, module, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeKernelModule, Target: module},
		Op:        OpEquals,
		Expected:  "disabled",
		Rationale: rationale,
	}
}

// sysctlIs: running kernel parameter must equal a value.
func sysctlIs(id, section, title string, level int, key, value, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeSysctl, Target: key},
		Op:        OpEquals,
		Expected:  value,
		Rationale: rationale,
	}
}

// svcDisabled: systemd unit must not be enabled. "not-found" also passes,
// since an uninstalled service cannot run.
func svcDisabled(id, section, title string, level int, unit, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeServiceEnabled, Target: unit},
		Op:        OpNotEquals,
		Expected:  "enabled",
		Rationale: rationale,
	}
}

// svcEnabled: systemd unit must be enabled.
func svcEnabled(id, section, title string, level int, unit, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeServiceEnabled, Target: unit},
		Op:        OpEquals,
		Expected:  "enabled",
		Rationale: rationale,
	}
}

// pkgAbsent / pkgInstalled: rpm database membership.
func pkgAbsent(id, section, title string, level int, pkg, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbePackageInstalled, Target: pkg},
		Op:        OpEquals,
		Expected:  "absent",
		Rationale: rationale,
	}
}

func pkgInstalled(id, section, title string, level int, pkg, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbePackageInstalled, Target: pkg},
		Op:        OpEquals,
		Expected:  "installed",
		Rationale: rationale,
	}
}

// fileMode: permissions must be no broader than the expected mode.
func fileMode(id, section, title string, level int, path, mode, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeFileMode, Target: path},
		Op:        OpModeAtMost,
		Expected:  mode,
		Rationale: rationale,
	}
}

// fileOwner: uid:gid must match exactly.
func fileOwner(id, section, title string, level int, path, owner, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeFileOwner, Target: path},
		Op:        OpEquals,
		Expected:  owner,
		Rationale: rationale,
	}
}

// mountOpt: mount point must carry an option.
func mountOpt(id, section, title string, level int, mp, option, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeMountOption, Target: mp, Arg: option},
		Op:        OpEquals,
		Expected:  "present",
		Rationale: rationale,
	}
}

// sshd: sshd_config directive must equal a value.
func sshd(id, section, title string, level int, directive, value, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeSSHDDirective, Target: directive},
		Op:        OpEquals,
		Expected:  value,
		Rationale: rationale,
	}
}

// fileHas / fileLacks: compiled-in regex over a file's contents. Only the
// match verdict crosses the wire, never the matched text.
func fileHas(id, section, title string, level int, path, pattern, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeFileRegex, Target: path, Arg: pattern},
		Op:        OpEquals,
		Expected:  "match",
		Rationale: rationale,
	}
}

func fileLacks(id, section, title string, level int, path, pattern, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeFileRegex, Target: path, Arg: pattern},
		Op:        OpEquals,
		Expected:  "no-match",
		Rationale: rationale,
	}
}

// auditRule: an auditd rule matching the pattern must be loaded.
func auditRule(id, section, title string, level int, pattern, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeAuditRule, Target: pattern},
		Op:        OpEquals,
		Expected:  "present",
		Rationale: rationale,
	}
}

// -----------------------------------------------------------------------------
// SECTION 1 — INITIAL SETUP
// -----------------------------------------------------------------------------

func init() {
	// 1.1.1 — Unused filesystem kernel modules.
	register(
		modDisabled("cis_rhel9_1_1_1_1", "1.1.1.1", "Ensure cramfs kernel module is not available", 1, "cramfs",
			"cramfs is an obsolete compressed filesystem. Leaving it loadable widens the kernel attack surface for no operational benefit on a server."),
		modDisabled("cis_rhel9_1_1_1_2", "1.1.1.2", "Ensure freevxfs kernel module is not available", 1, "freevxfs",
			"Veritas filesystem support is unused on virtually all Linux servers and is rarely audited upstream."),
		modDisabled("cis_rhel9_1_1_1_3", "1.1.1.3", "Ensure hfs kernel module is not available", 1, "hfs",
			"Legacy Apple filesystem support. Unused on servers and a historical source of kernel parsing bugs."),
		modDisabled("cis_rhel9_1_1_1_4", "1.1.1.4", "Ensure hfsplus kernel module is not available", 1, "hfsplus",
			"As hfs: an unused filesystem parser reachable from removable media."),
		modDisabled("cis_rhel9_1_1_1_5", "1.1.1.5", "Ensure jffs2 kernel module is not available", 1, "jffs2",
			"Flash filesystem for embedded devices; not used on server installs."),
		modDisabled("cis_rhel9_1_1_1_6", "1.1.1.6", "Ensure squashfs kernel module is not available", 2, "squashfs",
			"Squashfs is used by snap packages and some container images — verify nothing on the host depends on it before disabling."),
		modDisabled("cis_rhel9_1_1_1_7", "1.1.1.7", "Ensure udf kernel module is not available", 2, "udf",
			"Optical media filesystem. Disabling blocks a parser reachable by inserting media."),
		modDisabled("cis_rhel9_1_1_1_8", "1.1.1.8", "Ensure usb-storage kernel module is not available", 2, "usb-storage",
			"Blocks USB mass storage entirely. Prevents data exfiltration to removable drives, but also breaks legitimate USB media use — a common waiver on workstations."),
	)

	// 1.1.2 — Mount options on separate partitions.
	register(
		mountOpt("cis_rhel9_1_1_2_1_2", "1.1.2.1.2", "Ensure nodev option set on /tmp partition", 1, "/tmp", "nodev",
			"Device nodes under /tmp are never legitimate and can be used to reach raw devices."),
		mountOpt("cis_rhel9_1_1_2_1_3", "1.1.2.1.3", "Ensure nosuid option set on /tmp partition", 1, "/tmp", "nosuid",
			"Blocks setuid binaries dropped in a world-writable directory from escalating privilege."),
		mountOpt("cis_rhel9_1_1_2_1_4", "1.1.2.1.4", "Ensure noexec option set on /tmp partition", 1, "/tmp", "noexec",
			"Prevents executing payloads written to /tmp, a standard step in many intrusion chains."),

		mountOpt("cis_rhel9_1_1_2_2_2", "1.1.2.2.2", "Ensure nodev option set on /dev/shm partition", 1, "/dev/shm", "nodev",
			"Shared memory should never carry device nodes."),
		mountOpt("cis_rhel9_1_1_2_2_3", "1.1.2.2.3", "Ensure nosuid option set on /dev/shm partition", 1, "/dev/shm", "nosuid",
			"Blocks setuid escalation via shared memory objects."),
		mountOpt("cis_rhel9_1_1_2_2_4", "1.1.2.2.4", "Ensure noexec option set on /dev/shm partition", 1, "/dev/shm", "noexec",
			"Prevents in-memory execution from shared memory, a common fileless-malware technique."),

		mountOpt("cis_rhel9_1_1_2_3_2", "1.1.2.3.2", "Ensure nodev option set on /home partition", 1, "/home", "nodev",
			"User home directories have no legitimate need for device nodes."),
		mountOpt("cis_rhel9_1_1_2_3_3", "1.1.2.3.3", "Ensure nosuid option set on /home partition", 1, "/home", "nosuid",
			"Stops users introducing setuid binaries in their own directories."),

		mountOpt("cis_rhel9_1_1_2_4_2", "1.1.2.4.2", "Ensure nodev option set on /var partition", 1, "/var", "nodev",
			"Device nodes under /var indicate misuse."),
		mountOpt("cis_rhel9_1_1_2_4_3", "1.1.2.4.3", "Ensure nosuid option set on /var partition", 1, "/var", "nosuid",
			"Limits privilege escalation via files in variable data storage."),

		mountOpt("cis_rhel9_1_1_2_5_2", "1.1.2.5.2", "Ensure nodev option set on /var/tmp partition", 1, "/var/tmp", "nodev",
			"As /tmp: a world-writable location must not host device nodes."),
		mountOpt("cis_rhel9_1_1_2_5_3", "1.1.2.5.3", "Ensure nosuid option set on /var/tmp partition", 1, "/var/tmp", "nosuid",
			"Blocks setuid binaries in a world-writable directory."),
		mountOpt("cis_rhel9_1_1_2_5_4", "1.1.2.5.4", "Ensure noexec option set on /var/tmp partition", 1, "/var/tmp", "noexec",
			"Prevents execution of payloads staged in /var/tmp."),

		mountOpt("cis_rhel9_1_1_2_6_2", "1.1.2.6.2", "Ensure nodev option set on /var/log partition", 1, "/var/log", "nodev",
			"Log storage has no need for device nodes."),
		mountOpt("cis_rhel9_1_1_2_6_3", "1.1.2.6.3", "Ensure nosuid option set on /var/log partition", 1, "/var/log", "nosuid",
			"Logs are attacker-influenced content; deny setuid there."),
		mountOpt("cis_rhel9_1_1_2_6_4", "1.1.2.6.4", "Ensure noexec option set on /var/log partition", 1, "/var/log", "noexec",
			"Prevents executing anything written into log storage."),

		mountOpt("cis_rhel9_1_1_2_7_2", "1.1.2.7.2", "Ensure nodev option set on /var/log/audit partition", 1, "/var/log/audit", "nodev",
			"Audit storage integrity matters more than most; deny device nodes."),
		mountOpt("cis_rhel9_1_1_2_7_3", "1.1.2.7.3", "Ensure nosuid option set on /var/log/audit partition", 1, "/var/log/audit", "nosuid",
			"Deny setuid in the audit trail location."),
		mountOpt("cis_rhel9_1_1_2_7_4", "1.1.2.7.4", "Ensure noexec option set on /var/log/audit partition", 1, "/var/log/audit", "noexec",
			"Deny execution in the audit trail location."),
	)

	// 1.2 — Package management.
	register(
		fileLacks("cis_rhel9_1_2_1_2", "1.2.1.2", "Ensure gpgcheck is globally activated", 1,
			"/etc/dnf/dnf.conf", `(?m)^\s*gpgcheck\s*=\s*0`,
			"With gpgcheck disabled, dnf installs unsigned packages — a compromised or spoofed mirror can deliver arbitrary code as root."),
		fileHas("cis_rhel9_1_2_1_3", "1.2.1.3", "Ensure repo_gpgcheck is activated", 2,
			"/etc/dnf/dnf.conf", `(?m)^\s*repo_gpgcheck\s*=\s*1`,
			"Validates repository metadata signatures, not just package signatures. Some third-party repos do not sign metadata and will need a waiver."),
	)

	// 1.3 — Filesystem integrity.
	register(
		pkgInstalled("cis_rhel9_1_3_1", "1.3.1", "Ensure AIDE is installed", 1, "aide",
			"Filesystem integrity checking detects unauthorised modification of system binaries and configuration."),
	)

	// 1.4 — Bootloader.
	register(
		fileMode("cis_rhel9_1_4_2", "1.4.2", "Ensure permissions on bootloader config are configured", 1,
			"/boot/grub2/grub.cfg", "0600",
			"A readable grub.cfg discloses boot parameters and any encrypted password hash; a writable one allows persistent boot-time compromise."),
	)

	// 1.5 — Process hardening.
	register(
		sysctlIs("cis_rhel9_1_5_1", "1.5.1", "Ensure ASLR is enabled", 1,
			"kernel.randomize_va_space", "2",
			"Address space layout randomisation is a baseline mitigation against memory-corruption exploits. Value 2 randomises stack, heap and mmap."),
		sysctlIs("cis_rhel9_1_5_2", "1.5.2", "Ensure ptrace_scope is restricted", 1,
			"kernel.yama.ptrace_scope", "1",
			"Restricts ptrace to child processes, blocking a compromised process from reading memory of other processes owned by the same user — where credentials commonly sit."),
		fileHas("cis_rhel9_1_5_3", "1.5.3", "Ensure core dump backtraces are disabled", 1,
			"/etc/systemd/coredump.conf", `(?m)^\s*ProcessSizeMax\s*=\s*0`,
			"Core dumps can contain secrets held in process memory and are written to disk where they are rarely protected."),
		sysctlIs("cis_rhel9_1_5_4", "1.5.4", "Ensure core dumps are restricted", 1,
			"fs.suid_dumpable", "0",
			"Prevents setuid programs from dumping core, which would expose privileged memory contents to an unprivileged user."),
	)

	// 1.6 — Mandatory access control.
	register(
		pkgInstalled("cis_rhel9_1_6_1_1", "1.6.1.1", "Ensure SELinux is installed", 1, "libselinux",
			"SELinux is the primary mandatory access control on RHEL and constrains a compromised service to its policy domain."),
		fileLacks("cis_rhel9_1_6_1_2", "1.6.1.2", "Ensure SELinux is not disabled in bootloader configuration", 1,
			"/etc/default/grub", `selinux\s*=\s*0|enforcing\s*=\s*0`,
			"A kernel command line disabling SELinux silently overrides every policy setting, and survives reboots."),
		Check{
			ID: "cis_rhel9_1_6_1_3", Section: "1.6.1.3",
			Title: "Ensure SELinux policy is configured", Level: 1,
			Probe:     Probe{Kind: ProbeSELinuxPolicy},
			Op:        OpEquals,
			Expected:  "targeted",
			Rationale: "The targeted policy confines network-facing services. Hosts requiring MLS should override the expected value rather than waive the check.",
		},
		Check{
			ID: "cis_rhel9_1_6_1_4", Section: "1.6.1.4",
			Title: "Ensure the SELinux mode is enforcing", Level: 1,
			Probe:     Probe{Kind: ProbeSELinuxMode},
			Op:        OpEquals,
			Expected:  "enforcing",
			Rationale: "Permissive mode logs violations but blocks nothing. A host left permissive after troubleshooting has no mandatory access control at all.",
		},
		pkgAbsent("cis_rhel9_1_6_1_7", "1.6.1.7", "Ensure the MCS Translation Service is not installed", 2, "mcstrans",
			"mcstrans is unnecessary on most systems and has historically been a source of policy confusion."),
		pkgAbsent("cis_rhel9_1_6_1_8", "1.6.1.8", "Ensure SETroubleshoot is not installed", 2, "setroubleshoot",
			"SETroubleshoot is a desktop diagnostic tool; on a server it adds an unnecessary privileged daemon."),
	)

	// 1.7 — Warning banners.
	register(
		fileMode("cis_rhel9_1_7_4", "1.7.4", "Ensure access to /etc/motd is configured", 1, "/etc/motd", "0644",
			"A writable motd lets any user with access present arbitrary text to everyone who logs in."),
		fileMode("cis_rhel9_1_7_5", "1.7.5", "Ensure access to /etc/issue is configured", 1, "/etc/issue", "0644",
			"The pre-login banner must not be modifiable by unprivileged users."),
		fileMode("cis_rhel9_1_7_6", "1.7.6", "Ensure access to /etc/issue.net is configured", 1, "/etc/issue.net", "0644",
			"The network pre-login banner must not be modifiable by unprivileged users."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 2 — SERVICES
// -----------------------------------------------------------------------------

func init() {
	// 2.1 — Server services that should not run on a hardened host.
	register(
		svcDisabled("cis_rhel9_2_1_1", "2.1.1", "Ensure autofs services are not in use", 2, "autofs.service",
			"Automounting removable media allows an attacker with physical access to introduce a filesystem automatically."),
		svcDisabled("cis_rhel9_2_1_2", "2.1.2", "Ensure avahi daemon services are not in use", 1, "avahi-daemon.service",
			"mDNS service discovery broadcasts host information on the local network and has a history of remote vulnerabilities."),
		svcDisabled("cis_rhel9_2_1_3", "2.1.3", "Ensure dhcp server services are not in use", 1, "dhcpd.service",
			"A rogue or misconfigured DHCP server can redirect network clients."),
		svcDisabled("cis_rhel9_2_1_4", "2.1.4", "Ensure dns server services are not in use", 1, "named.service",
			"An unnecessary authoritative or recursive resolver is a high-value attack target and an amplification source."),
		svcDisabled("cis_rhel9_2_1_5", "2.1.5", "Ensure dnsmasq services are not in use", 1, "dnsmasq.service",
			"dnsmasq exposes DNS and DHCP; unnecessary on most servers."),
		svcDisabled("cis_rhel9_2_1_6", "2.1.6", "Ensure samba file server services are not in use", 1, "smb.service",
			"SMB is a frequent ransomware propagation path and should not be exposed unless the host is a file server."),
		svcDisabled("cis_rhel9_2_1_7", "2.1.7", "Ensure ftp server services are not in use", 1, "vsftpd.service",
			"FTP transmits credentials and data in cleartext, and anonymous access is a common misconfiguration. Use SFTP or HTTPS instead."),
		svcDisabled("cis_rhel9_2_1_8", "2.1.8", "Ensure message access server services are not in use", 1, "dovecot.service",
			"IMAP/POP3 services should not run on a host that is not a mail server."),
		svcDisabled("cis_rhel9_2_1_9", "2.1.9", "Ensure network file system services are not in use", 1, "nfs-server.service",
			"NFS exports are commonly over-permissioned and expose filesystems to the network."),
		svcDisabled("cis_rhel9_2_1_10", "2.1.10", "Ensure nis server services are not in use", 1, "ypserv.service",
			"NIS transmits password hashes over the network and is obsolete."),
		svcDisabled("cis_rhel9_2_1_11", "2.1.11", "Ensure print server services are not in use", 1, "cups.service",
			"CUPS listens on the network by default and is unnecessary on servers."),
		svcDisabled("cis_rhel9_2_1_12", "2.1.12", "Ensure rpcbind services are not in use", 1, "rpcbind.service",
			"rpcbind is a known DDoS amplification vector and is only needed for NFSv3 and NIS."),
		svcDisabled("cis_rhel9_2_1_13", "2.1.13", "Ensure rsync services are not in use", 1, "rsyncd.service",
			"The rsync daemon transfers data unencrypted and is frequently left unauthenticated."),
		svcDisabled("cis_rhel9_2_1_14", "2.1.14", "Ensure snmp services are not in use", 1, "snmpd.service",
			"SNMP, especially v1/v2c with default community strings, discloses detailed system information."),
		svcDisabled("cis_rhel9_2_1_15", "2.1.15", "Ensure telnet server services are not in use", 1, "telnet.socket",
			"Telnet transmits credentials in cleartext and has no place on a modern host."),
		svcDisabled("cis_rhel9_2_1_16", "2.1.16", "Ensure tftp server services are not in use", 1, "tftp.socket",
			"TFTP has no authentication or encryption of any kind. It is normally present only for PXE boot; anything else should use a real transfer protocol."),
		svcDisabled("cis_rhel9_2_1_17", "2.1.17", "Ensure web proxy server services are not in use", 1, "squid.service",
			"An open proxy can be abused to relay traffic and mask an attacker's origin."),
		svcDisabled("cis_rhel9_2_1_18", "2.1.18", "Ensure web server services are not in use", 1, "httpd.service",
			"An unnecessary web server materially increases remote attack surface."),
		svcDisabled("cis_rhel9_2_1_19", "2.1.19", "Ensure xinetd services are not in use", 1, "xinetd.service",
			"xinetd launches legacy network services, many of which are unauthenticated."),
	)

	// 2.2 — Client packages.
	register(
		pkgAbsent("cis_rhel9_2_2_1", "2.2.1", "Ensure ftp client is not installed", 2, "ftp",
			"Removing cleartext clients prevents their casual use and denies an attacker a convenient transfer tool."),
		pkgAbsent("cis_rhel9_2_2_2", "2.2.2", "Ensure ldap client is not installed", 2, "openldap-clients",
			"Unused LDAP clients provide an attacker with directory enumeration tooling."),
		pkgAbsent("cis_rhel9_2_2_3", "2.2.3", "Ensure nis client is not installed", 2, "ypbind",
			"NIS is obsolete and its client leaks authentication data."),
		pkgAbsent("cis_rhel9_2_2_4", "2.2.4", "Ensure telnet client is not installed", 2, "telnet",
			"Denies both casual cleartext use and a handy port-probing tool."),
		pkgAbsent("cis_rhel9_2_2_5", "2.2.5", "Ensure tftp client is not installed", 2, "tftp",
			"TFTP clients are commonly used to stage payloads onto a compromised host."),
	)

	// 2.3 — Time synchronisation.
	register(
		pkgInstalled("cis_rhel9_2_3_1", "2.3.1", "Ensure time synchronization is in use", 1, "chrony",
			"Without synchronised clocks, log correlation across hosts becomes unreliable and certificate validation can fail unpredictably."),
		svcEnabled("cis_rhel9_2_3_2", "2.3.2", "Ensure chrony service is enabled and running", 1, "chronyd.service",
			"An installed but disabled time daemon provides no synchronisation."),
	)

	// 2.4 — Job schedulers.
	register(
		svcEnabled("cis_rhel9_2_4_1_1", "2.4.1.1", "Ensure cron daemon is enabled and active", 1, "crond.service",
			"Scheduled maintenance and security tasks silently stop running when cron is disabled."),
		fileMode("cis_rhel9_2_4_1_2", "2.4.1.2", "Ensure permissions on /etc/crontab are configured", 1, "/etc/crontab", "0600",
			"A writable crontab is direct root code execution on a schedule."),
		fileMode("cis_rhel9_2_4_1_3", "2.4.1.3", "Ensure permissions on /etc/cron.hourly are configured", 1, "/etc/cron.hourly", "0700",
			"Anyone able to write into a cron directory executes code as root."),
		fileMode("cis_rhel9_2_4_1_4", "2.4.1.4", "Ensure permissions on /etc/cron.daily are configured", 1, "/etc/cron.daily", "0700",
			"Anyone able to write into a cron directory executes code as root."),
		fileMode("cis_rhel9_2_4_1_5", "2.4.1.5", "Ensure permissions on /etc/cron.weekly are configured", 1, "/etc/cron.weekly", "0700",
			"Anyone able to write into a cron directory executes code as root."),
		fileMode("cis_rhel9_2_4_1_6", "2.4.1.6", "Ensure permissions on /etc/cron.monthly are configured", 1, "/etc/cron.monthly", "0700",
			"Anyone able to write into a cron directory executes code as root."),
		fileMode("cis_rhel9_2_4_1_7", "2.4.1.7", "Ensure permissions on /etc/cron.d are configured", 1, "/etc/cron.d", "0700",
			"Anyone able to write into a cron directory executes code as root."),
		Check{
			ID: "cis_rhel9_2_4_1_8", Section: "2.4.1.8",
			Title: "Ensure crontab is restricted to authorized users", Level: 1,
			Probe:     Probe{Kind: ProbeFileExists, Target: "/etc/cron.deny"},
			Op:        OpEquals,
			Expected:  "absent",
			Rationale: "cron.allow is an explicit allowlist and is preferred; the presence of cron.deny indicates the weaker denylist model is in use.",
		},
	)
}

// -----------------------------------------------------------------------------
// SECTION 3 — NETWORK
// -----------------------------------------------------------------------------

func init() {
	// 3.1 — Network devices.
	register(
		svcDisabled("cis_rhel9_3_1_2", "3.1.2", "Ensure wireless interfaces are disabled", 1, "wpa_supplicant.service",
			"Wireless interfaces on a server bypass the wired network's perimeter controls entirely."),
		modDisabled("cis_rhel9_3_1_3", "3.1.3", "Ensure bluetooth services are not in use", 2, "bluetooth",
			"Bluetooth provides a short-range attack surface with no server use case."),
	)

	// 3.2 — Uncommon network protocol modules.
	register(
		modDisabled("cis_rhel9_3_2_1", "3.2.1", "Ensure dccp kernel module is not available", 2, "dccp",
			"DCCP is rarely used and its kernel implementation has received little security scrutiny."),
		modDisabled("cis_rhel9_3_2_2", "3.2.2", "Ensure tipc kernel module is not available", 2, "tipc",
			"TIPC is a cluster protocol with a history of critical remote kernel vulnerabilities (CVE-2021-43267)."),
		modDisabled("cis_rhel9_3_2_3", "3.2.3", "Ensure rds kernel module is not available", 2, "rds",
			"RDS has a poor security record and is unused outside specific HPC workloads."),
		modDisabled("cis_rhel9_3_2_4", "3.2.4", "Ensure sctp kernel module is not available", 2, "sctp",
			"SCTP is unused on most servers and expands the network-reachable kernel surface."),
	)

	// 3.3 — Network kernel parameters.
	register(
		sysctlIs("cis_rhel9_3_3_1", "3.3.1", "Ensure IP forwarding is disabled", 1,
			"net.ipv4.ip_forward", "0",
			"A host forwarding packets can be used to pivot between network segments. Routers, NAT gateways and container hosts legitimately need this — override the expected value rather than waiving, so the setting stays visible."),
		sysctlIs("cis_rhel9_3_3_2", "3.3.2", "Ensure packet redirect sending is disabled", 1,
			"net.ipv4.conf.all.send_redirects", "0",
			"Sending ICMP redirects allows a host to alter other systems' routing tables."),
		sysctlIs("cis_rhel9_3_3_3", "3.3.3", "Ensure bogus icmp responses are ignored", 1,
			"net.ipv4.icmp_ignore_bogus_error_responses", "1",
			"Prevents log flooding from malformed ICMP error responses."),
		sysctlIs("cis_rhel9_3_3_4", "3.3.4", "Ensure broadcast icmp requests are ignored", 1,
			"net.ipv4.icmp_echo_ignore_broadcasts", "1",
			"Stops the host being used as a Smurf amplification reflector."),
		sysctlIs("cis_rhel9_3_3_5", "3.3.5", "Ensure icmp redirects are not accepted", 1,
			"net.ipv4.conf.all.accept_redirects", "0",
			"Accepting ICMP redirects lets an attacker on the local segment reroute the host's traffic through a system they control."),
		sysctlIs("cis_rhel9_3_3_6", "3.3.6", "Ensure secure icmp redirects are not accepted", 1,
			"net.ipv4.conf.all.secure_redirects", "0",
			"Even gateway-sourced redirects should be refused when routing is static."),
		sysctlIs("cis_rhel9_3_3_7", "3.3.7", "Ensure reverse path filtering is enabled", 1,
			"net.ipv4.conf.all.rp_filter", "1",
			"Reverse path filtering drops packets whose source address is not reachable via the receiving interface, blocking basic address spoofing. Asymmetric-routing hosts need a documented override."),
		sysctlIs("cis_rhel9_3_3_8", "3.3.8", "Ensure source routed packets are not accepted", 1,
			"net.ipv4.conf.all.accept_source_route", "0",
			"Source routing lets a sender dictate the path a packet takes, bypassing routing-based controls."),
		sysctlIs("cis_rhel9_3_3_9", "3.3.9", "Ensure suspicious packets are logged", 1,
			"net.ipv4.conf.all.log_martians", "1",
			"Logging impossible source addresses surfaces spoofing attempts and misconfiguration."),
		sysctlIs("cis_rhel9_3_3_10", "3.3.10", "Ensure tcp syn cookies is enabled", 1,
			"net.ipv4.tcp_syncookies", "1",
			"SYN cookies keep the host serving legitimate connections during a SYN flood."),
		sysctlIs("cis_rhel9_3_3_11", "3.3.11", "Ensure ipv6 router advertisements are not accepted", 1,
			"net.ipv6.conf.all.accept_ra", "0",
			"Accepting router advertisements allows an attacker on the segment to become the host's default gateway."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 4 — HOST BASED FIREWALL
// -----------------------------------------------------------------------------

func init() {
	register(
		pkgInstalled("cis_rhel9_4_1_1", "4.1.1", "Ensure firewalld is installed", 1, "firewalld",
			"A host-based firewall is the last control when a service is unexpectedly exposed or a network ACL is wrong."),
		Check{
			ID: "cis_rhel9_4_1_2", Section: "4.1.2",
			Title: "Ensure firewalld service is enabled and running", Level: 1,
			Probe:     Probe{Kind: ProbeFirewalldState},
			Op:        OpEquals,
			Expected:  "active",
			Rationale: "An installed but inactive firewall provides no filtering. Hosts standardised on nftables directly should waive this and enable the nftables checks instead.",
		},
	)
}

// -----------------------------------------------------------------------------
// SECTION 5 — ACCESS CONTROL
// -----------------------------------------------------------------------------

func init() {
	// 5.1 — SSH server.
	register(
		fileMode("cis_rhel9_5_1_1", "5.1.1", "Ensure permissions on /etc/ssh/sshd_config are configured", 1,
			"/etc/ssh/sshd_config", "0600",
			"A writable sshd_config is remote root access; a readable one discloses the exact authentication surface."),
		sshd("cis_rhel9_5_1_4", "5.1.4", "Ensure sshd access is configured", 2, "allowusers", "unset",
			"An explicit AllowUsers/AllowGroups allowlist limits SSH to named accounts. Expected 'unset' inverts to a finding only when your profile overrides it — set the expected value to your allowlist."),
		sshd("cis_rhel9_5_1_5", "5.1.5", "Ensure sshd Banner is configured", 1, "banner", "/etc/issue.net",
			"A pre-authentication banner is required by many legal and regulatory regimes."),
		sshd("cis_rhel9_5_1_6", "5.1.6", "Ensure sshd Ciphers are configured", 1, "ciphers", "unset",
			"Explicitly configured strong ciphers prevent negotiation down to weak algorithms. 'unset' means the OpenSSH default set is in use, which is strong on RHEL 9 — override with your required list if you mandate one."),
		sshd("cis_rhel9_5_1_7", "5.1.7", "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured", 1,
			"clientaliveinterval", "15",
			"Bounded idle timeouts close abandoned sessions that would otherwise remain authenticated indefinitely."),
		sshd("cis_rhel9_5_1_8", "5.1.8", "Ensure sshd DisableForwarding is enabled", 2, "disableforwarding", "yes",
			"Port forwarding turns an SSH session into a tunnel into the internal network."),
		sshd("cis_rhel9_5_1_11", "5.1.11", "Ensure sshd IgnoreRhosts is enabled", 1, "ignorerhosts", "yes",
			"rhosts authentication trusts the remote host's claim about the user's identity."),
		sshd("cis_rhel9_5_1_12", "5.1.12", "Ensure sshd LoginGraceTime is configured", 1, "logingracetime", "60",
			"A long grace period allows an attacker to hold open many unauthenticated connections and exhaust the listener."),
		sshd("cis_rhel9_5_1_13", "5.1.13", "Ensure sshd LogLevel is configured", 1, "loglevel", "INFO",
			"INFO or VERBOSE is required for the login records that intrusion detection and forensics depend on."),
		sshd("cis_rhel9_5_1_14", "5.1.14", "Ensure sshd MaxAuthTries is configured", 1, "maxauthtries", "4",
			"Limits password guesses per connection, slowing brute force meaningfully."),
		sshd("cis_rhel9_5_1_15", "5.1.15", "Ensure sshd MaxSessions is configured", 1, "maxsessions", "10",
			"Caps multiplexed sessions per connection, limiting resource exhaustion."),
		sshd("cis_rhel9_5_1_16", "5.1.16", "Ensure sshd MaxStartups is configured", 1, "maxstartups", "10:30:60",
			"Throttles concurrent unauthenticated connections, the resource a brute-force tool consumes first."),
		sshd("cis_rhel9_5_1_17", "5.1.17", "Ensure sshd PermitEmptyPasswords is disabled", 1, "permitemptypasswords", "no",
			"Permitting empty passwords allows login to any account with a blank password field."),
		sshd("cis_rhel9_5_1_18", "5.1.18", "Ensure sshd PermitRootLogin is disabled", 1, "permitrootlogin", "no",
			"Direct root login removes per-administrator accountability and makes root a guessable remote target."),
		sshd("cis_rhel9_5_1_19", "5.1.19", "Ensure sshd PermitUserEnvironment is disabled", 1, "permituserenvironment", "no",
			"User-supplied environment variables can subvert the login shell, for example via LD_PRELOAD."),
		sshd("cis_rhel9_5_1_20", "5.1.20", "Ensure sshd UsePAM is enabled", 1, "usepam", "yes",
			"Without PAM, account lockout, password quality and session limits are all bypassed for SSH."),
		sshd("cis_rhel9_5_1_21", "5.1.21", "Ensure sshd HostbasedAuthentication is disabled", 1, "hostbasedauthentication", "no",
			"Host-based authentication trusts the client host rather than the user."),
		sshd("cis_rhel9_5_1_22", "5.1.22", "Ensure sshd GSSAPIAuthentication is disabled", 2, "gssapiauthentication", "no",
			"Unless Kerberos is in use, GSSAPI adds authentication surface for no benefit."),
	)

	// 5.2 — Privilege escalation.
	register(
		pkgInstalled("cis_rhel9_5_2_1", "5.2.1", "Ensure sudo is installed", 1, "sudo",
			"sudo provides the per-command authorisation and audit trail that shared root passwords cannot."),
		fileHas("cis_rhel9_5_2_2", "5.2.2", "Ensure sudo commands use pty", 1,
			"/etc/sudoers", `(?m)^\s*Defaults\s+.*\buse_pty\b`,
			"Forcing a pty prevents a program run under sudo from escaping into a background process that survives the session."),
		fileHas("cis_rhel9_5_2_3", "5.2.3", "Ensure sudo log file exists", 1,
			"/etc/sudoers", `(?m)^\s*Defaults\s+.*\blogfile\s*=`,
			"A dedicated sudo log preserves privileged command history independently of syslog."),
		fileLacks("cis_rhel9_5_2_4", "5.2.4", "Ensure users must provide password for escalation", 2,
			"/etc/sudoers", `(?m)^[^#]*\bNOPASSWD\b`,
			"NOPASSWD turns any compromise of a user session into immediate root, with no re-authentication."),
		fileLacks("cis_rhel9_5_2_5", "5.2.5", "Ensure re-authentication for privilege escalation is not disabled globally", 1,
			"/etc/sudoers", `(?m)^[^#]*!authenticate`,
			"!authenticate disables the sudo password prompt entirely."),
		fileHas("cis_rhel9_5_2_6", "5.2.6", "Ensure sudo authentication timeout is configured correctly", 1,
			"/etc/sudoers", `(?m)^\s*Defaults\s+.*\btimestamp_timeout\s*=`,
			"An unbounded sudo timestamp lets a later attacker reuse a still-valid escalation without a password."),
	)

	// 5.3 — PAM.
	register(
		pkgInstalled("cis_rhel9_5_3_1_1", "5.3.1.1", "Ensure latest version of pam is installed", 1, "pam",
			"PAM mediates every authentication path on the host."),
		pkgInstalled("cis_rhel9_5_3_1_2", "5.3.1.2", "Ensure libpwquality is installed", 1, "libpwquality",
			"Password quality enforcement depends on this library being present."),
		fileHas("cis_rhel9_5_3_2_2", "5.3.2.2", "Ensure pam_faillock module is enabled", 1,
			"/etc/pam.d/system-auth", `pam_faillock\.so`,
			"Without account lockout, an attacker can attempt unlimited password guesses against local accounts."),
		fileHas("cis_rhel9_5_3_2_3", "5.3.2.3", "Ensure pam_pwquality module is enabled", 1,
			"/etc/pam.d/system-auth", `pam_pwquality\.so`,
			"Password complexity is unenforced unless the module is in the stack."),
		fileHas("cis_rhel9_5_3_3_1_1", "5.3.3.1.1", "Ensure password failed attempts lockout is configured", 1,
			"/etc/security/faillock.conf", `(?m)^\s*deny\s*=\s*[1-5]\s*$`,
			"A lockout threshold of five or fewer attempts is the control that makes online password guessing impractical."),
		fileHas("cis_rhel9_5_3_3_2_2", "5.3.3.2.2", "Ensure minimum password length is configured", 1,
			"/etc/security/pwquality.conf", `(?m)^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9])`,
			"Fourteen characters is the current CIS floor; shorter passwords fall within practical offline cracking range."),
	)

	// 5.4 — User accounts and environment.
	register(
		fileHas("cis_rhel9_5_4_1_1", "5.4.1.1", "Ensure password expiration is configured", 1,
			"/etc/login.defs", `(?m)^\s*PASS_MAX_DAYS\s+([1-9]|[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|36[0-5])\s*$`,
			"Bounded password lifetime limits how long a leaked credential stays valid."),
		fileHas("cis_rhel9_5_4_1_2", "5.4.1.2", "Ensure minimum password days is configured", 1,
			"/etc/login.defs", `(?m)^\s*PASS_MIN_DAYS\s+[1-9]`,
			"A minimum age stops a user cycling through passwords to return to a previous one."),
		fileHas("cis_rhel9_5_4_1_3", "5.4.1.3", "Ensure password expiration warning days is configured", 1,
			"/etc/login.defs", `(?m)^\s*PASS_WARN_AGE\s+([7-9]|[1-9][0-9])`,
			"Advance warning avoids the lockouts that drive users toward weak, memorable replacements."),
		fileHas("cis_rhel9_5_4_2_4", "5.4.2.4", "Ensure root account access is controlled", 1,
			"/etc/shadow", `(?m)^root:[!*]`,
			"A locked root password forces all administrative access through accountable sudo sessions."),
		fileHas("cis_rhel9_5_4_3_2", "5.4.3.2", "Ensure default user shell timeout is configured", 2,
			"/etc/profile", `(?m)^\s*(readonly\s+)?TMOUT\s*=`,
			"An idle shell timeout limits the window in which an unattended session can be used."),
		fileHas("cis_rhel9_5_4_3_3", "5.4.3.3", "Ensure default user umask is configured", 1,
			"/etc/login.defs", `(?m)^\s*UMASK\s+0?027`,
			"A 027 umask stops newly created files being world-readable by default."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 6 — LOGGING AND AUDITING
// -----------------------------------------------------------------------------

func init() {
	// 6.1 — auditd.
	register(
		pkgInstalled("cis_rhel9_6_1_1_1", "6.1.1.1", "Ensure auditd packages are installed", 2, "audit",
			"auditd is the kernel-level audit trail; without it there is no reliable record of privileged activity."),
		svcEnabled("cis_rhel9_6_1_1_2", "6.1.1.2", "Ensure auditd service is enabled and active", 2, "auditd.service",
			"An installed but disabled auditd records nothing."),
		fileHas("cis_rhel9_6_1_2_1", "6.1.2.1", "Ensure audit log storage size is configured", 2,
			"/etc/audit/auditd.conf", `(?m)^\s*max_log_file\s*=\s*[0-9]+`,
			"An unbounded audit log fills the filesystem; an unconfigured one may rotate away evidence prematurely."),
		fileHas("cis_rhel9_6_1_2_2", "6.1.2.2", "Ensure audit logs are not automatically deleted", 2,
			"/etc/audit/auditd.conf", `(?m)^\s*max_log_file_action\s*=\s*keep_logs`,
			"Automatic deletion destroys the evidence an investigation depends on."),
		fileHas("cis_rhel9_6_1_2_3", "6.1.2.3", "Ensure system is disabled when audit logs are full", 2,
			"/etc/audit/auditd.conf", `(?m)^\s*(disk_full_action|admin_space_left_action)\s*=\s*(halt|single)`,
			"Halting on a full audit disk guarantees no privileged action goes unrecorded. Deliberately disruptive — many operators waive this after weighing availability against evidentiary completeness."),
		fileMode("cis_rhel9_6_1_3_1", "6.1.3.1", "Ensure audit log files mode is configured", 2, "/var/log/audit", "0700",
			"Audit logs frequently contain command lines and file paths that reveal sensitive operations."),
	)

	// 6.2 — Audit rules.
	register(
		auditRule("cis_rhel9_6_2_1_1", "6.2.1.1", "Ensure changes to system administration scope are collected", 2,
			`(?m)-w\s+/etc/sudoers`,
			"Changes to sudoers grant or revoke privilege; unlogged edits are how quiet persistence is established."),
		auditRule("cis_rhel9_6_2_1_2", "6.2.1.2", "Ensure actions as another user are always logged", 2,
			`(?m)-C\s+eu[i]?d!=[a-z]*uid`,
			"Records privilege escalation events, tying a privileged action back to the originating account."),
		auditRule("cis_rhel9_6_2_1_3", "6.2.1.3", "Ensure events that modify the sudo log file are collected", 2,
			`(?m)-w\s+/var/log/sudo`,
			"Tampering with the sudo log is a direct anti-forensic action."),
		auditRule("cis_rhel9_6_2_1_4", "6.2.1.4", "Ensure events that modify identity are collected", 2,
			`(?m)-w\s+/etc/(passwd|shadow|group|gshadow)`,
			"Account creation and password changes are the primary persistence mechanism after a host compromise."),
		auditRule("cis_rhel9_6_2_1_5", "6.2.1.5", "Ensure session initiation information is collected", 2,
			`(?m)-w\s+/var/(run|log)/(utmp|wtmp|btmp)`,
			"Login records are routinely wiped by intruders; auditing writes to them detects that."),
	)

	// 6.3 — Logging.
	register(
		pkgInstalled("cis_rhel9_6_3_1_1", "6.3.1.1", "Ensure rsyslog is installed", 1, "rsyslog",
			"Reliable local logging, and forwarding to a remote collector, both depend on it."),
		svcEnabled("cis_rhel9_6_3_1_2", "6.3.1.2", "Ensure rsyslog service is enabled and active", 1, "rsyslog.service",
			"An installed but disabled logger produces no records."),
		fileHas("cis_rhel9_6_3_1_3", "6.3.1.3", "Ensure rsyslog default file permissions are configured", 1,
			"/etc/rsyslog.conf", `(?m)^\s*\$FileCreateMode\s+0[0-6][04]0`,
			"Log files created world-readable disclose operational detail to every local account."),
		fileHas("cis_rhel9_6_3_1_4", "6.3.1.4", "Ensure logs are sent to a remote log host", 1,
			"/etc/rsyslog.conf", `(?m)^\s*[^#]*(@@?[a-zA-Z0-9.:_-]+|action\s*\(\s*type\s*=\s*"omfwd")`,
			"Remote logging is what preserves evidence when an attacker gains root and clears local logs. Hosts forwarding via a sidecar or journald-upload should override or waive."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 7 — SYSTEM MAINTENANCE
// -----------------------------------------------------------------------------

func init() {
	// 7.1 — System file permissions.
	register(
		fileMode("cis_rhel9_7_1_1", "7.1.1", "Ensure permissions on /etc/passwd are configured", 1, "/etc/passwd", "0644",
			"A writable passwd file allows account creation and UID manipulation."),
		fileOwner("cis_rhel9_7_1_2", "7.1.2", "Ensure permissions on /etc/passwd- are configured", 1, "/etc/passwd-", "0:0",
			"Backup copies are routinely overlooked and carry the same account data as the live file."),
		fileMode("cis_rhel9_7_1_3", "7.1.3", "Ensure permissions on /etc/group are configured", 1, "/etc/group", "0644",
			"Group membership determines authorisation across the system."),
		fileMode("cis_rhel9_7_1_4", "7.1.4", "Ensure permissions on /etc/group- are configured", 1, "/etc/group-", "0644",
			"The backup group file carries the same authorisation data."),
		fileMode("cis_rhel9_7_1_5", "7.1.5", "Ensure permissions on /etc/shadow are configured", 1, "/etc/shadow", "0000",
			"Read access to /etc/shadow yields every local password hash for offline cracking."),
		fileMode("cis_rhel9_7_1_6", "7.1.6", "Ensure permissions on /etc/shadow- are configured", 1, "/etc/shadow-", "0000",
			"The shadow backup is the single most commonly missed hash disclosure on a hardened host."),
		fileMode("cis_rhel9_7_1_7", "7.1.7", "Ensure permissions on /etc/gshadow are configured", 1, "/etc/gshadow", "0000",
			"Group password hashes permit unauthorised group membership."),
		fileMode("cis_rhel9_7_1_8", "7.1.8", "Ensure permissions on /etc/gshadow- are configured", 1, "/etc/gshadow-", "0000",
			"As gshadow: the backup carries identical secrets."),
		fileMode("cis_rhel9_7_1_9", "7.1.9", "Ensure permissions on /etc/shells are configured", 1, "/etc/shells", "0644",
			"A writable shells file influences which accounts are treated as interactive."),
		fileMode("cis_rhel9_7_1_10", "7.1.10", "Ensure permissions on /etc/security/opasswd are configured", 1,
			"/etc/security/opasswd", "0600",
			"opasswd stores previous password hashes for history enforcement and must be no more readable than shadow."),
	)

	// 7.2 — Local user and group settings.
	register(
		fileLacks("cis_rhel9_7_2_1", "7.2.1", "Ensure accounts in /etc/shadow are used", 1,
			"/etc/passwd", `(?m)^[^:]+:[^x!*:][^:]*:`,
			"A password hash stored in the world-readable /etc/passwd instead of /etc/shadow exposes it to every local account."),
		fileLacks("cis_rhel9_7_2_2", "7.2.2", "Ensure /etc/shadow password fields are not empty", 1,
			"/etc/shadow", `(?m)^[^:]+::`,
			"An empty password field permits login with no credential at all."),
		fileLacks("cis_rhel9_7_2_3", "7.2.3", "Ensure no legacy + entries exist in /etc/passwd", 1,
			"/etc/passwd", `(?m)^\+:`,
			"Legacy NIS continuation entries can be exploited to grant unintended access."),
		fileLacks("cis_rhel9_7_2_4", "7.2.4", "Ensure no legacy + entries exist in /etc/shadow", 1,
			"/etc/shadow", `(?m)^\+:`,
			"As passwd: an obsolete NIS artefact with authentication consequences."),
		fileLacks("cis_rhel9_7_2_5", "7.2.5", "Ensure no legacy + entries exist in /etc/group", 1,
			"/etc/group", `(?m)^\+:`,
			"As passwd: an obsolete NIS artefact with authorisation consequences."),
		Check{
			ID: "cis_rhel9_7_2_6", Section: "7.2.6",
			Title: "Ensure root is the only UID 0 account", Level: 1,
			Probe:     Probe{Kind: ProbeExtraUIDZero},
			Op:        OpEquals,
			Expected:  "none",
			Rationale: "A second UID 0 account is full root access under a name routine review is unlikely to question. Uses a dedicated probe because RE2 cannot express \"UID 0 and not root\" in a single pattern.",
		},
	)
}
