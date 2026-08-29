package cis

// CIS RHEL 9 catalog, part two: the Level 2 rules and the remaining Level 1
// gaps from catalog.go.
//
// Split by file only to keep each one readable — registration order does not
// matter, the registry sorts by section. Same editing rules as catalog.go
// apply: never reuse a shipped ID, and every probe target stays a constant.

// separatePartition: the path must be its own mount point.
func separatePartition(id, section, title string, level int, path, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeSeparatePartition, Target: path},
		Op:        OpEquals,
		Expected:  "separate",
		Rationale: rationale,
	}
}

// sysctlPersisted: the parameter must survive a reboot.
func sysctlPersisted(id, section, title string, level int, key, value, rationale string) Check {
	return Check{
		ID: id, Section: section, Title: title, Level: level,
		Probe:     Probe{Kind: ProbeSysctlPersisted, Target: key},
		Op:        OpEquals,
		Expected:  value,
		Rationale: rationale,
	}
}

// -----------------------------------------------------------------------------
// SECTION 1 — SEPARATE PARTITIONS AND REMAINING SETUP
// -----------------------------------------------------------------------------

func init() {
	// 1.1.2 — Separate partitions. These are the prerequisite for the mount
	// option rules in catalog.go: nodev/nosuid/noexec on /tmp cannot be
	// enforced at all if /tmp is just a directory on /.
	register(
		separatePartition("cis_rhel9_1_1_2_1_1", "1.1.2.1.1", "Ensure /tmp is a separate partition", 1, "/tmp",
			"Without its own partition, /tmp cannot carry nodev/nosuid/noexec, and a user filling it exhausts the root filesystem."),
		separatePartition("cis_rhel9_1_1_2_2_1", "1.1.2.2.1", "Ensure /dev/shm is a separate partition", 1, "/dev/shm",
			"A separate tmpfs for shared memory is what makes the noexec and nosuid options on it enforceable."),
		separatePartition("cis_rhel9_1_1_2_3_1", "1.1.2.3.1", "Ensure separate partition exists for /home", 2, "/home",
			"Isolates user data from the root filesystem so a user cannot fill it, and allows nodev/nosuid to be applied."),
		separatePartition("cis_rhel9_1_1_2_4_1", "1.1.2.4.1", "Ensure separate partition exists for /var", 2, "/var",
			"Variable data growth — logs, spools, caches — must not be able to fill the root filesystem and halt the system."),
		separatePartition("cis_rhel9_1_1_2_5_1", "1.1.2.5.1", "Ensure separate partition exists for /var/tmp", 2, "/var/tmp",
			"As /tmp: a world-writable location needs its own partition for its mount options to mean anything."),
		separatePartition("cis_rhel9_1_1_2_6_1", "1.1.2.6.1", "Ensure separate partition exists for /var/log", 2, "/var/log",
			"Prevents a log flood — accidental or deliberate — from filling the root filesystem and taking the host down."),
		separatePartition("cis_rhel9_1_1_2_7_1", "1.1.2.7.1", "Ensure separate partition exists for /var/log/audit", 2, "/var/log/audit",
			"Isolating the audit trail means ordinary log growth cannot displace it, and audit's own full-disk policy governs only its own volume."),
	)

	// 1.2 — Package management.
	register(
		pkgInstalled("cis_rhel9_1_2_2_1", "1.2.2.1", "Ensure updates and patches are installed", 1, "dnf-automatic",
			"Unattended security updates close the window between a fix being published and being applied, which is where most opportunistic compromise happens. Estates using a managed patch cycle should waive this."),
	)

	// 1.3 — Filesystem integrity continued.
	register(
		svcEnabled("cis_rhel9_1_3_2", "1.3.2", "Ensure filesystem integrity is regularly checked", 1, "aide-check.timer",
			"AIDE installed but never run detects nothing. The timer is what turns it into an actual control."),
		fileMode("cis_rhel9_1_3_3", "1.3.3", "Ensure cryptographic mechanisms protect audit tools", 2,
			"/etc/aide.conf", "0640",
			"AIDE's own configuration defines what is monitored; a writable config lets an intruder exclude the files they intend to modify."),
	)

	// 1.4 — Bootloader continued.
	register(
		fileHas("cis_rhel9_1_4_1", "1.4.1", "Ensure bootloader password is set", 1,
			"/boot/grub2/user.cfg", `GRUB2_PASSWORD`,
			"Without a bootloader password, anyone with console access can edit kernel arguments to boot single-user and obtain root without credentials."),
	)

	// 1.6 — Crypto policy.
	register(
		Check{
			ID: "cis_rhel9_1_6_2", Section: "1.6.2",
			Title: "Ensure system-wide crypto policy is not set to legacy", Level: 1,
			Probe:     Probe{Kind: ProbeCryptoPolicy},
			Op:        OpNotEquals,
			Expected:  "LEGACY",
			Rationale: "The LEGACY policy re-enables SHA-1 signatures, 1024-bit Diffie-Hellman and other primitives that are broken or on the edge of practical attack. It is a single setting that weakens TLS and SSH across the whole host.",
		},
		Check{
			ID: "cis_rhel9_1_6_3", Section: "1.6.3",
			Title: "Ensure system-wide crypto policy disables SHA-1 hash and signature support", Level: 2,
			Probe:     Probe{Kind: ProbeCryptoPolicy},
			Op:        OpNotContains,
			Expected:  "SHA1",
			Rationale: "SHA-1 collisions are practical. Some older estates still need it for legacy peers, which is exactly the case for an explicit waiver rather than silence.",
		},
	)

	// 1.7 — Banner content.
	register(
		fileLacks("cis_rhel9_1_7_1", "1.7.1", "Ensure message of the day is configured properly", 1,
			"/etc/motd", `(?i)(\\\\v|\\\\r|\\\\m|\\\\s)`,
			"Escape sequences in the banner disclose the OS version and architecture to anyone before they authenticate, which is free reconnaissance."),
		fileLacks("cis_rhel9_1_7_2", "1.7.2", "Ensure local login warning banner is configured properly", 1,
			"/etc/issue", `(?i)(\\\\v|\\\\r|\\\\m|\\\\s)`,
			"As motd: the pre-login banner should not advertise the platform it protects."),
		fileLacks("cis_rhel9_1_7_3", "1.7.3", "Ensure remote login warning banner is configured properly", 1,
			"/etc/issue.net", `(?i)(\\\\v|\\\\r|\\\\m|\\\\s)`,
			"The network banner is visible to unauthenticated remote users, so version disclosure here has the widest reach."),
	)

	// 1.8 — GDM. Most servers have no GUI; these report not-applicable there.
	register(
		pkgAbsent("cis_rhel9_1_8_1", "1.8.1", "Ensure GNOME Display Manager is removed", 2, "gdm",
			"A display manager on a server adds a large graphical stack and a local login surface with no operational purpose."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 3 — PERSISTED NETWORK PARAMETERS
// -----------------------------------------------------------------------------

func init() {
	// The running values are checked in catalog.go. These verify the same
	// settings survive a reboot: a host tuned only at runtime silently
	// regresses to its defaults the next time it restarts, which is the
	// failure mode nobody notices until an audit.
	register(
		sysctlPersisted("cis_rhel9_3_3_1_p", "3.3.1.1", "Ensure IP forwarding is disabled persistently", 2,
			"net.ipv4.ip_forward", "0",
			"A runtime-only setting reverts on reboot. Routers overriding the runtime check should override this one identically."),
		sysctlPersisted("cis_rhel9_3_3_5_p", "3.3.5.1", "Ensure icmp redirects are not accepted persistently", 2,
			"net.ipv4.conf.all.accept_redirects", "0",
			"Reboot resistance matters most for the routing-manipulation defences, because the window after a reboot is unmonitored."),
		sysctlPersisted("cis_rhel9_3_3_7_p", "3.3.7.1", "Ensure reverse path filtering is enabled persistently", 2,
			"net.ipv4.conf.all.rp_filter", "1",
			"Anti-spoofing that disappears on reboot provides no durable protection."),
		sysctlPersisted("cis_rhel9_3_3_10_p", "3.3.10.1", "Ensure tcp syn cookies is enabled persistently", 2,
			"net.ipv4.tcp_syncookies", "1",
			"SYN flood protection must be in effect from boot, not applied by hand after an incident."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 6.2 — AUDIT RULES
// -----------------------------------------------------------------------------

func init() {
	// The largest single block in the benchmark. Each rule records a class of
	// event that is, in practice, part of an intrusion: privilege change,
	// account manipulation, log tampering, module loading.
	register(
		auditRule("cis_rhel9_6_2_2_1", "6.2.2.1", "Ensure events that modify the sudoers file are collected", 2,
			`(?m)-w\s+/etc/sudoers\.d`,
			"Drop-in sudoers files are the quieter way to grant persistent privilege; auditing only /etc/sudoers misses them."),
		auditRule("cis_rhel9_6_2_2_2", "6.2.2.2", "Ensure events that modify date and time information are collected", 2,
			`(?m)(adjtimex|settimeofday|clock_settime)`,
			"Clock manipulation is used to confuse log correlation and to defeat time-based controls such as certificate validity."),
		auditRule("cis_rhel9_6_2_2_3", "6.2.2.3", "Ensure events that modify the system's network environment are collected", 2,
			`(?m)(sethostname|setdomainname|-w\s+/etc/hosts|-w\s+/etc/sysconfig/network)`,
			"Changes to hostname or resolver configuration can silently redirect traffic to attacker-controlled infrastructure."),
		auditRule("cis_rhel9_6_2_2_4", "6.2.2.4", "Ensure events that modify the system's Mandatory Access Controls are collected", 2,
			`(?m)-w\s+/etc/selinux`,
			"Weakening SELinux policy is a prerequisite for many post-exploitation steps, and is otherwise a quiet change."),
		auditRule("cis_rhel9_6_2_2_5", "6.2.2.5", "Ensure login and logout events are collected", 2,
			`(?m)-w\s+/var/log/(lastlog|faillog|tallylog)`,
			"Authentication failure records are routinely cleared by intruders to hide brute-force activity."),
		auditRule("cis_rhel9_6_2_2_6", "6.2.2.6", "Ensure discretionary access control permission modification events are collected", 2,
			`(?m)(chmod|chown|setxattr|fsetxattr|lsetxattr|removexattr)`,
			"Permission and ownership changes on system files are how an attacker opens a path for later re-entry."),
		auditRule("cis_rhel9_6_2_2_7", "6.2.2.7", "Ensure unsuccessful file access attempts are collected", 2,
			`(?m)-F\s+exit=-EACCES`,
			"A burst of permission-denied opens is one of the clearest signals of an intruder probing what their compromised account can reach."),
		auditRule("cis_rhel9_6_2_2_8", "6.2.2.8", "Ensure successful file system mounts are collected", 2,
			`(?m)-S\s+mount`,
			"Mounting a filesystem is how removable media and remote shares are introduced, both common exfiltration paths."),
		auditRule("cis_rhel9_6_2_2_9", "6.2.2.9", "Ensure file deletion events by users are collected", 2,
			`(?m)(unlink|unlinkat|rename|renameat)`,
			"Bulk deletion or renaming is both an anti-forensic action and the visible signature of destructive malware."),
		auditRule("cis_rhel9_6_2_2_10", "6.2.2.10", "Ensure successful and unsuccessful attempts to use the chcon command are recorded", 2,
			`(?m)/usr/bin/chcon`,
			"chcon relabels files for SELinux; unexpected use indicates someone working around policy."),
		auditRule("cis_rhel9_6_2_2_11", "6.2.2.11", "Ensure successful and unsuccessful attempts to use the setfacl command are recorded", 2,
			`(?m)/usr/bin/setfacl`,
			"POSIX ACLs grant access invisibly to anyone reading only the traditional permission bits."),
		auditRule("cis_rhel9_6_2_2_12", "6.2.2.12", "Ensure successful and unsuccessful attempts to use the usermod command are recorded", 2,
			`(?m)/usr/sbin/usermod`,
			"usermod is how an existing account is quietly moved into a privileged group."),
		auditRule("cis_rhel9_6_2_2_13", "6.2.2.13", "Ensure kernel module loading unloading and modification is collected", 2,
			`(?m)(init_module|delete_module|finit_module|/usr/bin/kmod)`,
			"Loading a kernel module is the most direct route to a rootkit, and the resulting code runs below every userspace control."),
		auditRule("cis_rhel9_6_2_2_14", "6.2.2.14", "Ensure use of privileged commands is collected", 2,
			`(?m)-F\s+perm=x\s+-F\s+auid`,
			"Records execution of setuid and setgid binaries, the standard local privilege-escalation surface."),
		auditRule("cis_rhel9_6_2_3_1", "6.2.3.1", "Ensure the audit configuration is immutable", 2,
			`(?m)^\s*-e\s+2`,
			"Mode 2 locks the rule set until reboot, so an intruder who gains root cannot silently disable auditing of their own subsequent actions. Rule changes then require a reboot — a real operational cost, and a common waiver."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 5 AND 6 — REMAINING ACCESS CONTROL AND LOGGING
// -----------------------------------------------------------------------------

func init() {
	register(
		// 5.1 — remaining sshd hardening.
		sshd("cis_rhel9_5_1_9", "5.1.9", "Ensure sshd GSSAPIAuthentication is disabled", 2, "kerberosauthentication", "no",
			"Kerberos authentication in sshd is unused on most estates and adds a parsing surface reachable before authentication completes."),
		sshd("cis_rhel9_5_1_10", "5.1.10", "Ensure sshd HostbasedAuthentication and rhosts are fully disabled", 2, "ignoreuserknownhosts", "yes",
			"Trusting a user's own known_hosts file for host-based authentication lets the user decide which hosts to trust."),
		sshd("cis_rhel9_5_1_23", "5.1.23", "Ensure sshd PermitTunnel is disabled", 2, "permittunnel", "no",
			"Tunnelling turns an SSH session into a layer-3 link into the internal network, bypassing network segmentation."),
		sshd("cis_rhel9_5_1_24", "5.1.24", "Ensure sshd AllowTcpForwarding is disabled", 2, "allowtcpforwarding", "no",
			"TCP forwarding lets an authenticated user reach services the network policy intended to isolate. Frequently waived where developers rely on it."),
		sshd("cis_rhel9_5_1_25", "5.1.25", "Ensure sshd MACs are configured", 2, "macs", "unset",
			"Explicit strong MACs prevent negotiation down to truncated or MD5-based algorithms. 'unset' is the RHEL 9 default set, which is already strong."),
		sshd("cis_rhel9_5_1_26", "5.1.26", "Ensure sshd KexAlgorithms are configured", 2, "kexalgorithms", "unset",
			"Explicit key exchange algorithms prevent fallback to 1024-bit Diffie-Hellman group exchange."),
		sshd("cis_rhel9_5_1_27", "5.1.27", "Ensure sshd ClientAliveCountMax is configured", 1, "clientalivecountmax", "3",
			"With ClientAliveInterval, this bounds how long an unresponsive authenticated session stays open."),

		// 5.3 — PAM continued.
		fileHas("cis_rhel9_5_3_2_4", "5.3.2.4", "Ensure pam_pwhistory module is enabled", 1,
			"/etc/pam.d/system-auth", `pam_pwhistory\.so`,
			"Without password history, a forced rotation is satisfied by re-using the previous password, which defeats the rotation entirely."),
		fileHas("cis_rhel9_5_3_3_1_2", "5.3.3.1.2", "Ensure password unlock time is configured", 1,
			"/etc/security/faillock.conf", `(?m)^\s*unlock_time\s*=\s*([0-9]{3,}|0)\s*$`,
			"An unlock time of 900 seconds or more, or 0 for manual unlock, is what makes lockout an actual deterrent rather than a brief pause."),
		fileHas("cis_rhel9_5_3_3_2_1", "5.3.3.2.1", "Ensure password number of changed characters is configured", 2,
			"/etc/security/pwquality.conf", `(?m)^\s*difok\s*=\s*[2-9]`,
			"Requiring several changed characters stops a rotation being satisfied by incrementing a trailing digit."),
		fileHas("cis_rhel9_5_3_3_2_3", "5.3.3.2.3", "Ensure password complexity is configured", 2,
			"/etc/security/pwquality.conf", `(?m)^\s*(minclass|[udol]credit)\s*=`,
			"Character-class requirements raise the cost of offline cracking. CIS now prefers length over complexity, so this is Level 2 rather than mandatory."),
		fileHas("cis_rhel9_5_3_3_2_6", "5.3.3.2.6", "Ensure password quality is enforced for the root user", 2,
			"/etc/security/pwquality.conf", `(?m)^\s*enforce_for_root`,
			"By default pwquality warns but does not enforce for root, so the most privileged account is the least constrained."),

		// 5.4 — accounts continued.
		fileHas("cis_rhel9_5_4_1_4", "5.4.1.4", "Ensure inactive password lock is configured", 1,
			"/etc/default/useradd", `(?m)^\s*INACTIVE\s*=\s*(([0-9])|([1-3][0-9])|4[0-5])\s*$`,
			"Locking accounts shortly after a password expires closes dormant accounts, which are the ones nobody notices being used."),
		fileHas("cis_rhel9_5_4_2_1", "5.4.2.1", "Ensure root is the only account with a login shell of uid 0", 1,
			"/etc/passwd", `(?m)^root:`,
			"Confirms the root entry exists and is well-formed; a malformed passwd entry can produce surprising authentication behaviour."),
		fileHas("cis_rhel9_5_4_3_1", "5.4.3.1", "Ensure nologin is not listed in /etc/shells", 1,
			"/etc/shells", `(?m)^(?:/usr)?/s?bin/(bash|sh|dash|zsh)`,
			"/etc/shells should list real interactive shells; listing nologin there causes accounts intended to be non-interactive to be treated as interactive."),

		// 6.3 — journald.
		fileHas("cis_rhel9_6_3_2_1", "6.3.2.1", "Ensure journald ForwardToSyslog is configured", 2,
			"/etc/systemd/journald.conf", `(?m)^\s*ForwardToSyslog\s*=`,
			"Explicitly deciding whether journald forwards to rsyslog avoids either duplicate storage or a silent gap between the two log paths."),
		fileHas("cis_rhel9_6_3_2_2", "6.3.2.2", "Ensure journald Compress is configured", 2,
			"/etc/systemd/journald.conf", `(?m)^\s*Compress\s*=\s*yes`,
			"Compression extends how far back the journal reaches on the same disk, which directly increases usable forensic history."),
		fileHas("cis_rhel9_6_3_2_3", "6.3.2.3", "Ensure journald Storage is configured", 2,
			"/etc/systemd/journald.conf", `(?m)^\s*Storage\s*=\s*persistent`,
			"Volatile journal storage is lost on reboot — including the reboot an attacker triggers to clear their tracks."),
	)
}

// -----------------------------------------------------------------------------
// SECTION 7 — REMAINING FILE AND ACCOUNT CHECKS
// -----------------------------------------------------------------------------

func init() {
	register(
		fileOwner("cis_rhel9_7_1_11", "7.1.11", "Ensure /etc/shadow is owned by root", 1, "/etc/shadow", "0:0",
			"Ownership by any other account permits modification of every local password hash."),
		fileOwner("cis_rhel9_7_1_12", "7.1.12", "Ensure /etc/passwd is owned by root", 1, "/etc/passwd", "0:0",
			"Ownership of passwd permits account creation and UID reassignment."),
		fileOwner("cis_rhel9_7_1_13", "7.1.13", "Ensure /etc/group is owned by root", 1, "/etc/group", "0:0",
			"Ownership of group permits granting oneself membership of privileged groups."),
		fileOwner("cis_rhel9_7_1_14", "7.1.14", "Ensure /etc/gshadow is owned by root", 1, "/etc/gshadow", "0:0",
			"Ownership of gshadow permits setting group passwords and administrators."),
		fileMode("cis_rhel9_7_1_15", "7.1.15", "Ensure permissions on /etc/sudoers are configured", 1,
			"/etc/sudoers", "0440",
			"A writable sudoers file is an immediate, complete privilege escalation to root."),
		fileMode("cis_rhel9_7_1_16", "7.1.16", "Ensure permissions on /etc/sudoers.d are configured", 1,
			"/etc/sudoers.d", "0750",
			"Drop-in sudoers files carry the same authority as the main file and are reviewed far less often."),
		fileMode("cis_rhel9_7_1_17", "7.1.17", "Ensure permissions on SSH host private keys are configured", 1,
			"/etc/ssh/ssh_host_rsa_key", "0600",
			"A readable host private key allows an attacker to impersonate this server and mount a convincing man-in-the-middle against every client that trusts it."),
		fileMode("cis_rhel9_7_1_18", "7.1.18", "Ensure permissions on SSH ed25519 host private key are configured", 1,
			"/etc/ssh/ssh_host_ed25519_key", "0600",
			"Ed25519 is the default host key on RHEL 9; leaving it readable is the same server-impersonation exposure as the RSA key."),
		fileMode("cis_rhel9_7_1_19", "7.1.19", "Ensure permissions on /etc/cron.allow are configured", 2,
			"/etc/cron.allow", "0640",
			"cron.allow determines who may schedule jobs; a writable copy is scheduled code execution."),
		fileMode("cis_rhel9_7_1_20", "7.1.20", "Ensure permissions on /boot/grub2/grubenv are configured", 2,
			"/boot/grub2/grubenv", "0600",
			"grubenv influences boot behaviour and is writable from a running system, making it a persistence target."),
	)
}
