# Security Policy

The Netwarden agent runs with elevated privileges on the hosts it monitors, so
we treat vulnerabilities in it as a priority.

## Reporting a vulnerability

Email **security@netwarden.com**. Please do not open a public issue or pull
request for a security problem.

Include as much of the following as you can:

- The agent version (`netwarden --version`) and operating system
- The affected component (collector, transport, spool, self-update, packaging)
- Steps to reproduce, or a proof of concept
- The impact as you understand it, and any conditions it depends on

A PGP key is available on request.

## What to expect

- We acknowledge reports within 24 hours.
- We confirm the issue, assess its severity and keep you informed while we
  work on a fix.
- We agree on a disclosure date with you and credit you in the release notes
  unless you prefer to stay anonymous.

## Supported versions

Security fixes are made on the latest release line. Install the current
release from https://get.netwarden.com or the package repositories described
in the README.

## Scope

In scope:

- Code in this repository, including every collector and the Windows
  self-update path
- The install scripts and packages published at https://get.netwarden.com

Of particular interest are issues that let a local unprivileged user, a
monitored workload or a network attacker influence what the agent reads,
executes or reports, and anything that weakens the self-update signature and
version checks.

The hosted Netwarden platform is not part of this repository. Report issues
with it to the same address.

## Safe harbor

We will not pursue legal action against researchers who act in good faith,
avoid privacy violations and service disruption, test only against systems
they own or are authorized to test, and give us reasonable time to fix an
issue before disclosing it.
