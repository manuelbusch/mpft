# Introduction

`mpft` sends and receives files over many protocols. Every endpoint is a URL,
and the prefix of that URL picks the protocol:

```
mpft cp report.pdf sftp://deploy@srv.example.com/incoming/
mpft cp report.pdf "s3://bucket/reports/" "mailto:boss@example.com?subject=Report"
mpft cp sftp://srv/var/log/app.log ./
mpft ls webdavs://cloud.example.com/documents/
```

One command copies from anywhere to anywhere: a local path, SFTP, SCP, FTP,
FTPS, HTTP, WebDAV, S3-compatible object storage, or an e-mail attachment.
The same options — checksums, signatures, timeouts, resuming, parallelism —
apply whatever the protocol is.

`mpft` is a Rust library with a command-line program of the same name on top.
This guide is about the program; [the appendix](appendix/library.md) covers
the library.

This guide describes `mpft` 0.1. `mpft --version` prints the version you have,
and `mpft --help` is always authoritative for the binary in front of you.
[Compatibility and stability](reference/compatibility.md) says what a script
may rely on from one version to the next, and [Licensing and
support](appendix/support.md) says under which terms and where to report a
problem.

The prose uses British spelling; the flags and keys are spelled as the
program spells them (`--color`, `[defaults] color`). Words the guide uses
with a fixed meaning — job, transfer, target, sidecar, via — are in the
[glossary](appendix/glossary.md).

## Who this guide is for

Anyone who has to move files between systems that do not speak the same
protocol: nightly exports, deployment artefacts, reports for a colleague,
an inbox on a partner's FTP server that has to end up in object storage.
No Rust knowledge is needed.

## How to read it

- **[Why mpft?](why-mpft.md)** makes the case, and says where other tools fit better.
- **Getting started** installs the program and explains the URL model, which is
  the one idea the rest of the guide rests on.
- **Everyday use** is task-by-task: one file, many targets, many files, and
  what happens when a transfer is interrupted.
- **Integrity and trust** is about knowing that what arrived is what was sent,
  and that the far side is who it claims to be.
- **Configuration** is how to stop typing all of that on every command line,
  and **Automation** how to let a machine run it unattended.
- **Services** covers the two ways `mpft` runs as a service — taking jobs over
  HTTP, and taking one upload over SSH and fanning it out from a host with
  the bandwidth — and the patterns in which the pieces are deployed.
- **Security** is one page for a reviewer: what is trusted, what is checked
  and when, where a secret is at each moment, and a hardening checklist.
- **Protocols** collects what is specific to each scheme.
- **Reference** is the lookup material: a quick reference, every flag, key,
  variable and exit code, the HTTP API and the relay protocol, and what is
  kept stable between versions.
- **Appendix** has the library, Windows, troubleshooting, the glossary and
  the licence.

Read the first three chapters in order; after that, each chapter stands on its
own.
