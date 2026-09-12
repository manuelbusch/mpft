# Quick reference

The commands that come up most, one line each. Every URL with a `?` needs
quotes; a trailing `/` on a target means *directory*.

## Copying

```
mpt cp report.pdf sftp://deploy@srv.example.com/incoming/           # upload into a directory
mpt cp sftp://deploy@srv.example.com/incoming/report.pdf ./         # download
mpt cp ftps://old.example.com/out/x.csv "s3://bucket/in/"           # server to server, nothing local
mpt cp report.pdf sftp://srv/in/ "s3://bucket/in/" "mailto:boss@example.com?subject=Report"   # fan-out
mpt cp report.pdf mpt://prod/incoming/                              # a profile from the configuration
mpt ls sftp://deploy@srv.example.com/incoming/                      # list
```

[Copying a file](../guide/copying.md), [Several targets at once](../guide/fan-out.md),
[Profiles](../configuration/profiles.md).

## Many files

```
mpt cp -t sftp://srv/in/ *.csv                                      # several sources into one target
mpt cp 'sftp://srv/out/*.csv' /data/incoming/                       # a pattern on the far side
mpt cp -r /data/export/ sftp://srv/in/export/                       # a tree
mpt cp -r --skip-existing --allow-empty sftp://srv/outbox/ /data/inbox/   # a repeatable pull
mpt cp -r --skip-existing --delete-source sftp://srv/outbox/ /data/inbox/ # drain an outbox
mpt cp --dry-run 'in/*.csv' out/                                    # what would run
mpt batch jobs.txt --parallel 8                                     # a job list
find /export -name '*.pdf' -printf '%p sftp://srv/in/\n' | mpt batch -          # from a pipe
inotifywait -m -e close_write --format '%w%f sftp://srv/in/' /spool | mpt batch - --follow   # a queue
```

[Many files](../guide/many-files.md), [Job lists and pipelines](../guide/job-lists.md).

## Integrity

```
mpt cp --hash sha256 report.pdf sftp://srv/in/                      # checksum file beside the copy
mpt cp --check sftp://srv/in/report.pdf ./                          # verify against the source's
mpt cp --sign ssh:~/.ssh/release_ed25519 report.pdf "s3://releases/" # sign the checksum file
mpt cp --verify-signers allowed_signers "s3://releases/report.pdf" ./ # refuse an untrusted signature
```

[Checksums](../trust/checksums.md), [Signatures](../trust/signatures.md).

## Reliability

```
mpt --resume cp big.iso sftp://srv/in/                              # continue a part file
mpt cp --cache --retries 2 big.iso sftp://a/ sftp://b/              # retry from memory
mpt --timeout 120 cp big.iso sftp://srv/in/                         # patience with a slow line
mpt cp report.pdf "sftp://srv/in/?connect_retries=3"                # retry the connect only
```

[Interrupted and repeated transfers](../guide/reliability.md).

## Credentials and trust

```
mpt --password-stdin cp report.pdf ftps://upload@ftp.example.com/in/ < secret.txt
mpt cp report.pdf "sftp://deploy@srv/in/?key=~/.ssh/deploy_ed25519"
mpt cp report.pdf "sftp://deploy@srv/in/?hostkey=SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY"
mpt cp report.pdf "sftp://srv/in/?known_hosts=accept-new"           # trust on first use
mpt cp report.pdf "ftps://upload@ftp.internal/in/?insecure=true"    # one self-signed endpoint
mpt credentials set mpt/partner-ftp                                 # OS key store (feature keyring)
```

[Credentials and secrets](../configuration/credentials.md),
[Securing the connection](../trust/connections.md).

## Configuration and diagnosis

```
mpt config check                                                    # which files, what they set
mpt profiles                                                        # what mpt://<name> stands for
mpt schemes                                                         # what this binary speaks
mpt -vv cp …                                                        # the protocol conversation
mpt --json cp … > report.json                                       # the report for a program
mpt completions zsh > ~/.zfunc/_mpt ; mpt man | man -l -
```

[The configuration file](../configuration/file.md), [Troubleshooting](../appendix/troubleshooting.md).

## Services

```
mpt cp --via ssh://relay@fast.example.com:2222 report.pdf mpt://prod/ mpt://archive/   # through a relay
mpt cp --via mpt://relay --via-credentials on-demand report.pdf ftp://upload@partner/in/
mpt relay --listen                                                  # on the relay host
MPT_API_TOKEN=… mpt serve                                           # jobs over HTTP (feature server)
curl -H "Authorization: Bearer $MPT_API_TOKEN" -d '{"src":"mpt://inbox/r.pdf","dst":"mpt://prod/"}' localhost:7788/v1/jobs
```

[Relaying through a fast host](../server/relay.md), [Jobs over HTTP](../server/serve.md).
