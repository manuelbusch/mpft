# Quick reference

The commands that come up most, one line each. Every URL with a `?` needs
quotes; a trailing `/` on a target means *directory*.

## Copying

```
mpft cp report.pdf sftp://deploy@srv.example.com/incoming/           # upload into a directory
mpft cp sftp://deploy@srv.example.com/incoming/report.pdf ./         # download
mpft cp ftps://old.example.com/out/x.csv "s3://bucket/in/"           # server to server, nothing local
mpft cp report.pdf sftp://srv/in/ "s3://bucket/in/" "mailto:boss@example.com?subject=Report"   # fan-out
mpft cp report.pdf mpft://prod/incoming/                              # a profile from the configuration
mpft ls sftp://deploy@srv.example.com/incoming/                      # list
```

[Copying a file](../guide/copying.md), [Several targets at once](../guide/fan-out.md),
[Profiles](../configuration/profiles.md).

## Many files

```
mpft cp -t sftp://srv/in/ *.csv                                      # several sources into one target
mpft cp 'sftp://srv/out/*.csv' /data/incoming/                       # a pattern on the far side
mpft cp -r /data/export/ sftp://srv/in/export/                       # a tree
mpft cp -r --skip-existing --allow-empty sftp://srv/outbox/ /data/inbox/   # a repeatable pull
mpft cp -r --skip-existing --delete-source sftp://srv/outbox/ /data/inbox/ # drain an outbox
mpft cp --dry-run 'in/*.csv' out/                                    # what would run
mpft batch jobs.txt --parallel 8                                     # a job list
find /export -name '*.pdf' -printf '%p sftp://srv/in/\n' | mpft batch -          # from a pipe
inotifywait -m -e close_write --format '%w%f sftp://srv/in/' /spool | mpft batch - --follow   # a queue
```

[Many files](../guide/many-files.md), [Job lists and pipelines](../guide/job-lists.md).

## Integrity

```
mpft cp --hash sha256 report.pdf sftp://srv/in/                      # checksum file beside the copy
mpft cp --check sftp://srv/in/report.pdf ./                          # verify against the source's
mpft cp --sign ssh:~/.ssh/release_ed25519 report.pdf "s3://releases/" # sign the checksum file
mpft cp --verify-signers allowed_signers "s3://releases/report.pdf" ./ # refuse an untrusted signature
```

[Checksums](../trust/checksums.md), [Signatures](../trust/signatures.md).

## Reliability

```
mpft --resume cp big.iso sftp://srv/in/                              # continue a part file
mpft cp --cache --retries 2 big.iso sftp://a/ sftp://b/              # retry from memory
mpft --timeout 120 cp big.iso sftp://srv/in/                         # patience with a slow line
mpft cp report.pdf "sftp://srv/in/?connect_retries=3"                # retry the connect only
```

[Interrupted and repeated transfers](../guide/reliability.md).

## Credentials and trust

```
mpft --password-stdin cp report.pdf ftps://upload@ftp.example.com/in/ < secret.txt
mpft cp report.pdf "sftp://deploy@srv/in/?key=~/.ssh/deploy_ed25519"
mpft cp report.pdf "sftp://deploy@srv/in/?hostkey=SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY"
mpft cp report.pdf "sftp://srv/in/?known_hosts=accept-new"           # trust on first use
mpft cp report.pdf "ftps://upload@ftp.internal/in/?insecure=true"    # one self-signed endpoint
mpft credentials set mpft/partner-ftp                                 # OS key store (feature keyring)
```

[Credentials and secrets](../configuration/credentials.md),
[Securing the connection](../trust/connections.md).

## Configuration and diagnosis

```
mpft config check                                                    # which files, what they set
mpft profiles                                                        # what mpft://<name> stands for
mpft schemes                                                         # what this binary speaks
mpft -vv cp …                                                        # the protocol conversation
mpft --json cp … > report.json                                       # the report for a program
mpft completions zsh > ~/.zfunc/_mpft ; mpft man | man -l -
```

[The configuration file](../configuration/file.md), [Troubleshooting](../appendix/troubleshooting.md).

## Services

```
mpft cp --via ssh://relay@fast.example.com:2222 report.pdf mpft://prod/ mpft://archive/   # through a relay
mpft cp --via mpft://relay --via-credentials on-demand report.pdf ftp://upload@partner/in/
mpft relay --listen                                                  # on the relay host
MPFT_API_TOKEN=… mpft serve                                           # jobs over HTTP (feature server)
curl -H "Authorization: Bearer $MPFT_API_TOKEN" -d '{"src":"mpft://inbox/r.pdf","dst":"mpft://prod/"}' localhost:7788/v1/jobs
```

[Relaying through a fast host](../server/relay.md), [Jobs over HTTP](../server/serve.md).
