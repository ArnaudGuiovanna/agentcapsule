# Backup and recovery

The objectives come from [ADR 004](adr/004-recovery-objectives.md):
- **A local restart** (a process, PostgreSQL, a host reboot) loses nothing.
- **After a disaster**, the platform restarts on a standby host within an
  hour. It may lose up to 15 minutes of database work and up to 24 hours of an
  agent's memory. Any such loss is announced and the work is run again.

This page covers what is in place. The rest of the plan is at the end.

## PostgreSQL: continuous archiving (REC-03)

[pgBackRest](https://pgbackrest.org/) pushes every WAL segment, and every base
backup, to **two repositories**. Each one is encrypted (AES-256) with its own
passphrase before it leaves the host:
1. **S3-compatible object storage**, versioned at the provider.
2. **The standby host, over SFTP.** Its host key is checked strictly. It is
   also where the standby will read WAL to replay.

Neither store sees data in clear, and either one alone restores the
database. `archive_timeout = 300` closes a segment at least every 5 minutes,
so a commit reaches both repositories within about 5 minutes. The RPO is 15
minutes, which keeps a margin for an outage of one store. Base backups run at
night:
- a full backup on Sunday;
- a differential backup on the other days.

Each repository keeps its own backups: four weeks on S3, two on the standby.
The WAL archive follows them.

### Freshness

Operators must learn that the RPO no longer holds before they need a backup.
Metrics and alerts watch both parts of it.
[observability.md](observability.md) lists them.

**WAL archiving.** At each scrape, the worker reads PostgreSQL's archiver:
- whether archiving is on, and `archive_timeout`;
- the time since the last archive;
- whether a completed segment waits;
- whether the latest attempt failed.

The alerts fire when:
- archiving is off, or `archive_timeout` is off or above 15 minutes;
- archiving has failed for 5 minutes;
- nothing was archived for 15 minutes while a segment waits: the RPO is
  breached;
- a segment has waited at every scrape for 15 minutes: archiving does not keep
  up.

An idle database writes no WAL, so it has nothing to archive. Its old last
archive raises no alert.

**Base backups.** Every 15 minutes, a timer runs `pgbackrest info` and writes,
for node_exporter, when the newest full and the newest differential backup of
each repository finished. The alerts fire when:
- a repository has no base backup from the last 26 hours (one per night, plus
  2 hours of margin);
- a repository has no full backup from the last 8 days (one per week, plus a
  day);
- pgBackRest cannot read a repository for 30 minutes;
- the times have not been collected for an hour.

The times come from the repositories, not from the backup jobs. A backup that
expired or was lost, or a store that cannot be read, shows too.

### Install

The files are in [deploy/backup](../deploy/backup).

1. **Install pgBackRest**: `apt install pgbackrest`. The configuration is
   qualified with pgBackRest 2.58.
2. **Repositories.**
   - Create the bucket at the provider, with versioning, and a credential
     limited to that bucket.
   - On the standby, create a `backup` user, limited to SFTP in its home, with
     a `repo` directory.
3. **Configuration and secrets.**
   - Copy `pgbackrest.conf` to `/etc/pgbackrest/` (root:postgres, 0640).
     Replace the endpoint, region, bucket and standby host.
   - Write `conf.d/secrets.conf` from the example (postgres, 0600). Generate
     each passphrase with `openssl rand -hex 32`.
   - **Keep a copy of both passphrases off the host**: without them, the
     backups cannot be read.
4. **SSH.**
   - Create the SSH key `backup_ed25519` of the `postgres` user and authorize
     it on the standby.
   - Put the standby's host key in `/etc/pgbackrest/known_hosts`
     (`ssh-keyscan -t ed25519 standby.example.net`).
5. **PostgreSQL.** Append [postgresql.conf](../deploy/backup/postgresql.conf)
   to the cluster's configuration, then restart PostgreSQL.
6. **First backup.** As `postgres`, create the stanza, check it, and take a
   first full backup into each repository:
   ```sh
   pgbackrest --stanza=agentcapsule stanza-create
   pgbackrest --stanza=agentcapsule check    # archives a segment to both repositories
   pgbackrest --stanza=agentcapsule --repo=1 --type=full backup
   pgbackrest --stanza=agentcapsule --repo=2 --type=full backup
   ```
7. **Timers.** Install `agentcapsule-pg-backup@.service` and the two timers in
   `/etc/systemd/system`, then run:
   ```sh
   systemctl enable --now agentcapsule-pg-backup-full.timer agentcapsule-pg-backup-diff.timer
   ```
8. **Freshness.**
   - Copy `agentcapsule-backup-metrics.py` to `/opt/agentcapsule/` (root,
     0755).
   - node_exporter's textfile collector must read
     `/var/lib/prometheus/node-exporter`. That is the default of the Debian
     and Ubuntu `prometheus-node-exporter` package. Otherwise, change
     `--textfile-directory` in the service.
   - Install `agentcapsule-backup-metrics.service` and its timer in
     `/etc/systemd/system`, then run:
     ```sh
     systemctl enable --now agentcapsule-backup-metrics.timer
     ```
   - Give Prometheus the rules of
     [deploy/prometheus/alerts.yml](../deploy/prometheus/alerts.yml).

### Qualify

`scripts/verify-backups.py` runs the shipped configuration against an object
store (SeaweedFS 4.53) and an SFTP server (OpenSSH), both run with Docker and
pinned by digest. It needs no root and runs in about four minutes:

```sh
python3 scripts/verify-backups.py --pg-bin <postgres-bin-dir> --pgbackrest <pgbackrest> \
  [--pg-library-path <dir>] --output <new-dir>
```

It checks:
- **The stanza and the backups**: creating the stanza and a full backup into
  each repository.
- **The loss bound**: a commit, with no manual switch, reaches both
  repositories within `archive_timeout` (30 s in the run; 30.3 s measured on
  2026-11-13).
- **Restoring**: from each repository alone, into a new data directory, every
  committed row is back (201 of 201). The restore from S3 goes through its
  differential backup.
- **Encryption**: neither store holds a marker written in the rows, while the
  primary's own WAL does. That control proves the search works.
- **Freshness**: `agentcapsule-backup-metrics.py`, run after the full backups
  and after a differential one into S3, reports the times of those backups.
  With the standby's store stopped, that repository is reported unreadable
  and S3's times stay. The file has mode 0644 and holds none of the run's
  secrets. Passed on 2026-11-13.

pgBackRest writes `<redacted>` in its logs for the S3 secret and the cipher
passphrases.

## Volume archives (REC-02)

The maintenance worker archives each agent's encrypted volume about once a day,
without being stopped. The volume RPO is 24 hours. Configure the `archives`
section of the worker ([worker.md](worker.md#nightly-encrypted-archives)):

- **A sleeping agent** is captured as it is, from 22 hours after its last
  archive (`every` minus `sleep_window`), or at once if it has none.
- **A running agent** is stopped briefly when its last archive is 24 hours old
  (`every`): authenticated quiescence, then the copy. It stays asleep and wakes
  on its next delivery. So the newest archive of an agent is at most `every`
  old, plus one pass and one capture, even if the agent never sleeps. A failed
  capture is retried after a delay, and an agent stopped uncleanly waits for its
  next clean sleep: the metric below shows such delays.
- **What is stored.** An archive is the agent's LUKS container, as it is on
  disk, with a manifest signed by the restore authority. It holds no key. It is
  published in one step: a crash leaves no partial archive.
- **Where.** In the worker's archive root, on this host. The worker keeps the
  `keep` newest archives of each agent (7 by default) and never deletes an
  agent's only archive.
- **Records.** PostgreSQL records each capture (`volume_archives`): times,
  size, volume, no content. They decide which agents are due, and give the
  metric `agentcapsule_worker_volume_archive_oldest_seconds`.

The archives are still on the host they protect. **Shipping them off the host**
(to the S3-compatible store and the standby) is a separate step: until it is
done, they do not survive the loss of the host.

The selection, the records and retention are tested on PostgreSQL. The KVM test
`TestProductWorkerNightlyVolumeArchives` covers real VMs: a sleeping agent
archived by the running maintenance loop while it delivers to another agent,
then an overdue running agent stopped for its archive and woken by its next
invocation. Each archive is opened with the restore authority (manifest, size,
digest). This test is compiled and remains to be run under KVM. A restore from
an archive is not yet built.

## Still to do (ADR 004)

1. **The standby.** It replays the WAL archive continuously
   (`restore_command` from repository 2), ready to be promoted.
2. **Freshness of the volume archives.** WAL archiving and the base backups
   have their metrics and alerts (above). The volume archive metrics exist;
   their alert rules remain.
3. **Volume archives off the host.** Nightly archives are taken on the host
   without stopping the maintenance worker (above). Shipping them to the
   S3-compatible store and to the standby, encrypted as they are, remains.
4. **The declared-loss state** in the code and the API. The P2 model is
   revised ([ADR 003](adr/003-restore-rpo.md#model-revision-option-b)).
5. **A failover exercise** that measures the RPO and the RTO.
6. **CI.** Ubuntu 24.04 ships an older pgBackRest than the qualified 2.58.
   Running this qualification in CI needs a pinned 2.58.
