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
   also where the standby reads WAL to replay ([below](#the-standby-rec-03)).

Neither store sees data in clear, and either one alone restores the
database. `archive_timeout = 300` closes a segment at least every 5 minutes,
so a commit reaches both repositories within about 5 minutes. The RPO is 15
minutes, which keeps a margin for an outage of one store.
`checkpoint_timeout` is pinned at 5 minutes too, and must not exceed
`archive_timeout`: right after PostgreSQL starts, the first forced switch
waits for the checkpointer's first wake, up to `checkpoint_timeout`. With
PostgreSQL 18.6, `archive_timeout = 10` and `checkpoint_timeout = 40`, it
came after 40 seconds; with both at 30, after 30.

Base backups run at night:
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
   - On the standby, create the `backup` user, limited to SFTP in its home,
     with a `repo` directory ([the standby](#the-standby-rec-03), step 1).
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
pinned by digest. It needs no root and runs in about seven minutes, the
standby included:

```sh
python3 scripts/verify-backups.py --pg-bin <postgres-bin-dir> --pgbackrest <pgbackrest> \
  [--pg-library-path <dir>] --output <new-dir>
```

It checks:
- **The stanza and the backups**: creating the stanza and a full backup into
  each repository.
- **The loss bound**: a commit, with no manual switch, reaches both
  repositories within `archive_timeout` (30 s in the run, with
  `checkpoint_timeout` scaled to match; 29.3 to 31.3 s measured over six
  runs on 2026-11-13).
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
passphrases. The run searches all its evidence, pgBackRest's own log files
included, for every secret it generated, and finds none.

The same run qualifies the standby ([below](#qualify-the-standby)).

## The standby (REC-03)

The standby host receives repository 2 over SFTP. Its PostgreSQL replays that
archive continuously, as a standby, so that it can take over within seconds.
The files are in [deploy/standby](../deploy/standby).

- **Where the WAL comes from.** pgBackRest on the standby has two
  repositories, tried in order:
  1. the SFTP directory, read on the standby's own disk: no network, no cost;
  2. the S3 store, with a read-only credential. A segment that did not reach
     the standby (the primary cannot reach it, a push failed) still comes
     from there. The replay goes on, and a promotion loses no more than the
     fresher store lacks.
- **What it may do.** `postgres` reads the SFTP directory through the
  `backup` group, and cannot write it. The S3 credential can only read and
  list. The standby takes no backup, and archives nothing until it is
  promoted.
- **How far behind it is.** A commit reaches the standby once its segment is
  archived, then at the standby's next poll (every 5 seconds): within about
  `archive_timeout`, 5 minutes in production. When the standby's SFTP server
  does not answer at all, the primary's push holds the segment for
  pgBackRest's `io-timeout` (1 minute) before it reaches S3: about 6 minutes
  then, still within the 15-minute RPO.

### Install the standby

On the standby host, as root.

1. **The SFTP user.** The primary pushes into its `repo` directory, which the
   standby reads as `/srv/backup/repo`:
   ```sh
   useradd --system --user-group --home-dir /srv/backup --shell /usr/sbin/nologin backup
   install -d -o root -g root -m 0755 /srv/backup
   install -d -o backup -g backup -m 0750 /srv/backup/repo
   install -d -m 0755 /etc/ssh/authorized_keys
   install -m 0644 backup_ed25519.pub /etc/ssh/authorized_keys/backup   # the primary's public key
   ```
   Append to `/etc/ssh/sshd_config` (a `Match` block comes last), then run
   `sshd -t && systemctl reload ssh`:
   ```
   Match User backup
       ChrootDirectory %h
       ForceCommand internal-sftp
       AuthorizedKeysFile /etc/ssh/authorized_keys/%u
       AllowTcpForwarding no
       X11Forwarding no
       PermitTTY no
   ```
   The key file is outside the chroot, so the `backup` user cannot change it.
2. **PostgreSQL and pgBackRest**, the same versions as the primary's:
   `apt install postgresql-18 pgbackrest`. Then let `postgres` read the
   repository: `usermod -aG backup postgres`.
3. **Configuration and secrets.**
   - Copy [pgbackrest.conf](../deploy/standby/pgbackrest.conf) to
     `/etc/pgbackrest/` (root:postgres, 0640). Replace the endpoint, region
     and bucket with the primary's.
   - Write `conf.d/secrets.conf` from
     [the example](../deploy/standby/conf.d/secrets.conf.example) (postgres,
     0600). The passphrases are the primary's, swapped: repository 1 here is
     repository 2 there. The S3 credential is a new one, limited to reading
     and listing the bucket.
4. **PostgreSQL.** Append [postgresql.conf](../deploy/standby/postgresql.conf)
   to `/etc/postgresql/18/main/postgresql.conf`. Its `archive_command` is
   empty on purpose: see [Promote](#promote).

Do not install the backup timers or the freshness timer of deploy/backup on
the standby. The freshness script names repository 1 `s3` and repository 2
`standby`, as on the primary; here the numbers mean other stores.

### Build

Once the primary has a backup in repository 2, as `postgres`:

```sh
pg_ctlcluster 18 main stop
pgbackrest --stanza=agentcapsule --type=standby --delta restore
pg_ctlcluster 18 main start
```

The restore copies the latest backup of the first repository that has one:
the local directory. It writes `standby.signal`, and sets in
`postgresql.auto.conf`:

```
restore_command = 'pgbackrest --stanza=agentcapsule archive-get %f "%p"'
```

That command searches both repositories, in order. Do not add `--repo=1` to
the restore: pgBackRest would copy it into `restore_command`, which would
then never fall back to S3.

PostgreSQL starts as a standby, replays the archive since the backup, then
follows it. To check it:
`psql -c 'SELECT pg_is_in_recovery(), pg_last_xact_replay_timestamp()'`.

The same commands rebuild the standby from a newer backup, for example after
the replay stopped for longer than the retention.

### Promote

When the primary is lost. The RTO starts at the decision to fail over.

1. **Fence the old primary.** It must not come back as a primary, nor push
   into the repositories:
   - stop it, or cut it off, if it can still be reached;
   - remove its key from `/etc/ssh/authorized_keys/backup` on the standby;
   - revoke its S3 credential at the provider.
2. **Promote**, as `postgres`: `pg_ctlcluster 18 main promote`. PostgreSQL
   first replays every segment it can still fetch, from either repository,
   then accepts writes on a new timeline. `SELECT pg_is_in_recovery()`
   returns `f`.
3. **Give it repositories of its own.** Until then it archives nothing, and
   keeps every new WAL segment in `pg_wal`. It must never push into the old
   primary's repositories.
   - `/etc/pgbackrest/pgbackrest.conf`: the primary's
     [file](../deploy/backup/pgbackrest.conf), with
     `repo1-path=/agentcapsule-2` (a path the old primary never wrote), and
     without the `repo2` lines until there is a new standby.
   - `conf.d/secrets.conf`: a new S3 credential that can write, and a new
     `repo1-cipher-pass`.

   Then, as `postgres`:
   ```sh
   pgbackrest --stanza=agentcapsule stanza-create
   psql -c "ALTER SYSTEM SET archive_command = 'pgbackrest --stanza=agentcapsule archive-push %p'" \
        -c "SELECT pg_reload_conf()"
   pgbackrest --stanza=agentcapsule check    # the new timeline reaches the new path
   pgbackrest --stanza=agentcapsule --repo=1 --type=full backup
   ```
   Leave the old repositories as they are: they hold the history up to the
   disaster.
4. **Then the rest of the platform**: the configuration, the authorities,
   the agents and the address ([ADR 004](adr/004-recovery-objectives.md)).
   Build a new standby as soon as possible, and give the new primary its
   `repo2` back. The backup timers back up both repositories, so they wait
   for it; until then, take the nightly backup with `--repo=1`. Install the
   freshness timer at once. Until there is a new standby, it reports the
   standby's repository as unreadable, and that alert stays on: there is no
   second copy.

### Qualify the standby

`scripts/verify-backups.py` (above) goes on with the standby, as
[deploy/standby](../deploy/standby) ships it. The SFTP server writes into a
directory of the host, which the standby reads as its repository 1, as on the
standby host; S3 is its repository 2, with a read-only credential. It checks:
- **The build**: from the local directory alone, the standby replays every
  committed row (201 of 201) and stays in recovery. It does not inherit the
  primary's `archive_command`.
- **The replay**: a commit made just after a segment switch, the worst case,
  is on the standby in 33.5 s, for `archive_timeout` = 30 s. With the SFTP
  server paused, it is there in 88.4 s, and its segment is not in the local
  directory: it came from S3. The extra minute is the primary's push waiting
  on the silent SFTP server (`io-timeout`).
- **The disaster**: the primary commits a row a second for 45 seconds, then
  stops at once (`pg_ctl -m immediate`). Its unfinished pushes, if any, are
  killed. The standby is promoted.
  - **The loss**: 22 of the 45 rows are on the promoted standby, 23 are
    lost. Every row whose commit ends inside the archived segments is there,
    and no row after them: the survivors are exactly the rows committed
    before the last archived segment ends. The oldest lost row was committed
    23.0 s before the loss, within `archive_timeout`.
  - **The promotion**: 0.5 s, from `pg_ctl promote` to the first write
    accepted, on timeline 2. Every row committed before the disaster
    phase is there too.
- **After the promotion**: the new primary archives timeline 2 into a
  repository of its own, with the WAL kept since the promotion (its history
  file included), and takes a full backup there. The old primary's
  repositories hold timeline 1 only. With the new configuration, the
  freshness script reports that backup in S3, and the standby's repository
  as unreadable.
- **The SFTP repository's modes**: files 0640 and directories 0750, so the
  `backup` group reads them and no one else does. The run uses a single user,
  so it does not exercise the group itself.

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

1. **Freshness of the volume archives and of the standby.** WAL archiving and
   the base backups have their metrics and alerts (above). The volume archive
   metrics exist; their alert rules remain. The standby's replay has no
   metric yet (`pg_last_xact_replay_timestamp()` on the standby).
2. **Volume archives off the host.** Nightly archives are taken on the host
   without stopping the maintenance worker (above). Shipping them to the
   S3-compatible store and to the standby, encrypted as they are, remains.
3. **The declared-loss state** in the code and the API. The P2 model is
   revised ([ADR 003](adr/003-restore-rpo.md#model-revision-option-b)).
4. **A failover exercise** that measures the RPO and the RTO of the whole
   platform, on real hosts. The database's part is measured
   ([the standby](#qualify-the-standby)); the configuration, the authorities,
   the agents and the address are not.
5. **CI.** Ubuntu 24.04 ships an older pgBackRest than the qualified 2.58.
   Running this qualification in CI needs a pinned 2.58.
