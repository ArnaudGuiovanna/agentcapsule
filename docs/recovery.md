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
9. **Heartbeat.** Install `agentcapsule-pg-heartbeat.service` and its timer
   in `/etc/systemd/system`, then run
   `systemctl enable --now agentcapsule-pg-heartbeat.timer`. It commits an
   empty transaction every minute, so that the standby's replay can be
   measured ([below](#how-far-behind-the-standby-is)).

### Qualify

`scripts/verify-backups.py` runs the shipped configuration against an object
store (SeaweedFS 4.53) and an SFTP server (OpenSSH), both run with Docker and
pinned by digest. It needs no root and runs in about seven minutes, the
standby included:

```sh
python3 scripts/verify-backups.py --pg-bin <postgres-bin-dir> --pgbackrest <pgbackrest> \
  [--pg-library-path <dir>] --output <new-dir>
```

`scripts/fetch-backup-tools.py` gets pgBackRest 2.58 without root or apt: the
exact package of Ubuntu 26.04, checked against its SHA-256
([scripts/README.md](../scripts/README.md#backup-qualifications)). CI runs
this qualification on every pull request and every push to `main`.

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
5. **Replay freshness.** Copy
   [agentcapsule-standby-metrics.py](../deploy/standby/agentcapsule-standby-metrics.py)
   to `/opt/agentcapsule/` (root, 0755). Install its service and timer in
   `/etc/systemd/system`, then run
   `systemctl enable --now agentcapsule-standby-metrics.timer`. node_exporter
   reads its textfile directory, as on the primary.

Do not install the backup timers, the freshness timer or the heartbeat of
deploy/backup on the standby. The freshness script names repository 1 `s3`
and repository 2 `standby`, as on the primary; here the numbers mean other
stores.

### How far behind the standby is

Every minute, `agentcapsule-standby-metrics.timer` asks the standby's
PostgreSQL, as `postgres`, and writes for node_exporter:
- whether it answered;
- whether it is in recovery, replaying the archive;
- the commit time of the last transaction it replayed
  (`pg_last_xact_replay_timestamp()`). If it replayed none since it started,
  the time it started.

**What is measured.** The age of the last replayed transaction measures the
replay only if the primary commits. An idle platform may commit nothing for
hours, and its standby would look late although nothing waits. So the primary
commits an empty transaction every minute (`agentcapsule-pg-heartbeat.timer`):
it takes a transaction ID and changes no table. A standby that keeps up has
then always replayed a transaction from the last 6 or 7 minutes:
`archive_timeout`, plus the heartbeat's minute, plus the push and the poll.
The commit time comes from the primary's clock: both hosts keep time with NTP.

The cost: the heartbeat's WAL makes `archive_timeout` close a segment every 5
minutes even when nothing else happens, 288 segments a day. Such a segment is
nearly empty: it compressed to less than a kilobyte with zstd
([measured](#qualify-the-shipping)).

The alerts fire when:
- the standby, in recovery, has replayed no transaction committed in the last
  15 minutes: it is behind the database's RPO (critical);
- it is not in recovery for 5 minutes: it was promoted, or started as a
  primary (critical). After a planned promotion, disable its timer;
- its PostgreSQL does not answer for 5 minutes;
- the replay has not been collected for 10 minutes, or never was.

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
   psql -c CHECKPOINT
   pgbackrest --stanza=agentcapsule --repo=1 --type=full backup
   ```
   Run the checkpoint before the backup. Until the checkpoint that follows
   the promotion ends, `pg_control` keeps the old timeline, and pgBackRest
   refuses the backup: `WAL timeline 2 does not match pg_control timeline 1`.
   PostgreSQL spreads that checkpoint over up to 90 % of
   `checkpoint_timeout`: up to about 4.5 minutes in production.
   Leave the old repositories as they are: they hold the history up to the
   disaster.
4. **Then the rest of the platform**: the configuration, the authorities,
   the agents and the address ([ADR 004](adr/004-recovery-objectives.md)).
   [Failover](#failover-rec-03) gives the whole procedure, in order.
   Build a new standby as soon as possible, and give the new primary its
   `repo2` back. The backup timers back up both repositories, so they wait
   for it; until then, take the nightly backup with `--repo=1`. Install the
   freshness timer at once. Until there is a new standby, it reports the
   standby's repository as unreadable, and that alert stays on: there is no
   second copy.
5. **The timers of a primary.** Disable `agentcapsule-standby-metrics.timer`
   on the promoted host: it now reports that the server is not in recovery.
   Enable `agentcapsule-pg-heartbeat.timer` once there is a new standby. Ship
   the new host's volume archives to stores of its own (a new bucket, or a
   new path, with new passphrases), as pgBackRest does: the old stores keep
   the history up to the disaster.

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

## The authorities' replica (D-05)

The key authority and the restore authority must never go back in time, and
must survive the primary. [ADR 005](adr/005-keys-outside-restored-domain.md)
keeps a synchronous replica of both on the standby: every write of the
authorities returns only once the standby holds it on disk. Volume keys, the
API's daily receipt keys and the catalogue's signing secret reach the
standby only wrapped to the operator's **unlock key**, which stays off both
hosts.

Without the replica, the authorities are standalone: losing the primary loses
every volume key, so every archive. Install the replica before any agent
holds data that matters.

`agentcapsule-authority` does every step. Build it like the worker, on the
same release, and install it on both hosts. On each host, one process owns
the authorities: the **authority service**, `agentcapsule-authority serve`
([ADR 006](adr/006-authority-service.md)), as the account
`agentcapsule-authority`. On the primary it serves the worker's socket and
the API's, and holds the link to the standby; on the standby it holds the
replica. While it runs, every other command that opens its directories refuses
(`authority_in_use`): stop it first where a step says so. Run the commands
that open the directories (`snapshot`, `init-replica`, `promote`,
`agentcapsule-admin init-key-authority` and `init-restore-authority`) as its
account, `runuser -u agentcapsule-authority -- …`: the directories belong to
it, and the commands refuse files of another owner.

### Install the authority service

Files of [deploy/systemd](../deploy/systemd), the same on both hosts:

| File | Install as | Role |
| --- | --- | --- |
| `agentcapsule-authority.service` | `/etc/systemd/system/` | The service, as `agentcapsule-authority`, `Restart=always` after 1 second, no core dump, no privilege; it writes only the authority directories and `/run/agentcapsule-authority` |
| `agentcapsule-authority.sysusers` | `/usr/lib/sysusers.d/agentcapsule-authority.conf` | The account `agentcapsule-authority`, and the group `agentcapsule-authority-clients` for the API's socket |
| `agentcapsule-authority.tmpfiles` | `/usr/lib/tmpfiles.d/agentcapsule-authority.conf` | `/run/agentcapsule-authority`, mode 2750: the sockets' directory |
| `agentcapsule-authority-client.conf` | `/etc/systemd/system/agentcapsule-worker.service.d/authority.conf` and `/etc/systemd/system/agentcapsule-api.service.d/authority.conf` | The worker's and the API's units start after the service (`Wants=`, `After=`), and do not restart with it |

**A new install**, on the primary, as root:
1. Install `/opt/agentcapsule/agentcapsule-authority` and the files above,
   then run `systemd-sysusers`, `systemd-tmpfiles --create` and
   `systemctl daemon-reload`.
2. **Initialize both authorities** as the service's account:
   ```sh
   install -d -o agentcapsule-authority -g agentcapsule-authority -m 0700 /var/lib/agentcapsule-key-authority /var/lib/agentcapsule-restore-authority
   runuser -u agentcapsule-authority -- agentcapsule-admin init-key-authority -root /var/lib/agentcapsule-key-authority
   runuser -u agentcapsule-authority -- agentcapsule-admin init-restore-authority -root /var/lib/agentcapsule-restore-authority \
     -data-root /var/lib/agentcapsule/host -key-authority-root /var/lib/agentcapsule-key-authority -key-authority-id <keyauth_…>
   ```
   Each prints the identity to pin.
3. **Configure** `/etc/agentcapsule/authority.json`, owned by root, not
   writable by others, from
   [primary.example.json](../runtime/authority/primary.example.json):
   - `role` is `primary`;
   - the two directories, with their identities;
   - `worker_socket` and `api_socket` in `/run/agentcapsule-authority`;
   - `api_uid` is the UID of the API's account (`id -u <account>`), not 0.
     Add that account to the group `agentcapsule-authority-clients`, which
     may open `api.sock`: the sysusers file's `m` line names it. Then run
     `systemd-sysusers` again;
   - `max_key_hold`: how long the worker may hold a key, for a boot or the
     format of a volume. `2m` by default, from `30s` to `10m`;
   - `authority_replica` once the replica is installed
     ([below](#install-the-replica)); without it, the authorities are
     standalone;
   - `metrics_listen`: `127.0.0.1:9466`. Add the `agentcapsule-authority`
     scrape job ([prometheus.yml](../deploy/prometheus/prometheus.yml)).
4. **Start it**: `systemctl enable --now agentcapsule-authority`. It logs
   `service_started` with its epoch and mode. Then give the worker its
   `authority` section ([worker.md](worker.md)) and start it, and give the
   API its flags ([docs/api](api/README.md#the-authority-service)):
   ```sh
   -authority-socket /run/agentcapsule-authority/api.sock \
     -restore-authority-id <restoreauth_…> -key-authority-id <keyauth_…>
   ```
   In production the API refuses to start without them
   (`authority_required_in_production`). Install the drop-in for both units.

**An existing install**, where the worker opened the authorities itself:
1. Install the new binaries, the files above, and run `systemd-sysusers`,
   `systemd-tmpfiles --create` and `systemctl daemon-reload`.
2. **Stop the worker**, and any archive or restore command.
3. **Give both authority directories to the service's account**:
   `chown -R agentcapsule-authority:agentcapsule-authority` on each, and on
   the link's private key `authority-primary.key` (mode 0600) if the replica
   is installed. The old worker can no longer open them: their owner is not
   its account.
4. **Write `/etc/agentcapsule/authority.json`** from the worker's sections:
   `key_authority` and `restore_authority` become the two directories,
   `authority_replica` moves unchanged. In `worker.json`, replace the three
   sections with `authority`: the worker refuses them now
   (`authority_service_required`).
5. **Start the service.** With the replica, check
   `agentcapsule_authority_replication_enabled 1` on port 9466, and that
   `_acknowledged_sequence` follows `_committed_sequence`. Install the
   worker's drop-in, start the worker, and add the scrape job.
6. **The API.** Add its account to `agentcapsule-authority-clients`, give it
   the three flags of a new install (step 4 above), install the drop-in for
   its unit, and restart it. A new release of the API refuses to start
   without them in production.

On the standby, the replica's `authority-replica.json` becomes
`/etc/agentcapsule/authority.json` with `"version": 2` and
`"role": "replica"` ([replica.example.json](../runtime/authority/replica.example.json)),
and runs under the same unit. The directory and the key already belong to
`agentcapsule-authority`.

**Rollback**, until the catalogue's version 4 (ADR 006, wave 5, which adds
the access revocation records): stop both, give the directories back to
root, restore the old `worker.json`, the old binaries, and the API's flags
without the authority service. A catalogue of version 4 does not go back.

**The service restarts** (an upgrade, a crash): for a few seconds no agent
boots, platform calls fail with an error the guest retries, deliveries wait,
and a restore pauses. Running VMs stay. The API keeps serving, but its
readiness probe answers 503 (`authority_unavailable`) until the service
answers again. Then restoring or deleting an agent waits up to
`max_key_hold` before it starts. An API that starts while the service does
not answer waits for it, and logs `authority_service_waiting` once. Upgrade
the service before the worker and the API; on a release that adds a record
to the stream, upgrade the standby's service first. Run `init-restore-authority` for a schema
upgrade with the service stopped. `AgentCapsuleAuthorityServiceDown`
(critical) fires when it does not answer for 2 minutes.

**The upgrade to wave 5** (the access revocation records, ADR 006) adds a
table and two statements to the stream. In this order:

1. On the standby, install the new binary and restart
   `agentcapsule-authority serve`. It adds the new tables to its replica
   when it opens it, and changes nothing recorded.
2. On the primary, stop the authority service, run
   `agentcapsule-admin init-restore-authority` again as
   `agentcapsule-authority` (it upgrades the catalogue to version 4 and
   keeps the identity), install the new binary, and start the service. A
   new service refuses an older catalogue
   (`restore_authority_upgrade_required`).
3. Then the worker and the API.

A standby left on the previous release refuses the first access revocation
record (`conflict` in `agentcapsule_authority_replica_refusals_total`), and
that refusal stops the primary: no authority operation runs until the
standby runs the new release
(`AgentCapsuleAuthorityReplicationStopped`). The revocation that met the
refusal took effect, and stays pending until the upgraded standby holds
its record.

**The upgrade to schema version 5** (scoped revocations and holds per
store, after the v0.1.0 audit, [ADR 006](adr/006-authority-service.md#changes-after-the-v010-audit))
adds a table, `revocation_scopes`, and one statement to the stream. Same
order as wave 5: the standby's service first, then on the primary
`init-restore-authority` (it upgrades the catalogue to version 5) with the
service stopped, then the new service, then the worker and the API. The
service speaks protocol 2 and still serves a worker of protocol 1 during
the upgrade. Subjects revoked before the upgrade stay in every store's
scope: a store restored later still fences them all.

### Install the replica

1. **On the primary, stop the authority service**:
   `systemctl stop agentcapsule-authority`. The worker waits for it, and
   keeps its VMs. The snapshot takes the directories' lock, and refuses
   while the service runs (`authority_in_use`).
2. **Upgrade the catalogue** to version 3, which adds the log: run
   `agentcapsule-admin init-restore-authority` again as
   `agentcapsule-authority`, with the same flags as at installation. It
   keeps the identity.
3. **Create the unlock key**, on a workstation if possible, or on the
   primary, then move it off:
   ```sh
   agentcapsule-authority unlock-key -out /root/agentcapsule-unlock.key
   ```
   It prints the recipient, the public part. Copy the key file to the safe
   that holds the backup passphrases ([below](#secrets-to-keep-off-the-hosts)),
   then delete it from the host (`shred -u`). Neither host keeps it.
4. **Create the link's certificates**, one per host. Each names the two
   authorities; use the identities pinned in `authority.json`:
   ```sh
   agentcapsule-authority certificate -role primary \
     -restore-authority-id <restoreauth_…> -key-authority-id <keyauth_…> \
     -certificate /etc/agentcapsule/authority-primary.crt -key /etc/agentcapsule/authority-primary.key
   ```
   Run it on the standby with `-role replica` and `authority-replica.*`. On
   each host, give the key file to `agentcapsule-authority` (mode 0600).
   Copy each `.crt` file, never a `.key`, to the other host. The certificates are pinned: replacing one means
   copying it again.
5. **Take the snapshot** on the primary, outside both authorities, the
   service stopped:
   ```sh
   runuser -u agentcapsule-authority -- agentcapsule-authority snapshot \
     -key-authority-root <key_authority.root> -key-authority-id <keyauth_…> \
     -restore-authority-root <restore_authority.root> -restore-authority-id <restoreauth_…> \
     -recipient <recipient> -out /var/lib/agentcapsule-authority-snapshot/authority-snapshot.sqlite
   ```
   Create that directory first, for the service's account:
   `install -d -o agentcapsule-authority -g agentcapsule-authority -m 0700 /var/lib/agentcapsule-authority-snapshot`.
   This **arms** both authorities: from now on the service refuses to start
   without `authority_replica`. The file holds the catalogue, the secret and
   every live key wrapped to the unlock key, and no secret in clear. It still
   lists agents, stores and revocations: copy it over SSH, then delete it.
6. **On the standby, create the replica** as `agentcapsule-authority`, which
   owns only its directory. Install the files of
   [Install the authority service](#install-the-authority-service) first:
   ```sh
   install -d -o agentcapsule-authority -g agentcapsule-authority -m 0700 /var/lib/agentcapsule-authority-replica
   runuser -u agentcapsule-authority -- agentcapsule-authority init-replica \
     -root /var/lib/agentcapsule-authority-replica/replica -snapshot /tmp/authority-snapshot.sqlite
   ```
   Then delete the snapshot on both hosts: `shred -u /tmp/authority-snapshot.sqlite`.
   It keeps a wrapped copy of every key it holds, so a key destroyed later
   would come back from it with the unlock key
   ([Deleting an agent](#deleting-an-agent-its-keys-and-its-archives-adr-018)).
7. **Configure and start the replica.** `/etc/agentcapsule/authority.json`,
   owned by root, not writable by others
   ([replica.example.json](../runtime/authority/replica.example.json)):
   ```json
   {
     "version": 2,
     "role": "replica",
     "root": "/var/lib/agentcapsule-authority-replica/replica",
     "restore_authority_id": "<restoreauth_…>",
     "key_authority_id": "<keyauth_…>",
     "listen": "0.0.0.0:7443",
     "certificate": "/etc/agentcapsule/authority-replica.crt",
     "key": "/etc/agentcapsule/authority-replica.key",
     "primary_certificate": "/etc/agentcapsule/authority-primary.crt",
     "metrics_listen": "127.0.0.1:9466"
   }
   ```
   Run `systemctl enable --now agentcapsule-authority`: the shipped unit runs
   `serve -config /etc/agentcapsule/authority.json` as
   `agentcapsule-authority`. Add the primary's address to its
   `IPAddressAllow=` in a drop-in, and let only that address reach the port.
   A version 1 file without `role` is read as the replica's too. It logs JSON events
   (`replica_started`, `replica_refused` with its kind, `replica_stopped`) and
   serves `agentcapsule_authority_replica_applied_sequence`, `_epoch`,
   `_last_apply_timestamp_seconds` and `_refusals_total{kind}`.
8. **On the primary, add `authority_replica`** to `authority.json`
   ([primary.example.json](../runtime/authority/primary.example.json)): the
   standby's address, this host's certificate and key, the standby's
   certificate, and `degraded_after` (`30s` by default, from `5s` to `10m`).
   Add the standby's address to the unit's `IPAddressAllow=` in a drop-in.
   Start the service. Check `agentcapsule_authority_replication_enabled 1`,
   and that `_acknowledged_sequence` follows `_committed_sequence`.

To **rebuild** the replica (a new standby, a lost disk): stop the authority
service, take a new snapshot with the same recipient, create the replica in
a new directory, start both. The snapshot keeps the epoch. A snapshot with another
recipient is refused: changing the unlock key is a later step.

### Secrets to keep off the hosts

Keep these in a safe off both hosts, with the backup passphrases. The
failover needs each of them, and no host can give them back:
- **the unlock key** (step 3). Without it, the replica's keys and secret do
  not open, and every agent's memory is lost with the primary. With it and a
  copy of the replica, anyone can open them: keep it like the backup
  passphrases;
- the API's receipt key and transit keys ([Prepare](#prepare)). Keep a
  retired transit key 4 weeks after it sealed its last content: an older
  database backup still needs it ([rotation](api/README.md#private-instructions));
- pgBackRest's cipher passphrases and the archive shipper's
  ([Volume archives off the host](#volume-archives-off-the-host-rec-02)).

The link's private keys stay on their hosts: each is replaced by a new
certificate and a new pin.

### Degraded mode

When the standby does not answer for `degraded_after` (30 seconds by
default, [worker.md](worker.md#degraded-mode)), the authority service enters
degraded mode, as ADR 005 (question 2) decides:

- **What continues**, without the standby: deliveries (their outcome
  records, reruns included), boots (fence revisions), the start of a
  revocation, the creation of a new day's receipt key
  ([below](#the-daily-receipt-keys)), and reads. These writes are on the
  primary only until the standby returns.
- **What waits** for the standby: creating an agent (registration, new
  volume key), deleting one (seal, key destruction), restoring one
  (reservation, declared losses, activation), the completion of a
  revocation, and the destruction of an old receipt key. Each attempt fails
  at its deadline, and its job retries.

**What the operator sees.** `AgentCapsuleAuthorityDegraded` (critical)
after a minute in degraded mode;
`agentcapsule_authority_replication_degraded_since_timestamp_seconds` gives
its start, and `_lag_records` how many writes the standby lacks.
`AgentCapsuleAuthorityOperationsRefused` (warning) when an operation gave up
waiting: users then see agent creation, deletion or restores fail. The
worker's job events report those retries with the reason `error`. The API's
readiness probe reports `"authority": "degraded"`, and stays ready.

**What to do.** Bring the standby, or the link, back: check
`agentcapsule-authority serve` on the standby
([Install the replica](#install-the-replica), step 7) and the network
between the hosts. The authority service resends the degraded writes first,
then leaves degraded mode by itself; the alert clears. Nothing is to be
replayed by hand. If the standby is lost for good, build a new replica
([Install the replica](#install-the-replica), "To rebuild"): the snapshot
needs the service stopped, which ends degraded mode too.

**Revocations of access** continue too: a member removed, a token revoked
takes effect at once on the primary. The API confirms a bearer token's
revocation at once, and reports a standing grant's (a member, an
assignment, a team, ...) as `pending` until the standby holds its record
([api/README.md](api/README.md#revocations-pending-and-confirmed)). In the
first `degraded_after` of an outage, before degraded mode begins,
revocations answer 503 `authority_unavailable`: try again. They do so for
the whole outage when a write that waits for the standby (an agent's
creation or deletion) was committed on the primary just as the standby went
away: nothing runs behind such a write until the standby holds it (ADR 006,
wave 5, Not done).

**If the primary is lost during degraded mode**, the outcomes recorded since
its start exist nowhere else. The standby cannot know whether degraded mode
ran: by definition it did not hear from the primary. It knows its **last
contact**, the last request of the primary it answered: the replica writes
that time on disk before it answers, and the primary reaches it every sixth
of `degraded_after` (5 seconds by default) even when nothing is written. No
degraded period can begin less than `degraded_after` after the last
contact. So the promotion compares the two
([Promote the replica](#promote-the-replica), step 5): when the last contact
is older than `degraded_after` at the failover, it assumes a degraded period
ran (ADR 005, item 14). It then revokes every bearer token issued before the
failover, moves every delegation trust's `minimum_iat` to the failover, and
the failover announces the window from the last contact to the failover. A
revocation started in that period was never confirmed, since its completion
waited. An access revocation still pending then must be made again: the
announcement lists that window.

An idle primary also learns at once, at its next heartbeat, that its standby
went away: it enters degraded mode after `degraded_after` without an
operation, and `AgentCapsuleAuthorityDegraded` fires.

#### Pending revocations

`agentcapsule_api_access_revocations_pending` counts the revocations the
API reports as `pending`, and
`agentcapsule_api_access_revocation_oldest_pending_seconds` gives how long
the oldest has waited ([observability.md](observability.md)). In degraded
mode they grow; once the standby catches up, the API confirms them within
seconds and both fall to 0. Pending revocations long after degraded mode
ended mean that the standby does not take their records: a standby of an
older release, which refuses them (see the upgrade above). Each one took
effect on the primary already; nothing is to be revoked again while the
primary lives. `GET /v1/access-revocations/{id}` gives one revocation's
state.

**Do not restart the authority service to clear it.** A service that
restarts cannot tell a standby that is down from one that was promoted
(ADR 005, finding 2): it runs no authority operation at all, reads and
deliveries included, until it reaches the standby again. Meanwhile the API's
readiness probe reports `"authority": "waiting"`. The service tries to reach
the standby as soon as it starts, without waiting for an operation.
`AgentCapsuleAuthorityReplicationStopped` (critical) fires after 5 minutes
of such failures. It also fires when the replica refuses the service, after
a promotion for instance. Restarting the worker is harmless: degraded mode
belongs to the service, and goes on.

### The daily receipt keys

The API encrypts each idempotency receipt, the secrets of the tokens it
issues included, with the key of its day, UTC
([api/README.md](api/README.md#the-daily-receipt-keys)). The authority
service keeps these keys in the key authority, as it keeps volume keys:
each reaches the standby wrapped to the unlock key, a snapshot carries
them, and the promotion installs them. The service, every minute:
- creates tomorrow's key a day ahead, while the standby answers;
- creates today's if it is missing, and gives the API yesterday's, today's
  and tomorrow's;
- destroys each day's key at 01:00 UTC two days after its day began: 24
  hours after the last receipt it can have encrypted expired, and an hour
  for the clocks. A database backup then holds no token secret anyone can
  read once that time has passed: at most 49 hours after it was taken.

Nothing is to be done by hand. **In degraded mode**, tomorrow's key waits
for the standby. If the standby is still away when the day comes, the
service creates the day's key on the primary alone, and the API goes on
(ADR 006, answer 4(b)). The destruction of an old key waits for the
standby: the key then lives longer than its two days on the primary,
`agentcapsule_authority_receipt_keys_overdue` counts it, and
`AgentCapsuleReceiptKeyNotDestroyed` (warning) fires after an hour. If the
primary is lost before the standby holds a key created alone, a replay of a
request of that day answers 409 `idempotency_receipt_unreadable` after the
failover: the request took effect, and does not run again. The bearer tokens
issued in that period are revoked at the failover: a key is created on the
primary alone only after `degraded_after` without the standby, so the
promotion finds a last contact older than that, and revokes every bearer
token issued before the failover ([Degraded mode](#degraded-mode)).

`AgentCapsuleReceiptKeyMissing` (critical) fires when the service has held
no usable key of the day for 5 minutes: the API then refuses every request
that takes an `Idempotency-Key`, with 503 `authority_unavailable`. It happens when a day starts
while a restarted service waits for its standby (it creates nothing then),
and tomorrow's key was not created ahead. Bring the standby back, as for
`AgentCapsuleAuthorityReplicationStopped`. `AgentCapsuleNextReceiptKeyMissing`
(warning) fires when tomorrow's key has been missing for an hour: the
standby has been away that long, and the next day's key will be created on
the primary alone if it does not return by midnight UTC.

### Promote the replica

When the primary is lost, the replica on the standby becomes both
authorities: the same identities, under the **next epoch**. This is part of
the [failover](#the-procedure), which gives the order of everything else. On
the standby, as root. Follow this order.

1. **Stop the old primary through the provider**: power it off, or delete
   the machine, and check that the provider reports it stopped. Cutting it
   off the network is not enough. With two hosts, the old primary cannot
   tell an unreachable standby from a promoted one, so nothing else stops it
   ([ADR 005](adr/005-keys-outside-restored-domain.md#findings-for-the-product-owner),
   finding 2). Otherwise, after `degraded_after` without the standby, it
   would enter [degraded mode](#degraded-mode) and keep recording outcomes
   that the promoted side never sees.
2. **Stop the replica's listener**, and keep it stopped:
   `systemctl disable --now` its unit. `serve` also stops by itself once its
   replica is promoted, and refuses to start again (`replica_promoted`).
3. **Fetch the unlock key** from the safe into a file owned by
   `agentcapsule-authority`, mode 0600, for example
   `/var/lib/agentcapsule-authority-replica/unlock.key`.
4. **Prepare the target directories**, empty, owned by
   `agentcapsule-authority`: `install -d -o agentcapsule-authority -g
   agentcapsule-authority -m 0700` on their parent if it is not writable by
   that account. The promotion writes the volume keys in clear into the new
   authorities, which belong to the service's account, as on the primary.
5. **Promote**, into the directories the service will own on this host, as
   `agentcapsule-authority`:
   ```sh
   runuser -u agentcapsule-authority -- agentcapsule-authority promote \
     -replica-root /var/lib/agentcapsule-authority-replica/replica \
     -key-authority-root /var/lib/agentcapsule-key-authority -key-authority-id <keyauth_…> \
     -restore-authority-root /var/lib/agentcapsule-restore-authority -restore-authority-id <restoreauth_…> \
     -unlock-key-file /var/lib/agentcapsule-authority-replica/unlock.key
   ```
   Add `-degraded-after <duration>` if the old primary's
   `authority_replica.degraded_after` was not the default 30 seconds.
   It checks both identities against the replica and that every wrapped
   secret opens, before it writes anything. Then it marks the replica
   promoted: from then on the replica refuses every record. It writes both
   authorities, with the next epoch on disk before their first write, and
   deletes the replica's wrapped copies. It prints:
   ```json
   {"restore_authority_id":"restoreauth_…","key_authority_id":"keyauth_…","epoch":2,"previous_epoch":1,"sequence":4182,
    "announcement":{"failover":"2026-11-16T10:12:40.512Z","last_contact":"2026-11-16T10:02:03.120Z","degraded":true,
    "window":{"from":"2026-11-16T10:02:03.120Z","to":"2026-11-16T10:12:40.512Z"},"blanket_revocation_id":"arv_…"}}
   ```
   `epoch` is the new primary's. `sequence` is the last record the replica
   applied: every write the old primary acknowledged is at or before it.
   `announcement` is what the failover announces
   ([Degraded mode](#degraded-mode)). `last_contact` is the replica's last
   contact with the old primary; absent when the old primary never reached
   it. When it is older than `degraded_after` at the failover, `degraded` is
   true: a degraded period may have run. The promoted authorities then hold
   the **blanket revocation** (`blanket_revocation_id`): every bearer token
   issued before `failover` (API tokens, service tokens, platform
   credentials) is revoked, and every delegated token too, by moving each
   delegation trust's `minimum_iat` past `failover`. The reconciliation
   writes it into the database ([the procedure](#the-procedure), step 7).
   `window` is the period to announce. After a disaster the promotion runs
   minutes after the last contact: expect `degraded` to be true, unless the
   standby heard from the primary less than `degraded_after` before you
   promote.
   Run the command again after any failure, **before starting the
   service in the primary role**:
   it completes an interrupted promotion, or prints the same result. Until it
   succeeds, the replica's directory still holds wrapped copies of the keys.
   A key that a worker destroyed meanwhile is not published again. Its
   errors:
   - `unlock_key_file_must_be_private`: the file must be a regular file of
     mode 0600, owned by `agentcapsule-authority`;
   - `unlock_key_does_not_open_replica`: another unlock key. Nothing was
     written;
   - `replica_identity_mismatch`: these identities are not the replica's;
   - `replica_unavailable`: the directory is missing, or not owned by
     `agentcapsule-authority`;
   - `old_primary_still_replicating`: a record reached the replica during
     the promotion. The old primary still runs: go back to step 1;
   - `promoted_authority_conflict`: a target directory holds other
     authorities;
   - `authority_in_use`: another process holds a directory: the replica's
     service still runs (step 2), or another command. Nothing was written.

   Then delete the key file: `shred -u` it.
6. **Switch the service to the primary role** and start it: write
   `/etc/agentcapsule/authority.json` from
   [primary.example.json](../runtime/authority/primary.example.json), with
   the promoted directories and the same identities, **without
   `authority_replica`**, then `systemctl enable --now agentcapsule-authority`.
   The authorities run alone: no standby exists, so nothing can set them
   back, and every write proceeds, seals, new keys and key destruction
   included. A fence receipt carries the epoch that signed it: nothing the
   old primary signed binds here, and every boot and restore scans under the
   new epoch. Until step 7, losing this host loses both authorities. With
   `authority_replica`, the service refuses to start
   (`authority_replica_not_armed`) until step 7 arms the authorities. After a
   restart, the service delays the first reservations and key destructions
   by `max_key_hold`. The daily receipt keys came with the promotion: a
   receipt the promoted database holds is replayed as before, except one
   whose key the old primary created alone in degraded mode
   ([The daily receipt keys](#the-daily-receipt-keys)). The service goes on
   creating and destroying them. Once the database runs here, reconcile it
   with the promoted authorities, then start the API with the same
   identities; then restore the lost host's agents and start the worker
   ([the procedure](#the-procedure), steps 7, 8, 13 and 14).
7. **Seed a new standby** as soon as possible: a new host, or the old one
   once **wiped**. The old host's authority directories hold the old epoch,
   and keys destroyed since the failover: delete them before the host serves
   again, and never start its worker or its replica on them. Then
   [install the replica](#install-the-replica) with this host as the
   primary, from step 1:
   - a **new unlock key** (step 3 there): the old one was on this host. The
     promoted authorities hold no recipient, so the snapshot takes the new
     one;
   - new certificates for both sides (step 4 there): this host now takes
     the `primary` role;
   - the authority service stops for the snapshot (step 1 there), as for
     the first one, then restarts with `authority_replica`.

   The snapshot keeps the new epoch. The new standby refuses the old
   primary's records (`older_epoch`), and the pins refuse its certificate.

### Reconcile the database

The promoted database is older than the promoted authorities by its loss
window: a member removed, a token revoked, an agent deleted or restored in
the last minutes before the disaster is in the authorities and not in the
database. `agentcapsule-admin reconcile` brings the database up to the
authorities ([ADR 006](adr/006-authority-service.md), wave 7). The API
refuses to start until it has run for the authorities' epoch
(`authority_not_reconciled`), and its readiness probe answers 503
`authority_not_reconciled`. Run it as the API's account, with the API's
database and its three authority flags:

```sh
runuser -u <the API's account> -- env AGENTCAPSULE_DATABASE_URL=<the API's> agentcapsule-admin reconcile \
  -authority-socket /run/agentcapsule-authority/api.sock \
  -restore-authority-id <restoreauth_…> -key-authority-id <keyauth_…>
```

It:
1. writes into the authorities each access revocation the database holds
   and they lack, and each revocation subject (`agent/…`, `request/…`,
   `event/…`): the WAL shipped them, the old primary's authorities lost
   them;
2. replays into the database each access revocation record it lacks, with
   its effect, in the order they were recorded. A record the database holds
   is not replayed: its row committed with the revocation, so a grant made
   after it is never undone. A rotated LLM provider whose new credential the
   database lost is disabled: its administrator creates it again. A
   rotated delegation trust whose new keys it lost is revoked: run
   `configure-delegation -action rotate` again;
3. copies the authorities' revocation subjects into
   `revocation_catalogue`;
4. resumes the deletion of each agent whose store the authorities sealed,
   or whose `agent/` subject they hold: the deletion was requested before
   the disaster;
5. reports each store whose registration or incarnation differs;
6. records that it reconciled the epoch.

It prints one JSON object:

```json
{"epoch":2,"restore_authority_id":"restoreauth_…",
 "announcement":{"from":"2026-11-16T10:02:03.12Z","to":"2026-11-16T10:12:40.512Z","blanket_revocation_id":"arv_…"},
 "records_replayed":3,"records_kept":0,"subjects_kept":0,"subjects_copied":1,
 "deletions_resumed":["agt_…"],"deletions_not_resumed":[],
 "divergent_stores":[{"store":"agt_…","reason":"incarnation","authority_incarnation":2,"database_incarnation":1}],
 "reconciled_at":"…"}
```

- `announcement` is there when the promotion assumed a degraded period:
  announce its window, and issue new bearer tokens (below).
- `deletions_not_resumed`: an agent the database does not know
  (`unknown_agent`: created and deleted in the window), or in a phase no
  deletion starts from (`phase`). Nothing serves it.
- `divergent_stores`: `incarnation`, the agent was restored in the window,
  and its restore on this host starts again from the authorities' state;
  `not_enrolled`, the agent was created in the window and the database
  lost it; `not_registered`, the database enrolled a store the authorities
  never registered; `volume`, their volumes differ. A restore of the lost
  host's agents ([the procedure](#the-procedure), step 13) refuses such an
  agent (`authority`): it stays out of service. The report is kept in
  `authority_reconciliations`.

Every step can be run again: a later run replays nothing more, and prints
the same report. Run it again after any failure: `authority_unavailable_try_again`
and `reconcile_failed_try_again` mean exactly that; `reconcile_conflict_try_again`
that the authorities changed epoch during the run; `reconcile_record_invalid`
that an authority holds a record this release cannot replay. Errors of the
authority flags are those of the API (`authority_identity_mismatch`, …).

**After a degraded period** (the promotion printed `"degraded": true`),
every bearer token issued before the failover is revoked, the platform
operator's credential included:
- issue a new platform credential: `agentcapsule-admin bootstrap-platform`
  with the same receipt key file and a new token file
  ([bootstrap.md](bootstrap.md#2-create-the-platform-operators-credential));
- organizations issue new service tokens, and their identity providers new
  delegated tokens: those issued before the failover are refused;
- announce the window: outcomes confirmed in it may be lost, and the
  revocations still pending in it must be made again
  ([Pending revocations](#pending-revocations)).

A database restored in place, on the same host, from an older backup is
behind the authorities in the same way, with the same epoch: run
`reconcile` before starting the API again. The API cannot tell such a
restore apart, and does not refuse to start.

## Failover (REC-03)

When the primary host is lost, the standby takes over: first the database,
then the API, then the agents and the address clients use. ADR 004 sets the
objectives: the service answers on the standby within an hour of the
decision, and the database loses at most 15 minutes. The database, the API
and the authorities fail over; the authorities' promotion is tested in Go and
by `verify-failover.py` on one machine, not yet between two hosts. The
standby takes the lost host's agents over and restores each from its newest
archive ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md)): tested with a
fake host and the real stores, and on KVM on 2026-11-17 with a second worker
host on the same machine, not yet between two hosts.

### Who decides

The operator on call decides. A failover loses work, so it is for a disaster
only: the host, its disks or its datacenter lost, or a repair that would take
longer than the RTO. A crash or a reboot loses nothing
([ADR 004](adr/004-recovery-objectives.md)): restart instead.

The usual signals are `AgentCapsuleTargetDown` for the API, a host that does
not answer, or a provider that reports it lost. The standby's own alerts stay
quiet: it is still replaying.

**Write down the time of the decision.** The RTO starts there.

### Prepare

This must be ready before any disaster, so that the failover takes minutes:
- **The standby's PostgreSQL**, replaying the archive
  ([the standby](#the-standby-rec-03)), with its alerts.
- **The same release** of `agentcapsule-api` and `agentcapsule-admin` as on
  the primary, installed on the standby and not started. The same for
  `agentcapsule-worker`, with its configuration for the standby: the same
  `authority` section, and a `host_id`, a runtime root, a provisioning UID
  range and an archive root of its own. Prepare the primary role's
  `authority.json` for the standby's service too: the directories the
  authorities will be promoted into, the same identities, and no
  `authority_replica` ([Promote the replica](#promote-the-replica)).
- **The agents' harness packages.** The standby's worker boots each agent's
  release from its own cache. Copy the primary's harness cache (the
  registry's `cache`, `<runtime root>/releases` by default) to the standby's
  whenever a release is imported: the worker checks each image against its
  digest before it boots it. The platform's built-in harness needs nothing.
  The worker service also fetches again, from its registry and by digest, a
  package that an agent of its host pins and its cache lacks
  ([registry.md](registry.md#refilling-the-cache)); the copy spares the wait
  and a registry outage.
- **Fetching archives**: rclone, the shipper and the standby's
  `rclone.conf` ([Install on the standby](#install-on-the-standby), step 2).
- **The new primary's repository**: the S3 path (`/agentcapsule-2`), a
  credential that can write there, and a new passphrase. Prepare them in
  advance, and keep them off the standby until the promotion.
- **The API's configuration and keys.** The operator copies them at
  installation, and again at each rotation, to a safe off both hosts:
  - the receipt key (`-receipt-key-file`). The installation is bound to it,
    and it also seals the LLM providers' credentials. It no longer encrypts
    new receipts: the daily keys of the authority service do, and the
    promotion brings them ([The daily receipt keys](#the-daily-receipt-keys));
  - the transit keys (`-transit-key`): every one still needed;
  - the TLS certificate and key (`-tls-cert`, `-tls-key`): the API serves
    HTTPS only;
  - the API's flags and environment, except the database's address.

  They must be the same bytes. The API refuses another receipt key
  (`receipt_key_does_not_match_installation`) and other transit keys
  (`transit_keys_do_not_match_installation`).

**This copy is still made by hand.** D-05 is decided
([ADR 005](adr/005-keys-outside-restored-domain.md)). The authorities now
replicate to the standby ([above](#the-authorities-replica-d-05)), but these
installation secrets do not yet: installing them on the standby in advance,
wrapped to the unlock key, is a later step. Until then, the operator copies
these files by hand, out of band.

### The procedure

On the standby host, as root unless said otherwise. Follow this order. Each
step gives its time: measured on one machine where it says so, estimated
otherwise ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md#the-procedure-and-its-time)).
Steps 1 to 10 are the RTO: about 20 to 25 minutes. The agents come back after,
one by one (step 13).

1. **Decide**, and write down the time. Fetch the unlock key and the API's
   keys from the safe. *About 10 minutes, estimated.*
2. **Fence the old primary** (*2 to 5 minutes, estimated*). It must accept no more writes, and reach
   neither store:
   - power it off through the provider, and check that the provider reports
     it stopped. Cutting it off the network is not enough: the old primary
     cannot tell an unreachable standby from a promoted one
     ([Promote the replica](#promote-the-replica), step 1). If it might
     still be running (a network partition), do this first: until it stops,
     clients may still write to it;
   - remove its keys from the standby's SFTP accounts:
     `/etc/ssh/authorized_keys/backup` (pgBackRest) and
     `/etc/ssh/authorized_keys/archives` (the volume archives);
   - revoke its S3 credentials at the provider: pgBackRest's and the archive
     shipper's.
3. **Promote the authorities**: [Promote the replica](#promote-the-replica),
   steps 2 to 6: the promotion, then the authority service in the primary
   role. They need neither the database nor the API. The API needs the
   service: it does not start before it answers. *Under a minute.*
4. **Promote** the standby's PostgreSQL, as `postgres` (*0.5 s measured;
   with step 5, 1 to 2 minutes on real hosts*):
   ```sh
   pg_ctlcluster 18 main promote
   psql -Atc 'SELECT pg_is_in_recovery(), pg_last_xact_replay_timestamp()'
   ```
   `f` means promoted. Write down the time it prints: the loss window starts
   there ([below](#announce-the-databases-loss)).
5. **Give it a repository of its own**: [Promote](#promote), step 3, up to
   `pgbackrest check`. The checkpoint and the full backup are not needed to
   serve: take them right after step 9. Disable
   `agentcapsule-standby-metrics.timer`.
6. **Install the API's configuration and keys** from the safe, with the modes
   the API requires: the directory and the key files readable by the API's
   account only (0700 and 0600). The organizations' identity trusts are in
   PostgreSQL: the promoted database brings them.
   Set `AGENTCAPSULE_DATABASE_URL` to the standby's own PostgreSQL.
7. **Reconcile the database** with the promoted authorities:
   [Reconcile the database](#reconcile-the-database). It replays the access
   revocations the database lost, the blanket revocation of bearer tokens
   when the promotion assumed a degraded period, the revocation subjects
   and the deletions, and reports the stores that differ. Until it has run,
   the API refuses to start (`authority_not_reconciled`). *Under a second
   measured; a minute typed.*
8. **Start the API** with the same flags as on the primary
   ([docs/api](api/README.md)): the same authority socket and identities,
   except `-host-id`: the standby's worker `host_id`, where new agents go. On
   the lost host's, reservations fail with 503. Before it listens, it checks
   that the authority service holds those identities, then the schema, the
   keys, and that step 7 reconciled the authorities' epoch. *Steps 6 to 9:
   0.1 s measured; 1 to 2 minutes typed.*
9. **Check it** on the standby:
   ```sh
   curl -fsS --cacert <the CA of the API's certificate> \
     --resolve api.example.net:8443:127.0.0.1 https://api.example.net:8443/v1/health/ready
   ```
   It answers `{"status":"ready","authority":"standalone"}`: the promoted
   authorities run alone until a new standby is seeded. Then make an
   authenticated read and an authenticated write with the platform
   operator's token. List the organizations
   (`GET /v1/organizations?limit=1`). Create one named for the check
   (`POST /v1/organizations`, with an `Idempotency-Key`). An organization
   cannot be deleted, so disable it after
   (`POST /v1/organizations/{id}/disable`). If tenants sign in with a
   delegated identity, have one read `GET /v1/organizations/current`. After a
   degraded period the platform operator's token was revoked with every
   bearer token issued before the failover: make these checks with the new
   one ([Reconcile the database](#reconcile-the-database)), and tenants with
   tokens issued after the failover.
10. **Move the address** that clients use to the standby: DNS, a floating
   address or the load balancer. The RTO ends when clients reach the API
   there. *About 5 minutes, estimated.*
11. **Announce** the database's loss window
    ([below](#announce-the-databases-loss)), and the window of a degraded
    period when step 7 printed one.
12. **Take the lost host over** (*seconds*), with the `host_id` of each
    worker's configuration:
    ```sh
    agentcapsule-admin take-over-host -lost-host <the lost host's host_id> -host <this host's host_id> \
      -confirm <the lost host's host_id>
    agentcapsule-admin configure-host -host-id <this host's host_id> -storage-mib <the lost host's limit>
    ```
    It is final: the lost host's worker gets no work again, and refuses to
    start. It is an audited operator command: `-dry-run` checks it and
    records nothing. It prints its outcome and the number of agents to
    restore. The second command gives this host the storage that new agents
    may reserve.
13. **Restore the agents**, the maintenance worker stopped:
    ```sh
    /opt/agentcapsule/agentcapsule-worker -config /etc/agentcapsule/worker.json \
      -restore-host <the lost host's host_id> \
      -archive-root /var/lib/agentcapsule-archives \
      -archive-fetch /opt/agentcapsule/agentcapsule-archive-ship.py
    ```
    Each agent of the lost host moves here and is restored from its newest
    archive that a store holds: the standby's copy, or S3's
    ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md)). Its losses after
    that archive are declared, and its lost invocations and agent-to-agent
    events queued again. It prints a line per agent, then the totals. *About
    5 seconds per agent, plus 15 seconds per GiB of volume from the standby's
    disk, estimated; more from S3.* Read the report:
    - `restored`: done.
    - `failed`: run the same command again; it resumes. `archive_unavailable`:
      no store holds a complete, valid copy of any of its archives. `state`
      with an imported harness: copy its package into the cache
      ([Prepare](#prepare)), then run again.
    - `skipped`: nothing here can restore it. `no_archive`: never archived;
      `provisioning`: `agentcapsule-admin abandon-provisioning -agent-id <id>
      -confirm <id>` ends its reservation if it obtained no volume;
      `deleting`: its deletion does not end yet. Each stays out of service
      on the lost host.
14. **Start the maintenance worker** on the promoted authorities, through
    the authority service started at step 3: `systemctl enable --now
    agentcapsule-worker`. The reruns start at once, and so do the deletions
    the reconciliation resumed. *Seconds.*
15. **Protect the new primary**: the checkpoint and the full backup of
    [Promote](#promote), step 3, then its freshness timer, and the archive
    shipper to stores of its own ([Promote](#promote), step 5). Build a new
    standby as soon as possible: its PostgreSQL ([the standby](#the-standby-rec-03))
    and the authorities' replica
    ([Promote the replica](#promote-the-replica), step 7).

What the failover still leaves undone is in
[ADR 020](adr/020-restoring-a-lost-hosts-agents.md#what-stays-undone).

### Announce the database's loss

Work that the platform confirmed in the window may be lost. Announce it to
the callers ([ADR 003](adr/003-restore-rpo.md), option B).
- **The window starts** at the commit time of the last transaction that the
  standby replayed: `pg_last_xact_replay_timestamp()`, read after the
  promotion (it no longer changes then). Every transaction committed until
  then is on the standby. None committed later is. The time comes from the
  primary's clock, kept by NTP.
- **It ends** when the old primary stopped accepting writes. If it went
  down, that is when it stopped answering, from monitoring outside the host.
  If it might have kept running, the window ends when it was fenced.
- **What to say**: work that the platform confirmed between those two times
  may be lost; check it and send it again. The window covers the whole
  platform: the restored database cannot tell which organizations wrote
  during it.
- **What clients see.** An ID acknowledged in the window is unknown: reading
  it gives 404. The same request with the same `Idempotency-Key` creates it
  again, under a new ID, because its receipt was lost with it.
- **How long it can be.** About `archive_timeout` plus the push: up to about
  5 minutes, 6 if the standby's SFTP server was silent, plus up to a minute
  if the primary was idle (the heartbeat commits once a minute). A longer
  window means the standby was behind, and `AgentCapsuleStandbyReplayBehind`
  should have fired.

### Not measured yet

- **The agents**: their restore on another host runs with a fake host and
  the real stores (2.6 s for a 64 MiB volume from S3); with real VMs it needs
  a run under KVM (`TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost`,
  written). So does the worker, with its promoted authorities and its own
  copies of the receipt and transit keys. The time per GiB of volume is an
  estimate.
- **The authorities' promotion between two hosts**: the Go tests run the
  replica, the promotion and the seeding of a new standby on one machine,
  in one or two processes; `verify-failover.py` runs the replica and the
  promotion with the shipped binaries, on one machine.
- **Moving the address** that clients use.
- **The network between real hosts**: the qualification below runs on one
  machine.
- **The human part**: detecting the loss, deciding, and fetching the keys
  from the safe.
- **Fencing the archive shipper**: the qualification fences pgBackRest's
  credential and key only.

### Qualify the failover

`scripts/verify-failover.py` runs this procedure for the database, the
authorities and the API on one machine. Containers and local processes stand
for the hosts. The stores, the primary and the standby are those of
`verify-backups.py`, with `archive_timeout` and `checkpoint_timeout` scaled
down to 30 seconds. It builds the API, the admin tool and
`agentcapsule-authority` from the sources (`--go`), starts both APIs in
production mode over HTTPS with a certificate from a CA of its own, each on
its host's authority service, needs no root, and runs in about 3 minutes:

```sh
python3 scripts/verify-failover.py --pg-bin <postgres-bin-dir> --pgbackrest <pgbackrest> \
  --go <go> [--pg-library-path <dir>] --output <new-dir>
```

The run:
1. **Installs the primary**: the schema, the receipt key and a platform token
   (`bootstrap-platform`), a transit key, the authority service with its
   replica on the standby ([Install the replica](#install-the-replica): both
   authorities, the unlock key, the link's certificates, the snapshot), a
   tenant whose members sign in with a delegated identity, base backups, and
   the API on the authority service. The API's readiness reports the service
   `synchronous`. A directory stands for the operator's safe, where the
   unlock key and the API's keys are kept. The identity trust is in
   PostgreSQL, and reaches the standby with it.
2. **A client writes** through the API: it creates an organization every 0.2
   seconds with the platform token, and records each ID it is given, and
   when.
3. **The standby** is built from its own disk, and replays.
4. **The disaster** comes one and a half `archive_timeout` after a segment
   switch: halfway through a segment. Three seconds before it, in the
   segment that never ships, the tenant's owner removes its second member:
   the standby's replica holds the revocation's record before PostgreSQL
   commits it. The primary's PostgreSQL, authority service and API are
   killed with SIGKILL, with any push in progress. Its data directory, its
   authorities and the WAL that pgBackRest had not pushed are deleted.
5. **The failover**, steps 2 to 9 above, timed from the decision. The old
   primary's S3 credential is revoked in the store's configuration (SeaweedFS
   reloads it on SIGHUP), and its key is removed from the SFTP account. Then
   the authorities' promotion, with the unlock key from the safe, at epoch 2:
   the standby heard from the primary seconds before, so it announces no
   degraded period; the standby's authority service in the primary role; the
   database's promotion, the new repository, the keys installed from the
   safe. The API, started then, refuses (`authority_not_reconciled`), and the
   promoted database still holds the removed member's membership.
   `agentcapsule-admin reconcile` replays the revocation; then the API
   starts on the promoted authorities with the same identities and the
   standby's host ID, readiness (`"authority": "standalone"`), and the first
   authenticated read and write. The read is made twice: with the platform
   token, and with a delegated identity (a JWT signed by the client's Ed25519
   key). The removed member's JWT gets 401.
6. **The takeover**, step 12 above: `take-over-host` on the promoted
   database, a dry run first, then `configure-host` for the standby. Without
   `-confirm` it is refused. Repeated, it prints the same record,
   `unchanged`; another successor is refused (`conflict`), and so is the
   lost host as a successor (`host_lost`). The agents' restore (step 13)
   needs KVM: it is not run here. The KVM campaign runs it, in process,
   without this failover
   (`TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost`, passed
   on 2026-11-17).
7. **The checks.**
   - Every write acknowledged before the window is on the standby, and every
     missing one is inside it. The survivors are a prefix of the writes.
   - A lost ID reads 404, and its retry with the same key creates it again,
     under a new ID.
   - A kept write, retried with the same key, replays its first answer: its
     receipt names the daily receipt key of its day, which the authorities'
     promotion brought ([The daily receipt keys](#the-daily-receipt-keys)).
   - After the fence, the old primary's credential gets 403 from S3, and SFTP
     refuses its key. The standby's credential still reads.
   - A checkpoint, then a full backup into the new repository.
8. **No secret of the run is in the evidence**: the S3 credentials, the
   passphrases, the platform token, the receipt and transit keys, the
   unlock key, the link's private keys, the client's private key and its
   JWTs.

Results of two runs on 2026-11-16, PostgreSQL 18.6 and pgBackRest 2.58,
with the reconciliation (ADR 006 wave 7):

| | Run 1 | Run 2 |
| --- | --- | --- |
| **RTO**: from the decision to the first authenticated write | 1.90 s | 1.74 s |
| fence, promote the authorities, start their service | 0.28, 0.01 and 0.05 s | 0.23, 0.01 and 0.05 s |
| promote the database, own repository | 0.53 and 0.74 s | 0.52 and 0.74 s |
| install the keys; the API refused before the reconciliation; reconcile | 0.00, 0.07 and 0.06 s | 0.00, 0.03 and 0.03 s |
| start the API, ready, read, write | 0.00, 0.06, 0.04 and 0.02 s | 0.00, 0.06, 0.02 and 0.01 s |
| The member removed 3 s before the disaster: in the promoted database, after the reconciliation, its JWT | active, revoked, 401 | active, revoked, 401 |
| The standby's last contact before the failover; degraded period announced | 3.3 s; no | 3.3 s; no |
| Acknowledged writes lost, of those made | 79 of 393 | 77 of 393 |
| **RPO**: age of the oldest lost write at the disaster | 15.77 s | 15.33 s |
| Window to announce: last replayed commit to the disaster | 15.97 s | 15.53 s |
| Full backup into the new repository, after the RTO | 4.49 s | 3.89 s |

The runs before the reconciliation, on the same day, measured an RTO of
2.12 and 1.74 s.

No worker runs, so the authorities hold no agent: their promotion opens no
volume key here, only the daily receipt keys. On a host with agents it unwraps each one, and takes
longer. The runs of 2026-11-13, before the API needed the authority service,
measured an RTO of 1.60 s without the authorities' steps.

**How the numbers scale to production.** The loss follows `archive_timeout`.
Halfway through a 30-second segment, each run lost about half of it: 15 to
15.5 seconds. With 300 seconds, the same moment loses about 2.5 minutes. The
worst case, a disaster just before a segment closes or while it is pushed,
loses `archive_timeout` plus the push: about 5 minutes, 6 with the standby's
SFTP server silent. The RTO measured here does not depend on `archive_timeout`.
It is the commands, the authorities' promotion and the API's start, in
seconds. On real hosts, the push to S3 and pgBackRest's check cross a
network, the operator types the commands, and the steps above that are not
measured add to it.

CI runs this qualification in the `backups` job, with PostgreSQL 16.

## Volume archives (REC-02)

> **After a disaster**, the keys that open these archives and the restore
> authority's catalogue come from the authorities' replica on the standby
> ([D-05](#the-authorities-replica-d-05)), once promoted. Without the
> replica, they are lost with the primary, and so is every agent's memory, not
> just its last 24 hours. The standby restores the lost host's agents from
> the stores' copies ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md),
> [the procedure](#the-procedure), step 13).

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
  agent's only archive. It applies retention after each capture of an agent;
  `agentcapsule-worker -collect-garbage` applies it to every agent at once,
  with the purge of deleted agents' archives
  ([worker.md](worker.md#collecting-garbage-on-demand)).
- **Records.** PostgreSQL records each capture (`volume_archives`): times,
  size, volume, no content. They decide which agents are due, and give the
  metric `agentcapsule_worker_volume_archive_oldest_seconds`.

Every hour, the archives are copied off the host, to the S3-compatible store
and to the standby ([below](#volume-archives-off-the-host-rec-02)).

The selection, the records and retention are tested on PostgreSQL. The KVM test
`TestProductWorkerNightlyVolumeArchives` covers real VMs: a sleeping agent
archived by the running maintenance loop while it delivers to another agent,
then an overdue running agent stopped for its archive and woken by its next
invocation. Each archive is opened with the restore authority (manifest, size,
digest). It passed on KVM on 2026-11-13 (13 of 13 worker tests, guest v19).
Restoring an agent from one of these archives is the next section.

## Restoring an agent from an archive

The worker restores one agent, on its own host, from one of its archives
(REC-02). The agent gets a **new incarnation** of the same volume, and every
outcome the archive lacks is **declared lost**, as
[ADR 003](adr/003-restore-rpo.md#model-revision-option-b) requires. This is the
building block of a disaster restore: on the host that takes a lost host over,
the same restore moves the agent there first
([ADR 020](adr/020-restoring-a-lost-hosts-agents.md),
[the procedure](#the-procedure), step 13).

### Run it

The restore is a mode of the worker, like the archive on demand
([worker.md](worker.md#restoring-an-agent)). It needs product provisioning, the
authority service, and a restore authority catalogue at version 2: run
`agentcapsule-admin init-restore-authority` again on an older one, the service
stopped. Stop the maintenance worker first, so that it releases its listeners,
and restart it after. The authority service keeps running.

```sh
/opt/agentcapsule/agentcapsule-worker \
  -config /etc/agentcapsule/worker.json \
  -restore-agent "$AGENT_ID" \
  -restore-id rst_0123456789abcdef0123456789abcdef \
  -archive-id "$ARCHIVE_ID" \
  -archive-root /var/lib/agentcapsule-archives
```

- **The restore ID** is a new `rst_` identifier with 32 lowercase hexadecimal
  digits. Keep it: the same command with the same ID resumes the restore. The
  ID above is an example.
- **The archive** is one of the agent's archives in the archive root: a nightly
  one (`volume_archives`) or one taken on demand. It must be of the agent's
  current volume and of its size. The worker authenticates it and hashes it
  before it stops anything.
- **The newest archive.** An archive can hold outcomes that another lacks only
  by being newer. So the worker refuses a nightly archive when a newer one of
  the agent is still in the archive root (`restore_failed_newer_archive`).
  Nothing has stopped then. To restore an older one anyway, move the newer one
  out of the root first. An archive taken on demand is not recorded, so it is
  never refused for this reason.
- **The harness** must report the outcomes its store holds (the `outcomes`
  feature of [the control protocol](guest/capsule-control.md)). The Go
  harnesses and the Python SDK of this version do; a harness package built
  before must be rebuilt and imported again. Before it stops anything,
  the worker checks the agent's harness: it asks the running VM, or boots a
  sleeping agent restricted for the check (`restore_failed_unsupported_harness`).

On success, the worker prints a receipt and exits:

```json
{"restore_id":"rst_…","agent_id":"…","archive_id":"arc_…","incarnation":2,"losses":2,"unmatched_losses":0,"reruns_queued":2,"reruns_skipped":0}
```

`reruns_queued` and `reruns_skipped` count the lost invocations and
agent-to-agent events that run again and those that do not
([The losses](#the-losses)).

On failure, it prints `restore_failed_<reason>` on standard error. The reasons
are `archive`, `newer_archive`, `busy`, `authority`, `unsupported_harness`,
`state` and `error`. `authority` is a refusal of the authorities. While they
do not answer (the service restarts, or waits for the standby in degraded
mode), the restore does not fail: it logs `restore_paused` with the reason
`authority_unavailable` or `waits_for_replica`, waits (1 second, then twice as
long each time, up to 30 seconds), and resumes from its last durable step.
`SIGINT` or `SIGTERM` stops it; the same command resumes it later.

### What it does

The steps follow the restore model:
1. **Out of service.** One PostgreSQL transaction records the restore
   (`volume_restores`, migration 0029) and makes the volume `RESTORING` at the
   next incarnation. From then on, the agent gets no ordinary boot, no delivery
   and no archive: its deliveries wait. Every check of the old incarnation
   fails.
2. **Reservation.** The restore authority reserves the same incarnation. The
   old incarnation can no longer record an outcome.
3. **Retirement.** The agent's VMs are removed.
4. **Install.** The archive is written into the agent's volume file, in place:
   the volume keeps its identity and its key. The bytes written must match the
   archive's digest.
5. **Restricted boot.** The image boots at the new incarnation, restricted: no
   delivery, no platform channel. The guest moves the image's marker to the new
   incarnation. The worker fences it with every revocation.
6. **Activation.** The restore authority inspects the outcomes that the image
   holds against those it recorded for the agent. It asks for a repair first.
   Then it declares lost, for the new incarnation, each recorded outcome still
   missing, and only then publishes the activation in PostgreSQL.
7. **Back in service.** The restricted boot is removed. One transaction copies
   the declared losses into PostgreSQL, puts each lost invocation and each
   lost agent-to-agent event back in the queue or skips it, and makes the
   volume `READY` again. The agent wakes on
   its next delivery, at the new incarnation: the first one is usually a
   rerun.

### Crashes

A crash at any step leaves the volume `RESTORING`: nothing serves it. Run the
same command again, with the same restore ID: it resumes from the last step
that committed.
- A crash during the copy redoes the copy from the archive.
- A crash during the restricted boot boots again.
- Once the activation is published, the worker only removes the boot, copies
  the losses, decides the reruns and puts the volume back in service. These
  commit together or not at all.

To use another archive, run the command with a **new** restore ID. It replaces
an unfinished restore that has not activated yet, one incarnation further. An
activated restore cannot be replaced: resume it.

### The losses

The restore authority keeps the declared losses outside the restored domain.
The worker copies the losses of the new incarnation into PostgreSQL
(`volume_restore_losses`), in the transaction that puts the volume back in
service. Each row names the restore, the incarnation, the outcome and the time,
and, when the database still knows it, the delivery whose outcome it is: its
mailbox, and its invocation for an owner instruction. The worker finds them by
computing the outcome ID of each of the agent's mailboxes. A loss without a
mailbox is work that the restored database lost too, within its own window.
The rows are never changed or deleted. The restore authority keeps each
outcome's event ID, the mailbox's, with the outcome (ADR 005 item 8, since
ADR 006 wave 5): a loss names it even when the database lost the mailbox.
The announcement after a failover (wave 7) will list them; the
`volume_restore_losses` rows do not carry it yet.

### The lost invocations

In the same transaction, each lost invocation runs again or is skipped
(`invocation_reruns`, migration 0030). The rules are the defaults of
[ADR 003](adr/003-restore-rpo.md#done-running-the-lost-invocations-again),
which the product owner confirmed on November 16, 2026.
- **A rerun is queued** for an invocation whose delivery PostgreSQL recorded,
  unless its requester canceled it. It goes back to the agent's queue under
  the same mailbox ID, at its place: the lost work runs first. It gets fresh
  attempts and its first delivery window again, counted from the restore. It
  keeps its mandate and that mandate's remaining budget; only the mandate's
  expiry moves with the new deadline. The input's purge waits.
- **The rerun is skipped** when the requester can no longer invoke the agent
  (`requester_revoked`), the agent is being deleted (`agent_unavailable`), or
  the content is no longer stored (`input_purged`, `attachments_purged`). A
  requester revoked after the restore is checked again before the rerun
  reaches the agent: the rerun is then skipped, and nothing is sent.
- **The API.** The invocation's state is `lost` until its rerun ends, with
  `lost_at`, the time of the loss. A skipped one keeps `lost`, and its
  `error_code` gives the reason. The result that the database still holds
  stays readable. The rerun's result replaces it; the invocation then ends
  like any other, `completed` for instance, and keeps `lost_at`. The filter
  `?state=lost` lists the lost invocations.
- **Cancel.** The requester can cancel a lost invocation until its rerun
  reaches the agent. The rerun then never runs.
- **The authority** records the rerun when it is delivered: the outcome's
  status becomes `rerun_confirmed`.

### The lost agent-to-agent events

In the same transaction, each lost request, reply or status that PostgreSQL
recorded as delivered is delivered again to the restored agent, or is skipped
(`peer_redeliveries`, migration 0033). The rules are
[ADR 008](adr/008-redelivering-lost-agent-requests.md)'s, with defaults
pending the product owner.
- **Only the restored agent runs again.** The event goes back to its queue
  under the same mailbox ID, at its place, with fresh attempts. The other
  agent's side was not lost.
- **A request never reopens.** A request event is delivered again only while
  the request is `PROCESSING`, with no closure under way and before its
  deadline. The request goes back to `DELIVERING` and keeps its deadline; its
  sender reads `DELIVERING`, then `PROCESSING` once the recipient has it
  again. A request in a final state (`REPLIED`, `DECLINED`, `EXPIRED`,
  `CANCELED`, `FAILED`) keeps it: its event is skipped with
  `request_closed`.
- **A reply or a status** is delivered again to the sender, with a fresh
  7-day window. Its request keeps its final state. `sender_notified` is false
  until it arrives again.
- **Skipped**, with a reason: `agent_unavailable` (a party is being deleted),
  `requester_revoked` (the person the request was sent for can no longer
  invoke the sender), `content_purged` (the content is no longer kept). An
  active request that is not delivered again fails at once, with the reason
  `lost_in_restore`, and its sender gets the `FAILED` status.
- **Content** waits, without a retention, while its redelivery is queued.
- **Cancel.** The sender's owner cancels a request delivered again like any
  active request (`POST /v1/agent-requests/{id}/cancel`).
- **The API.** `GET /v1/agent-requests/{id}` gives `lost_at`. The sender's
  status read and its A2A task follow the request's state.
- **The authority** records the redelivery when it is delivered: the
  outcome's status becomes `rerun_confirmed`.

### Test a restore

A restore takes the agent out of service. To learn that it would work, without
it, run the restore test (OPR-5, [worker.md](worker.md#testing-a-restore)),
beside the maintenance worker:

```sh
/opt/agentcapsule/agentcapsule-worker \
  -config /etc/agentcapsule/worker.json \
  -test-restore "$AGENT_ID" \
  -archive-root /var/lib/agentcapsule-archives \
  -scratch /var/lib/agentcapsule-restore-tests \
  -archive-fetch /opt/agentcapsule/agentcapsule-archive-ship.py
```

It takes the archive a restore after the host's loss would take: the newest
that PostgreSQL records for the agent's current volume ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md#3-which-archive)).
It checks what a restore checks before it stops anything: the manifest the
restore authority signed, a store that is not sealed, the size and the
SHA-256 digest, the agent's volume and its size. Then it copies the archive
into its own directory under `-scratch` and checks that the key the key
authority lends for the agent opens the copy's key slot: the key and the
archive belong together. It unlocks no payload, mounts nothing and boots
nothing, and changes no row, no authority record, no archive and no volume.
It prints what it checked and removes its copy.

Run it for an agent after its first nightly archive, after a change of the
authorities (a promotion, a migration to the authority service), and from
time to time on a few agents. With `-archive-fetch` and the archive removed
from the archive root by retention, it tests the copy of a store instead:
the standby's, or S3's. What it does not prove: that the guest's file system
inside the volume is sound and that the harness boots and answers. Only a
restore proves those, as the KVM test below does.

### Tests

- PostgreSQL: the incarnation changes only through a restore, the steps of the
  operation, the atomic steps, the mapping of the losses
  (`internal/controlplane/volume_restores_test.go`).
- PostgreSQL: the restore test checks the newest recorded archive, refuses
  another key's container, altered bytes, a missing archive, and changes no
  table, no authority record and no file of the archive or runtime roots
  (`TestRestoreTestChecksTheNewestArchiveAndChangesNothing`, in process and
  through the authority service).
- The coordinator, with a fake host and a real guest protocol over a harness
  database: only the outcomes after the archive declared lost, a stop after
  each step and resumption, a copy cut half way, a failure after the
  declaration, a superseded restore, refusals before anything stops
  (`internal/worker/restore_test.go`).
- PostgreSQL: the reruns of the lost invocations, the API state, `lost_at` and
  the filters, failures injected before and after the decisions, a crash
  during a rerun's delivery, a revoked requester, purged content, and cancel
  (`internal/controlplane/invocation_reruns_test.go`).
- PostgreSQL: the redeliveries of lost agent-to-agent events: a request its
  recipient lost, final requests that do not reopen, a reply and a status the
  sender lost, both parties restored, a revoked requester, purged content, a
  party being deleted, and cancel
  (`internal/controlplane/peer_redeliveries_test.go`).
- KVM: `TestProductWorkerRestoresAgentFromArchive` restores a real agent from
  an archive taken on demand, stopped twice and resumed. It checks the
  installed bytes, the losses and their invocations, the two invocations
  `lost` then run again to `completed` with `lost_at`, the authority's
  `rerun_confirmed`, the agent answering at the new incarnation, and the old
  incarnation refused. It passed on KVM on November 15, 2026, and again on
  November 17 (`scripts/verify-product-guest.py`, guest v26, 26 of 26 worker
  tests).
- KVM: `TestProductWorkerRestoresAgentToAgentExchange` restores two agents
  of an organization after an A2A exchange: the recipient's answered request
  is not delivered again, the sender's invocation runs again and its reply is
  delivered again, and the authority records both reruns. It passed on KVM
  on November 17, 2026.
- On another host ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md#tests)):
  the takeover and the move in PostgreSQL
  (`internal/controlplane/host_takeovers_test.go`); `-restore-host` with the
  fake host (`internal/worker/host_restore_test.go`); a restore from the
  stores' copies (`verify-archive-shipping.py --restore-from-copies`); and,
  on KVM, passed on November 17, 2026 with a second worker host on the same
  machine,
  `TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost`, which needs
  rclone (`AGENTCAPSULE_KVM_RCLONE` or `PATH`) and the `nobody` account. It
  runs the shipper of the sources under test, and rclone from its own copy in
  `/var/tmp`, which `nobody` can reach.

## Volume archives off the host (REC-02)

### Installation and update receipts

The host CLI takes a full PostgreSQL backup in each configured pgBackRest repository. It records each full backup label in `database_backup_sets` after checking the repository status and running `pgbackrest --repo=N verify` against each repository. Noble ships pgBackRest 2.50, whose verifier checks the entire repository, including its WAL. The status field `database_backups_verified` records this check.

For `volume_shipping_verified`, the host archives its smoke-test agent and starts the shipper. It then fetches that archive separately from the S3 and standby crypt remotes. Each fetch has its own empty destination. The worker's restore test reads that copy, authenticates the manifest and binding, checks the digest and volume identity, makes a scratch copy and opens the LUKS container with the agent's current key. The operation records each store's archive ID, byte count and completed checks in `volume_copy_checks`. Budget scratch space for a fetched archive plus one copy of its volume. The two store tests run sequentially.

`off_host_backup_verified` also requires encrypted database repositories using S3 and SFTP, and encrypted volume copies over those protocols. For each pair, the helper resolves the configured transport hosts, rejects an address assigned to the current host, and checks that the two sets of addresses are disjoint. Operators establish physical and administrative independence with their storage providers. A production update requires the off-host checks to pass.

### WSL recovery qualification, 19 November 2026

An unprivileged Ubuntu 24.04 fixture ran two separate services and repositories in a private network namespace on one WSL2 machine. SeaweedFS 4.53 served S3 over TLS. OpenSSH 9.6p1 served SFTP over a public-key-authenticated test listener. The clients were PostgreSQL 16.15, pgBackRest 2.50 and Ubuntu's rclone 1.60.1. Both destinations used loopback addresses, so the off-host separation check stays false. This run qualifies protocol and storage recovery on one kernel. Physical site independence requires a separate exercise.

| Exercise | S3 result | SFTP result |
|---|---|---|
| Repeat shipping of one signed 1 MiB probe archive | First run uploaded one archive. The second uploaded zero. | First run uploaded one archive. The second uploaded zero. |
| Independent PostgreSQL recovery | Restored full set `20261119-235205F`, booted PostgreSQL and read the committed SQL sentinel. | Restored full set `20261119-235209F`, booted PostgreSQL and read the same sentinel. |
| Independent volume recovery | Fetched the signed probe and verified its digest. In the worker test, reopened 67,108,864 LUKS bytes with the agent's current key. | Verified the same digest and reopened 67,108,864 LUKS bytes with the agent's current key. A subsequent fetch rejected a payload corrupted without changing its size. |

The fixture removed the source PostgreSQL cluster and the original probe archive before recovery. During each independent database restore and probe fetch it suspended the other store. The worker also exercised loss of its original host with the newest archive removed from the standby. It recovered incarnation 2 from S3, retained the two earlier outcomes, reported the one expected post-archive loss, and retrieved the older archive from SFTP. The worker scenario used its in-process host fixture. Its separate LUKS check authenticates a real encrypted container from each store. [Worker recovery test](../internal/worker/host_restore_shipped_test.go)

The local receipt is `_evidence/cli-backup-review/summary.json`. Its redacted `qualification.log` records the two backup labels, independent SQL results, archive digest, LUKS sizes and expected loss. The receipt and log contain no repository credentials or volume keys.

### Shipping archives

Every hour, `agentcapsule-archive-ship.timer` copies every complete archive of
the worker's archive root to the two stores of ADR 004: the S3-compatible
object store, and the standby host over SFTP. Either store alone restores an
archive. The files are in [deploy/backup](../deploy/backup) and
[deploy/standby](../deploy/standby). The tool is rclone, qualified in version
1.60.1: Ubuntu 26.04's package `1.60.1+dfsg-4ubuntu3.2`, which depends only on
libc6.

- **What is shipped.** Each archive directory, `arc_` and 32 hexadecimal
  digits, with its `volume.luks` and its `manifest.json`. Never a
  `.pending-*` directory (a capture in progress) nor a `.removed-*` one (a
  removal in progress).
- **Encrypted again, names included.** Each store is an rclone crypt remote
  with its own two passphrases, kept off the host like pgBackRest's. The
  containers are LUKS already, but the manifests are in clear: they name the
  agent and its volume, and give the size, the digest and the harness. With
  crypt, a store sees encrypted names and contents only: no archive ID, no
  agent ID, no manifest. It still sees the number of files, their sizes and
  their times. Crypt also authenticates each block, so a copy altered on a
  store fails on the way back. The cost is a second encryption pass, small
  next to the upload.
- **Complete or not.** The data goes first, the manifest last. An archive is
  complete on a store when its manifest is there, reads as the manifest of
  that archive, and its data has the size the manifest gives. On S3, an
  interrupted upload leaves no object. Over SFTP, rclone 1.60 writes in place:
  an interrupted upload leaves a partial file under its final name, and its
  size or its manifest gives it away. A fetch applies the same rule, then
  checks the SHA-256 digest of the manifest.
- **Never rewritten.** The shipper writes nothing into an archive that is
  complete on a store. Each run lists each store first: a complete archive is
  left alone, an incomplete one is uploaded again, over its partial files. It
  does not rely on rclone's `--immutable`: in 1.60, an SFTP upload cut short
  leaves a partial file that `--immutable` would then refuse at every run.
- **A changed archive.** An archive never changes once captured: only a fault
  or an intrusion changes one. When the host's copy differs from a store's
  complete copy (another size, or written after the upload), the run reports
  it: the metric `agentcapsule_archive_ship_changed_archives`, the alert
  `AgentCapsuleArchiveChanged`, a line in the journal with the archive ID,
  and a failed run. The store keeps the copy it received.
- **Retention by age only.** A store removes an archive once its copy there
  is older than the store's retention: **30 days on S3, 7 days on the
  standby**. Removing an archive from the host removes no copy: the worker's
  retention or a mistake on the host leaves the stores as they are. An archive
  older than a store's retention is not shipped to it. The manifest is removed
  first, so a copy being removed is never complete.
- **Why these numbers.** The 24-hour RPO needs one archive per agent on each
  store, the newest, and the worker takes one a day. Retention removes an
  agent's newest copy only if no newer one arrived for 7 days: long after the
  alerts on the volume archives (26 hours) and on shipping (2 hours). The
  standby needs the latest archives for a failover; 7 days match what the host
  keeps (7 archives per agent). S3 keeps 30 days, about the four weeks of
  database backups it holds: a bad archive can be replaced by an older one,
  and an intrusion found within a month leaves copies from before it. A store
  holds about the agents' volume sizes times its retention in days.
- **The bucket.** A bucket of its own, `agentcapsule-volume-archives`, not a
  path in pgBackRest's. Many S3-compatible providers limit a credential to
  whole buckets only: the shipper's credential then reaches no database backup, and
  pgBackRest's reaches no archive. Versioning, object lock and lifecycle rules
  are set per bucket too. One bucket per host.
- **Protect the S3 copy from the host.** The host's credential can delete in
  the bucket: retention needs it. A host taken over could delete the copies.
  Turn on versioning and object lock (governance mode, 30 days by default),
  and a lifecycle rule that removes noncurrent versions after a day and
  incomplete multipart uploads after a day. A deletion then only hides a
  version, which stays until its lock ends. The standby's copy has no such
  protection yet ([still to do](#still-to-do-adr-004)).
- **When.** Every hour, up to 5 minutes later at random. The worker captures
  agents one by one, all day long, so there is no nightly moment to follow. An
  archive reaches both stores about an hour after its capture at most. An
  agent's newest archive on a store is then at most `every` (24 hours) plus
  that hour old. To hold 24 hours strictly on the stores, set the worker's
  `every` to `23h`.
- **Who.** The archive root belongs to root, mode 0700, and stays so: the
  worker refuses any other mode. The service runs the script as root, in a
  file system that is read-only for it, except its state directory and
  node_exporter's. The script opens the archives' files read-only. rclone,
  which talks to the stores, runs as `agentcapsule-ship` and receives each
  file on its standard input: it can open no file of the archive root, nor any
  other file of root. Its configuration, with the stores' secrets, is readable
  by `agentcapsule-ship` and writable by root only. Rejected: a group or an
  ACL on the archive root (it would no longer be 0700), and
  `CAP_DAC_READ_SEARCH` for rclone (it could then read every file of the host).

### Freshness of the copies

Each run writes, per store (`s3`, `standby`), for node_exporter
([observability.md](observability.md)):
- the time of the last successful ship: the store then held every complete
  archive the host had, within its retention;
- the number of such archives the store lacks after the run;
- the number of archives that changed on the host after their upload;
- whether the store could be listed.

A store that cannot be listed has no counts in the file: its own alert fires
instead. The alerts fire when:
- a store has lacked some archives for 2 hours: two missed runs. 24 hours
  plus 2, the bound of `AgentCapsuleVolumeArchiveStale` on the host;
- a store could not be listed at two runs in a row (90 minutes);
- an archive changed on the host after its upload (critical);
- the shipper has not run for 3 hours, or never ran.

The first run uploads every archive: until it ends, the 2-hour alert may fire.

### Install on the host

1. **rclone**: `apt install rclone`.
2. **The bucket.** Create `agentcapsule-volume-archives` with versioning,
   object lock and the lifecycle rule above. Create two credentials limited to
   it:
   - for the host: list, read, write and delete objects, and set an object's
     ACL (`s3:PutObjectAcl`). rclone 1.60 sends `x-amz-acl: private` with
     every upload, and cannot leave it out;
   - for the standby: list and read only.
3. **The standby's SFTP user**: [below](#install-on-the-standby), step 1.
4. **The user.** Install
   [agentcapsule-archive-ship.sysusers](../deploy/backup/agentcapsule-archive-ship.sysusers)
   as `/usr/lib/sysusers.d/agentcapsule-ship.conf`, then run `systemd-sysusers`.
5. **Configuration and secrets.**
   ```sh
   install -d -o root -g agentcapsule-ship -m 0750 /etc/agentcapsule-archive-ship
   ssh-keygen -t ed25519 -N "" -f /etc/agentcapsule-archive-ship/ssh_ed25519
   chgrp agentcapsule-ship /etc/agentcapsule-archive-ship/ssh_ed25519
   chmod 0640 /etc/agentcapsule-archive-ship/ssh_ed25519
   ssh-keyscan standby.example.net > /etc/agentcapsule-archive-ship/known_hosts
   ```
   Keep every host key of the standby in `known_hosts`, and check their
   fingerprints: rclone 1.60's SSH client prefers the RSA key, and refuses
   the server if only its ed25519 key is listed.
   Write `/etc/agentcapsule-archive-ship/rclone.conf` from
   [the example](../deploy/backup/rclone.conf.example) (root:agentcapsule-ship,
   0640). Replace the endpoint, region, credential and standby host. Generate
   four passphrases with `openssl rand -hex 32`: two for each store. **Keep a
   copy of the four off the host**: without them, the copies cannot be read.
   The file takes what `rclone obscure <passphrase>` prints.
6. **The script and the timer.** Copy
   [agentcapsule-archive-ship.py](../deploy/backup/agentcapsule-archive-ship.py)
   to `/opt/agentcapsule/` (root, 0755). Install
   `agentcapsule-archive-ship.service` and its timer in `/etc/systemd/system`,
   then run `systemctl enable --now agentcapsule-archive-ship.timer`.
7. **Check**: `systemctl start agentcapsule-archive-ship.service`. The last
   line of its journal gives, per store, the archives uploaded, pending,
   changed and removed by retention.

### Install on the standby

1. **The SFTP user** `archives`, separate from pgBackRest's `backup`: neither
   key reaches the other's files. The host writes into its `volumes`
   directory, which is `/srv/backup/archives/volumes` on this disk:
   ```sh
   useradd --system --user-group --home-dir /srv/backup/archives --shell /usr/sbin/nologin archives
   install -d -o root -g root -m 0755 /srv/backup/archives
   install -d -o archives -g archives -m 0750 /srv/backup/archives/volumes
   install -m 0644 ssh_ed25519.pub /etc/ssh/authorized_keys/archives   # the host's public key
   ```
   Append [sshd-archives.conf](../deploy/standby/sshd-archives.conf) to
   `/etc/ssh/sshd_config`, then run `sshd -t && systemctl reload ssh`. Its
   umask makes the files 0640 and the directories 0750.
2. **To fetch archives back**, install in advance, as the standby's pgBackRest
   secrets, so that a fetch fits in the RTO:
   - rclone, the `agentcapsule-ship` user (the same sysusers file), and the
     script in `/opt/agentcapsule/`;
   - `usermod -aG archives agentcapsule-ship`: it reads the archives through
     that group, and cannot write them;
   - `/etc/agentcapsule-archive-ship/rclone.conf` from
     [the standby's example](../deploy/standby/rclone.conf.example)
     (root:agentcapsule-ship, 0640): the host's four passphrases, and the
     read-only S3 credential. There, `standby` is this disk and `s3` the
     bucket.

### Fetch an archive back

The worker does this itself: `-restore-host` for every agent of a lost host,
and `-restore-agent … -archive-fetch` for one
([worker.md](worker.md#restoring-a-lost-hosts-agents)). By hand, on the
standby or any host that takes over, as root:
1. **Choose the archive**: the agent's newest in `volume_archives`, in the
   restored database, that a store holds. To list the archives of a store:
   ```sh
   rclone --config /etc/agentcapsule-archive-ship/rclone.conf lsf standby:   # or s3:
   ```
2. **Fetch it** into the worker's archive root:
   ```sh
   python3 -I /opt/agentcapsule/agentcapsule-archive-ship.py --archive-root /var/lib/agentcapsule-archives \
     fetch --store standby --archive arc_<32 hex>
   ```
   With `--store s3`, from the bucket. The script refuses an archive already
   in the root. It copies into a hidden `.pending-` directory, checks that the
   copy is complete (manifest, size, SHA-256 digest), then renames it into the
   root: files 0600 and directories 0700, as the worker writes them.
3. The restore authority authenticates the manifest when the archive is
   opened. The restore installs the volume and declares the loss
   ([Restoring an agent](#restoring-an-agent-from-an-archive)).

### Qualify the shipping

`scripts/verify-archive-shipping.py` runs the shipped script and
configurations with rclone 1.60.1 against an S3 store (SeaweedFS 4.53, over
TLS) and an SFTP server (OpenSSH, with the Match block above), both run with
Docker and pinned by digest, as `verify-backups.py` does. The archives are
captured with the platform's own code and signed by a real restore authority;
random bytes stand for the LUKS container, which needs root. It needs no root:

```sh
python3 scripts/verify-archive-shipping.py --rclone <rclone> --go <go> \
  --pg-bin <postgres-bin-dir> [--pg-library-path <dir>] --output <new-dir>
```

`scripts/fetch-backup-tools.py` gets rclone 1.60.1 the same way as
pgBackRest. CI runs this qualification too.

It checks:
- **The first ship.** The four archives within S3's 30 days reach S3; the
  three within the standby's 7 days reach the standby; one 40 days old reaches
  neither. A 12 MiB archive goes to S3 in parts. `.pending-` and `.removed-`
  directories never leave the host.
- **A second run** uploads nothing: both stores' listings, times included,
  stay the same.
- **Interruptions.**
  - A shipper killed during an upload to S3 leaves no object there.
  - A network cut, the SFTP server paused during an upload, leaves a partial
    data file on the standby's disk (10 MB) and no manifest. A fetch refuses
    that copy, and the next run uploads it again. Back from the cut, sshd
    answered again after 1.4 seconds.
  - A manifest cut short on the standby's disk no longer decrypts. The next
    run uploads it again, without the data.
- **A changed archive.** One archive grown by 5 bytes, another rewritten in
  place with the same size: both are reported changed, on both stores, and no
  store is written.
- **The metrics**, after each run: mode 0644, no leftover file, no archive ID,
  agent ID or secret. With the standby's SFTP server stopped, that store is
  unreadable, without counts, and keeps its last success; S3's values do not
  change.
- **A fetch from each store alone**, the other one stopped, with the
  standby's configuration: 5 archives from S3 and 4 from the standby's disk.
  Each copy is byte-identical, and the restore authority opens it (signed
  manifest, binding, size, digest). The standby's S3 credential can neither
  write nor delete.
- **No clear text.** Neither the S3 API's view (names and objects), nor
  SeaweedFS's data directory, nor the standby's disk holds an archive ID, an
  agent ID, a volume ID, a file name, a manifest field or a marker written in
  the volumes. The host's own archive root holds them all, and a copy sent in
  clear through the same stores is found in all three: the controls that the
  search works. On the standby's disk, files are 0640 and directories 0750.
- **Retention by age.** An archive removed from the host stays on both
  stores. With a retention between the ages of the copies (155 seconds in the
  run), the older copies go, 4 on S3 and 3 on the standby; the newest stays,
  and the host's archive root does not change.
- **The standby's replay**, on a primary and a standby that replays its WAL
  archive (PostgreSQL 18.6), with `archive_timeout` scaled to 10 seconds, the
  heartbeat to 2 and the alert to 30:
  - with the heartbeat, the last replayed transaction was at most 12 seconds
    old, over a minute. The segments archived meanwhile compressed to 678 to
    810 bytes with zstd;
  - without it, the idle primary's standby passed the alert after 59 seconds,
    although nothing was late: the reason for the heartbeat;
  - with archiving cut, it passed the alert after 29 seconds, and was back
    below it 6 seconds after archiving resumed;
  - promoted, it reports that it is not in recovery; stopped, that PostgreSQL
    does not answer, without replay values.
- **The units.** `systemd-analyze verify` (systemd 259), in a throwaway root,
  prints nothing for the six units, and `systemd-sysusers` creates
  `agentcapsule-ship`. `systemd-analyze security` rates the shipper 3.8, the
  heartbeat 2.3 and the standby's metrics 3.1.

The run takes about 7 minutes. It searches its evidence for every secret it
generated, and finds none. Passed on 2026-11-13.

With `--restore-from-copies --native-tools <dir>`, it also restores a lost
host's agent from these stores' copies (`TestRestoreFromShippedCopies`, with
a PostgreSQL of its own and a fake host, [ADR 020](adr/020-restoring-a-lost-hosts-agents.md)):
the agent's two archives shipped with the host's configuration, the newest
removed from the standby's copy, the host's archive root deleted; the
standby takes the host over and restores the agent with its own
configuration. The newest archive comes from S3, is verified against the
restore authority, installed into a volume created on the new host, and only
the outcome after it is declared lost; the older one comes from the
standby's disk, unchanged. Its archives leave the stores again before the
next stage.

## Deleting an agent: its keys and its archives (ADR 018)

Deleting an agent is final. There is no undo
([ADR 018](adr/018-key-lifecycle-and-archive-deletion.md)). Stopping an agent
is the reversible action.

What goes, and when:

| What | When |
| --- | --- |
| New work; its messages, results and files in the database | In the commit of the deletion request |
| Its VM and boot credentials | Once every agent's store has fenced the deletion: the host stops the VM for good |
| The seal of its store (restore authority) | Then. It never lifts: no restore, no archive and no boot of this store from then on |
| Its volume key | Right after the seal, on the primary and the standby's replica in one write. In degraded mode the deletion waits for the standby |
| Its volume | Right after the key |
| Its archives on this host | Within an hour after the key ([worker.md](worker.md#nightly-encrypted-archives)) |
| Its archives on S3 | 30 days after their upload, by age; a locked version up to a day more |
| Its archives on the standby | 7 days after their upload, by age |
| Its content in the database backups | Their retention: 4 weeks on S3, 2 on the standby |

From the destruction of its key, **none of its archives opens anywhere**: an
archive is the LUKS container, and its only key slot opens with that key. The
copies that wait for their age on the stores are ciphertext that nothing can
read. Until then they still open: `AgentCapsuleDeletionUnfinished` fires when
a deletion has not finished 6 hours after its request
([observability.md](observability.md#alerts)).

A destroyed key comes back only from a copy kept outside the platform. Keep
none:
- **Turn off the provider's disk snapshots and backups** of both hosts. The
  primary keeps the volume keys in clear on its disk, the standby wrapped to
  the unlock key. A provider's copy of either disk would bring back every key
  destroyed since, for the copy's retention.
- **Never back up the authority directories** or the replica's, by any tool.
  The backups of this page never include them.
- **Delete the authority snapshot** on both hosts once the replica is created
  ([Install the replica](#install-the-replica), step 6).
- **Wipe the old primary** after a failover before it serves again
  ([Promote the replica](#promote-the-replica), step 7).
- **Keep the unlock key off both hosts**: with it, a copy of the replica opens.

The platform does not scrub freed disk blocks, nor a guest's memory: these
rules are about copies, not about forensic erasure.

## Still to do (ADR 004)

1. **Lost requests between agents, on KVM.** A restore delivers again the
   agent-to-agent events it lost
   ([above](#the-lost-agent-to-agent-events), ADR 008).
   `TestProductWorkerRestoresAgentToAgentExchange` is written and not yet
   run.
2. **Restoring onto the standby.** Built: the takeover, the fetch from the
   stores, the move and the restore of each agent
   ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md)). Not yet: its KVM
   run, parallel restores, the harness packages imported on the standby, the
   agents still provisioning or being deleted, and what ADR 006 waves 5 to 7
   add ([ADR 020](adr/020-restoring-a-lost-hosts-agents.md#what-stays-undone)).
3. **A failover exercise** that measures the RPO and the RTO of the whole
   platform, on real hosts. The database, the authorities and the API fail
   over on one machine, with their configuration and keys, and the standby
   takes the lost host over ([Qualify the failover](#qualify-the-failover)).
   The agents (KVM), the address clients use, and the network between real
   hosts are not
   measured. The API's keys reach the standby by an operator's copy, a
   stand-in until D-05 is decided.
4. **The standby's copy of the volume archives against the host.** The host's
   SFTP account can delete there: retention needs it. A host taken over could
   delete the standby's copies; object lock protects only S3's. A retention
   run on the standby itself, with an SFTP account that can neither delete
   nor rename (`internal-sftp -P`), would close that gap.
5. **Object lock, with the chosen provider.** Versioning, object lock and the
   lifecycle rules are recommended, not qualified: SeaweedFS stands for the
   provider without them.
6. **PostgreSQL 18 in CI.** CI runs both qualifications (the `backups` job
   of [ci.yml](../.github/workflows/ci.yml)). Its runner is Ubuntu 24.04,
   which ships an older pgBackRest and rclone. So `fetch-backup-tools.py`
   gets Ubuntu 26.04's packages, pgBackRest 2.58 and rclone 1.60.1, and
   checks their SHA-256. They need glibc 2.38 at most, and the runner has
   2.39. PostgreSQL is another matter: Ubuntu 26.04's PostgreSQL 18 needs
   glibc 2.43, so CI uses Ubuntu 24.04's PostgreSQL 16. The qualifications
   with PostgreSQL 18 run on Ubuntu 26.04 only (above). A runner on Ubuntu
   26.04 would close that gap.
