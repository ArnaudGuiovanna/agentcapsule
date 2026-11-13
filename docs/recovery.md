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
worker's authorities returns only once the standby holds it on disk. Volume
keys and the catalogue's signing secret reach the standby only wrapped to the
operator's **unlock key**, which stays off both hosts.

Without the replica, the authorities are standalone: losing the primary loses
every volume key, so every archive. Install the replica before any agent
holds data that matters.

`agentcapsule-authority` does every step. Build it like the worker, on the
same release, and install it on both hosts.

### Install the replica

1. **On the primary, stop the worker** (and any archive or restore command).
   The first snapshot must not run beside a worker that writes without the
   replica.
2. **Upgrade the catalogue** to version 3, which adds the log: run
   `agentcapsule-admin init-restore-authority` again, with the same flags as
   at installation. It keeps the identity.
3. **Create the unlock key**, on a workstation if possible, or on the
   primary, then move it off:
   ```sh
   agentcapsule-authority unlock-key -out /root/agentcapsule-unlock.key
   ```
   It prints the recipient, the public part. Copy the key file to the safe
   that holds the backup passphrases ([below](#secrets-to-keep-off-the-hosts)),
   then delete it from the host (`shred -u`). Neither host keeps it.
4. **Create the link's certificates**, one per host. Each names the two
   authorities; use the identities pinned in the worker's configuration:
   ```sh
   agentcapsule-authority certificate -role primary \
     -restore-authority-id <restoreauth_…> -key-authority-id <keyauth_…> \
     -certificate /etc/agentcapsule/authority-primary.crt -key /etc/agentcapsule/authority-primary.key
   ```
   Run it on the standby with `-role replica` and `authority-replica.*`. Once
   the replica's account exists (step 6), give it its key file
   (`chown agentcapsule-authority`, mode 0600). Copy each `.crt` file, never a
   `.key`, to the other host. The certificates are pinned: replacing one means
   copying it again.
5. **Take the snapshot** on the primary, outside both authorities:
   ```sh
   agentcapsule-authority snapshot \
     -key-authority-root <key_authority.root> -key-authority-id <keyauth_…> \
     -restore-authority-root <restore_authority.root> -restore-authority-id <restoreauth_…> \
     -recipient <recipient> -out /root/authority-snapshot.sqlite
   ```
   This **arms** both authorities: from now on the worker refuses to start
   without `authority_replica`. The file holds the catalogue, the secret and
   every live key wrapped to the unlock key, and no secret in clear. It still
   lists agents, stores and revocations: copy it over SSH, then delete it.
6. **On the standby, create the replica** as a dedicated account, for example
   `agentcapsule-authority`, which owns only its directory:
   ```sh
   useradd --system --user-group --home-dir /var/lib/agentcapsule-authority-replica --shell /usr/sbin/nologin agentcapsule-authority
   install -d -o agentcapsule-authority -g agentcapsule-authority -m 0700 /var/lib/agentcapsule-authority-replica
   runuser -u agentcapsule-authority -- agentcapsule-authority init-replica \
     -root /var/lib/agentcapsule-authority-replica/replica -snapshot /tmp/authority-snapshot.sqlite
   ```
7. **Configure and start the replica.** `/etc/agentcapsule/authority-replica.json`,
   owned by root, not writable by others:
   ```json
   {
     "version": 1,
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
   Run `agentcapsule-authority serve -config /etc/agentcapsule/authority-replica.json`
   under systemd, as `agentcapsule-authority`, with `Restart=always`. Let only
   the primary's address reach the port. It logs JSON events
   (`replica_started`, `replica_refused` with its kind, `replica_stopped`) and
   serves `agentcapsule_authority_replica_applied_sequence`, `_epoch`,
   `_last_apply_timestamp_seconds` and `_refusals_total{kind}`.
8. **On the primary, add `authority_replica`** to the worker's configuration
   ([worker.md](worker.md#replica-of-the-authorities)), then start the
   worker. Check `agentcapsule_authority_replication_enabled 1`, and that
   `_acknowledged_sequence` follows `_committed_sequence`.

To **rebuild** the replica (a new standby, a lost disk): stop the worker,
take a new snapshot with the same recipient, create the replica in a new
directory, start both. The snapshot keeps the epoch. A snapshot with another
recipient is refused: changing the unlock key is a later step.

### Secrets to keep off the hosts

Keep these in a safe off both hosts, with the backup passphrases. The
failover needs each of them, and no host can give them back:
- **the unlock key** (step 3). Without it, the replica's keys and secret do
  not open, and every agent's memory is lost with the primary. With it and a
  copy of the replica, anyone can open them: keep it like the backup
  passphrases;
- the API's receipt key and transit keys ([Prepare](#prepare));
- pgBackRest's cipher passphrases and the archive shipper's
  ([Volume archives off the host](#volume-archives-off-the-host-rec-02)).

The link's private keys stay on their hosts: each is replaced by a new
certificate and a new pin.

### What is not built yet

- **Promotion.** The internal API exists (`restoreauthority.Promote`: it
  checks the unlock key, refuses every later record, writes both authorities
  with their identities and the next epoch, then deletes the wrapped copies).
  The `agentcapsule-admin` command and the failover steps come later.
- **Degraded mode.** While the standby does not answer, the authorities'
  writes wait: deliveries, boots, provisioning and removals retry until it
  returns. ADR 005 (question 2) lets some continue after 30 seconds; that is
  a later step, with its alerts.
- **Revocations of access** in the authority, and their replay into
  PostgreSQL after a promotion.
- **The daily receipt key** of ADR 005's decision.
- **An authority service** owning both directories, serving the worker and
  the API over a local socket. Today each worker process opens the
  authorities and holds its own link.

## Failover (REC-03)

When the primary host is lost, the standby takes over: first the database,
then the API, then the agents and the address clients use. ADR 004 sets the
objectives: the service answers on the standby within an hour of the
decision, and the database loses at most 15 minutes. Today the database and
the API can fail over. The agents cannot yet: restoring them on the standby
needs D-05.

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
  the primary, installed on the standby and not started.
- **The new primary's repository**: the S3 path (`/agentcapsule-2`), a
  credential that can write there, and a new passphrase. Prepare them in
  advance, and keep them off the standby until the promotion.
- **The API's configuration and keys.** The operator copies them at
  installation, and again at each rotation, to a safe off both hosts:
  - the receipt key (`-receipt-key-file`). The installation is bound to it,
    and it also seals the LLM providers' credentials;
  - the transit keys (`-transit-key`): every one still needed;
  - the delegated-identity trust file (`-delegated-identity-file`). It
    holds public keys only;
  - the TLS certificate and key, when the API listens beyond loopback;
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

On the standby host, as root unless said otherwise. Follow this order.

1. **Decide**, and write down the time.
2. **Fence the old primary.** It must accept no more writes, and reach
   neither store:
   - stop it, or cut it off from its clients and the network, if it can
     still be reached. If it might still be running (a network partition), do
     this first: until it stops, clients may still write to it;
   - remove its keys from the standby's SFTP accounts:
     `/etc/ssh/authorized_keys/backup` (pgBackRest) and
     `/etc/ssh/authorized_keys/archives` (the volume archives);
   - revoke its S3 credentials at the provider: pgBackRest's and the archive
     shipper's.
3. **Promote** the standby's PostgreSQL, as `postgres`:
   ```sh
   pg_ctlcluster 18 main promote
   psql -Atc 'SELECT pg_is_in_recovery(), pg_last_xact_replay_timestamp()'
   ```
   `f` means promoted. Write down the time it prints: the loss window starts
   there ([below](#announce-the-databases-loss)).
4. **Give it a repository of its own**: [Promote](#promote), step 3, up to
   `pgbackrest check`. The checkpoint and the full backup are not needed to
   serve: take them right after step 7. Disable
   `agentcapsule-standby-metrics.timer`.
5. **Install the API's configuration and keys** from the safe, with the modes
   the API requires: the directory and the key files readable by the API's
   account only (0700 and 0600), the trust file writable by its owner only.
   Set `AGENTCAPSULE_DATABASE_URL` to the standby's own PostgreSQL.
6. **Start the API** with the same flags as on the primary
   ([docs/api](api/README.md)). It checks the schema and the keys before it
   listens.
7. **Check it** on the standby:
   ```sh
   curl -fsS http://127.0.0.1:8080/v1/health/ready
   ```
   Then make an authenticated read and an authenticated write with the
   platform operator's token. List the organizations
   (`GET /v1/organizations?limit=1`). Create one named for the check
   (`POST /v1/organizations`, with an `Idempotency-Key`). An organization
   cannot be deleted, so disable it after
   (`POST /v1/organizations/{id}/disable`). If tenants sign in with a
   delegated identity, have one read `GET /v1/organizations/current`.
8. **Move the address** that clients use to the standby: DNS, a floating
   address or the load balancer. The RTO ends when clients reach the API
   there.
9. **Announce** the database's loss window
   ([below](#announce-the-databases-loss)).
10. **Protect the new primary**: the checkpoint and the full backup of
    [Promote](#promote), step 3, then its freshness timer. Build a new
    standby as soon as possible.
11. **The agents**: not possible yet. Restoring them on the standby needs
    D-05, and a run under KVM
    ([Restoring an agent](#restoring-an-agent-from-an-archive)).

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

- **The agents**: restoring them on the standby needs D-05, and a run under
  KVM. So does the worker, with its authorities and its own copies of the
  receipt and transit keys.
- **Moving the address** that clients use.
- **The network between real hosts**: the qualification below runs on one
  machine.
- **The human part**: detecting the loss, deciding, and fetching the keys
  from the safe.
- **Fencing the archive shipper**: the qualification fences pgBackRest's
  credential and key only.

### Qualify the failover

`scripts/verify-failover.py` runs this procedure for the database and the API
on one machine. Containers and local processes stand for the hosts. The
stores, the primary and the standby are those of `verify-backups.py`, with
`archive_timeout` and `checkpoint_timeout` scaled down to 30 seconds. It
builds the API and the admin tool from the sources (`--go`), needs no root,
and runs in about 2.5 minutes:

```sh
python3 scripts/verify-failover.py --pg-bin <postgres-bin-dir> --pgbackrest <pgbackrest> \
  --go <go> [--pg-library-path <dir>] --output <new-dir>
```

The run:
1. **Installs the primary**: the schema, the receipt key and a platform token
   (`bootstrap-platform`), a transit key, a tenant whose member signs in with
   a delegated identity, base backups, and the API. A directory stands for
   the operator's safe, where the API's keys and trust file are copied.
2. **A client writes** through the API: it creates an organization every 0.2
   seconds with the platform token, and records each ID it is given, and
   when.
3. **The standby** is built from its own disk, and replays.
4. **The disaster** comes one and a half `archive_timeout` after a segment
   switch: halfway through a segment. The primary's PostgreSQL and API are
   killed with SIGKILL, with any push in progress. Its data directory and the
   WAL that pgBackRest had not pushed are deleted.
5. **The failover**, steps 2 to 7 above, timed from the decision. The old
   primary's S3 credential is revoked in the store's configuration (SeaweedFS
   reloads it on SIGHUP), and its key is removed from the SFTP account. Then
   the promotion, the new repository, the keys installed from the safe, the
   API started, readiness, and the first authenticated read and write. The
   read is made twice: with the platform token, and with a delegated identity
   (a JWT signed by the client's Ed25519 key).
6. **The checks.**
   - Every write acknowledged before the window is on the standby, and every
     missing one is inside it. The survivors are a prefix of the writes.
   - A lost ID reads 404, and its retry with the same key creates it again,
     under a new ID.
   - After the fence, the old primary's credential gets 403 from S3, and SFTP
     refuses its key. The standby's credential still reads.
   - A checkpoint, then a full backup into the new repository.
7. **No secret of the run is in the evidence**: the S3 credentials, the
   passphrases, the platform token, the receipt and transit keys, the
   client's private key and its JWTs.

Results of two runs on 2026-11-13, PostgreSQL 18.6 and pgBackRest 2.58:

| | Run 1 | Run 2 |
| --- | --- | --- |
| **RTO**: from the decision to the first authenticated write | 1.60 s | 1.60 s |
| fence, promote, own repository | 0.23, 0.53 and 0.74 s | 0.23, 0.53 and 0.74 s |
| install the keys, start the API, ready, read, write | 0.00, 0.00, 0.05, 0.02 and 0.01 s | the same |
| Acknowledged writes lost, of those made | 78 of 393 | 79 of 394 |
| **RPO**: age of the oldest lost write at the disaster | 15.53 s | 15.78 s |
| Window to announce: last replayed commit to the disaster | 15.73 s | 15.98 s |
| Full backup into the new repository, after the RTO | 3.64 s | 4.04 s |

**How the numbers scale to production.** The loss follows `archive_timeout`.
Halfway through a 30-second segment, each run lost about half of it: 15.5 to
16 seconds. With 300 seconds, the same moment loses about 2.5 minutes. The
worst case, a disaster just before a segment closes or while it is pushed,
loses `archive_timeout` plus the push: about 5 minutes, 6 with the standby's
SFTP server silent. The RTO measured here does not depend on `archive_timeout`.
It is the commands and the API's start, in seconds. On real hosts, the push
to S3 and pgBackRest's check cross a network, the operator types the
commands, and the steps above that are not measured add to it.

CI runs this qualification in the `backups` job, with PostgreSQL 16.

## Volume archives (REC-02)

> **Not yet true after a disaster.** The keys that open these archives stay
> in the key authority, on the primary host: nothing copies them yet. If the
> host is lost, the archives on S3 and on the standby cannot be opened, and
> the agents' memory is lost, not just its last 24 hours. The restore
> authority's catalogue is lost too. This waits for D-05
> ([ADR 005](adr/005-keys-outside-restored-domain.md)). A restore on the same
> host, from a local archive, is not affected.

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

Every hour, the archives are copied off the host, to the S3-compatible store
and to the standby ([below](#volume-archives-off-the-host-rec-02)).

The selection, the records and retention are tested on PostgreSQL. The KVM test
`TestProductWorkerNightlyVolumeArchives` covers real VMs: a sleeping agent
archived by the running maintenance loop while it delivers to another agent,
then an overdue running agent stopped for its archive and woken by its next
invocation. Each archive is opened with the restore authority (manifest, size,
digest). This test is compiled and remains to be run under KVM. Restoring an
agent from one of these archives is the next section.

## Restoring an agent from an archive

The worker restores one agent, on its own host, from one of its archives
(REC-02). The agent gets a **new incarnation** of the same volume, and every
outcome the archive lacks is **declared lost**, as
[ADR 003](adr/003-restore-rpo.md#model-revision-option-b) requires. This is the
building block of a disaster restore. A restore onto another host needs the
keys, secrets and revocations outside the restored domain
([D-05](adr/005-keys-outside-restored-domain.md)): it is not possible yet.

### Run it

The restore is a mode of the worker, like the archive on demand
([worker.md](worker.md#restoring-an-agent)). It needs product provisioning, both
authorities, and a restore authority catalogue at version 2: run
`agentcapsule-admin init-restore-authority` again on an older one. Stop the
maintenance worker first, so that it releases its listeners, and restart it
after.

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

`reruns_queued` and `reruns_skipped` count the lost invocations that run
again and those that do not ([The losses](#the-losses)).

On failure, it prints `restore_failed_<reason>` on standard error. The reasons
are `archive`, `newer_archive`, `busy`, `authority`, `unsupported_harness`,
`state` and `error`.

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
   the declared losses into PostgreSQL, puts each lost invocation back in the
   queue or skips it, and makes the volume `READY` again. The agent wakes on
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
The rows are never changed or deleted.

### The lost invocations

In the same transaction, each lost invocation runs again or is skipped
(`invocation_reruns`, migration 0030). The rules are the defaults of
[ADR 003](adr/003-restore-rpo.md#done-running-the-lost-invocations-again),
which the product owner has not confirmed yet.
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

Agent-to-agent requests, replies and statuses that a restore lost are
recorded with their mailbox, and are not delivered again.

### Tests

- PostgreSQL: the incarnation changes only through a restore, the steps of the
  operation, the atomic steps, the mapping of the losses
  (`internal/controlplane/volume_restores_test.go`).
- The coordinator, with a fake host and a real guest protocol over a harness
  database: only the outcomes after the archive declared lost, a stop after
  each step and resumption, a copy cut half way, a failure after the
  declaration, a superseded restore, refusals before anything stops
  (`internal/worker/restore_test.go`).
- PostgreSQL: the reruns of the lost invocations, the API state, `lost_at` and
  the filters, failures injected before and after the decisions, a crash
  during a rerun's delivery, a revoked requester, purged content, and cancel
  (`internal/controlplane/invocation_reruns_test.go`).
- KVM: `TestProductWorkerRestoresAgentFromArchive` restores a real agent from
  an archive taken on demand, stopped twice and resumed. It checks the
  installed bytes, the losses and their invocations, the two invocations
  `lost` then run again to `completed` with `lost_at`, the authority's
  `rerun_confirmed`, the agent answering at the new incarnation, and the old
  incarnation refused. It is compiled and remains to be run as root
  (`scripts/verify-product-guest.py`).

## Volume archives off the host (REC-02)

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

On the standby, or any host that takes over, as root:
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
   opened. Installing the volume and declaring the loss is the restore
   coordinator's job, still to do.

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

## Still to do (ADR 004)

1. **Lost requests between agents.** A restore queues the lost invocations
   again and shows them as `lost` (above). The requests and messages between
   agents that it lost stay recorded, without a rerun
   ([ADR 003](adr/003-restore-rpo.md#what-remains)).
2. **Restoring onto the standby.** A fetch of an archive is qualified
   ([above](#fetch-an-archive-back)). Installing it there and restoring the
   agent needs the authorities on the standby: their replica is built
   ([D-05](#the-authorities-replica-d-05)); its promotion command is not.
3. **A failover exercise** that measures the RPO and the RTO of the whole
   platform, on real hosts. The database and the API fail over on one
   machine, with their configuration and keys
   ([Qualify the failover](#qualify-the-failover)). The agents (D-05 and
   KVM), the address clients use, and the network between real hosts are not
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
