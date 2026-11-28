# TREK: 5.1.2 → 5.2.1 and SQLite → PostgreSQL 18

Upstream docs: [Database: Postgres](https://github.com/liketrek/TREK/wiki/Database-Postgres),
[5.2.0 release notes](https://github.com/liketrek/TREK/releases/tag/v5.2.0).

TREK 5.2.0 added PostgreSQL support. `TREK_DB_URL` selects it; without that
variable TREK keeps using `data/travel.db`. A `db:move-to-postgres` command
copies an existing SQLite install into an empty Postgres database, checks the
copy and rolls back if anything fails. It never writes to `travel.db`, so
SQLite stays the way back.

**The move is one-way.** Nothing copies Postgres data back into SQLite. To
return, start TREK on the untouched `travel.db` again; anything written on
Postgres in the meantime is not in it.

## What is in this repo

| File | What it is |
|---|---|
| `apps/utilities/trek/db-pv.yaml` | hostPath PV at `/appdata/trek-db`, pinned to `k3s-worker` |
| `apps/utilities/trek/db-pvc.yaml` | `trek-db-data` claim |
| `apps/utilities/trek/db-init-configmap.yaml` | first-start script creating the non-superuser role `trek` |
| `apps/utilities/trek/db.yaml` | `postgres:18` Deployment + `trek-db` Service |
| `apps/utilities/trek/db-secret.yaml` | **gitignored**, applied by hand: the two database passwords |
| `apps/utilities/trek/secret.yaml` | **gitignored**, applied by hand: holds the commented-out `TREK_DB_URL` |
| `docs/runbooks/trek-move-to-postgres-job.yaml` | the one-shot move Job, applied by hand |

Three design points worth knowing before you start:

* **`postgres:18` mounts its volume at `/var/lib/postgresql`**, not
  `/var/lib/postgresql/data` — images 14 to 17 use the `/data` path and 18
  refuses it. A database stays on the major it was created with, so changing
  the image tag later does not upgrade the data.
* **The Postgres volume is `/appdata/trek-db`, outside `/appdata/trek`.** The
  TREK entrypoint runs `chown -R node /app/data` on every start; a Postgres
  data directory underneath it would be handed to uid 1000 and the postgres
  image (uid 999) would stop reading it.
* **TREK connects as the role `trek`, which is not a superuser.** A backup TREK
  restores is a SQL script run by this role, so a privileged role would let a
  crafted archive run commands in the database container. TREK refuses restores
  and plugin databases (`db:own`) while it is connected as one, and warns at
  startup. The role is created by `db-init-configmap.yaml` on the database's
  **first start only**; it is not created again later.

The move Job lives under `docs/runbooks/` on purpose. The `utilities`
ApplicationSet recurses `apps/utilities/*`, so a Job in the app folder would be
owned by ArgoCD and re-created on every sync.

## Before you start

* ArgoCD syncs `apps/utilities/trek` with `prune: true` and `selfHeal: true`,
  so **stopping TREK has to go through git** — a `kubectl scale` is reverted
  within a few minutes. Patching the Application does not help either, because
  the ApplicationSet controller rewrites it.
* TREK runs on `k3s-worker`, where its hostPath data lives. The trek
  Deployment, `trek-db-pv` and the move Job are all pinned to that node, so
  nothing in this procedure can land on `k3s-cp` and find an empty directory.
* Expect TREK to be down from step 2 until step 5.

---

## Step 1 — upgrade to 5.2.1 on SQLite, and bring up Postgres

The move command refuses a `travel.db` that is not at the migration level of
the image running the command, so 5.2.1 has to start on SQLite once first.

Apply the database passwords by hand:

```bash
kubectl apply -f apps/utilities/trek/db-secret.yaml
```

Then commit the image bump and the Postgres manifests:

```bash
git add apps/utilities/trek .gitignore docs/runbooks && git commit -m "Add Postgres 18 for TREK and upgrade it to 5.2.1" && git push
```

Wait for both pods, then confirm the role was created without superuser rights:

```bash
kubectl -n utilities rollout status deploy/trek-db
kubectl -n utilities rollout status deploy/trek
kubectl -n utilities exec deploy/trek-db -- psql -U postgres -d trek -c \
  "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname='trek'"
```

All three of `rolsuper`, `rolcreatedb` and `rolcreaterole` must be `f`, and the
database and its `public` schema must be owned by `trek`:

```bash
kubectl -n utilities exec deploy/trek-db -- psql -U postgres -d trek -tAc \
  "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='trek'; \
   SELECT nspowner::regrole FROM pg_namespace WHERE nspname='public'"
```

Both lines must read `trek`. If the role is missing, the first start ran without
`TREK_DB_PASSWORD`: the database exists but the role does not, and a restart
will not create it. Delete `/appdata/trek-db` on `k3s-worker` while it is still
empty of TREK data and start again.

Check that TREK migrated `travel.db` and is healthy, and that the log has no
line beginning `[DB] The database lacks`:

```bash
kubectl -n utilities logs deploy/trek | grep -iE 'migrat|\[DB\]|version'
```

**Now take a backup** in TREK under **Admin → Backup** and download it. A
backup taken on SQLite cannot be restored into Postgres, so this is your way
back to 5.2.1-on-SQLite, not a way forward.

## Step 2 — stop TREK

```bash
sed -i '' 's/^  replicas: 1$/  replicas: 0/' apps/utilities/trek/deployment.yaml
git commit -am "Stop TREK for the Postgres move" && git push
```

The SQLite file must not change while it is read. Wait for the pod to go:

```bash
kubectl -n utilities get pods -l app=trek -w
```

## Step 3 — give TREK the connection URL

Uncomment the `TREK_DB_URL` line in `apps/utilities/trek/secret.yaml` and apply
it. TREK is at 0 replicas, so this takes effect only at step 5, and the move
Job reads the URL from this Secret.

```bash
kubectl apply -f apps/utilities/trek/secret.yaml
kubectl -n utilities get secret trek-secrets -o jsonpath='{.data.TREK_DB_URL}' | base64 -d; echo
```

## Step 4 — run the move

```bash
kubectl apply -f docs/runbooks/trek-move-to-postgres-job.yaml
kubectl -n utilities logs -f job/trek-move-to-postgres
```

The Job copies every table, each plugin's data and the id sequences in one
transaction, reads every table back and compares row counts and a checksum
against the SQLite file. Only a copy that matches is committed. It prints the
tables and rows it copied and anything it could not carry over.

Wait for it to succeed before going on:

```bash
kubectl -n utilities wait --for=condition=complete --timeout=30m job/trek-move-to-postgres
```

If it refuses or fails, it writes nothing and leaves the Postgres database
empty, so you can fix the cause and apply it again (delete the Job first). The
log names the table, row and column in every case. The ones to expect:

| The log says | What to do |
|---|---|
| NUL characters (U+0000) in values | Add `--drop-nul` to the Job's `command`, as the comment there shows. It drops them the way TREK would on its next write and lists every value it changed. |
| the Postgres database is not empty | A previous attempt left something behind, or TREK started on it. Drop and recreate the database, or point `TREK_DB_URL` at a new one. |
| `travel.db` is at the wrong migration level | The image tag in the Job does not match the version that last started on the file. Make them equal. |
| a table or column only one side has | Do not force it. Stay on SQLite — it still works — and report the message upstream with any `[DB] The database lacks` line from step 1. |
| two rows a unique key holds equal, or a value outside a column's allowed set | Correct or remove the row in `travel.db` with TREK stopped, then run again. |

Uploads are not moved and need not be: files, covers, photos and avatars stay
in `/appdata/trek/uploads` and the copied rows point at them as before. Keep
the same `ENCRYPTION_KEY` — the stored secrets move across still encrypted
with it.

Then clear the Job away:

```bash
kubectl -n utilities delete job trek-move-to-postgres
```

## Step 5 — start TREK on Postgres

```bash
sed -i '' 's/^  replicas: 0$/  replicas: 1/' apps/utilities/trek/deployment.yaml
git commit -am "Start TREK on Postgres" && git push
kubectl -n utilities rollout status deploy/trek
```

Verify the start banner names Postgres and that no schema creation ran:

```bash
kubectl -n utilities logs deploy/trek | head -40
```

It should read `Database:       Postgres postgres://trek:***@trek-db:5432/trek`.
Then sign in at <https://trek.shiba-toast.com>, open a few trips, open a file
and a photo, and check **Admin → Plugins**.

Last, take a fresh backup under **Admin → Backup**. It now holds
`travel.pgdump` instead of `travel.db`.

## Going back

`travel.db` is untouched in `/appdata/trek/data`. Comment `TREK_DB_URL` out of
`apps/utilities/trek/secret.yaml`, apply it, and restart TREK — it runs on the
file as it was before the move. Anything written on Postgres is not in it. To
try the move again, drop and recreate the Postgres database first.

Keep `travel.db` as a copy for a while. It does not interfere with a Postgres
install that holds data; TREK only refuses to start when the Postgres database
is *empty* and `travel.db` has accounts.

## Day 2

* **Keep `replicas: 1`.** TREK holds rate limits, pending one-time codes, the
  permission cache and WebSocket connections in memory, and serializes writes
  behind a database-wide advisory lock. Postgres does not make it scale out.
  The `Recreate` strategy also has to stay: a rolling update would migrate the
  database while the old pod still writes to it.
* **Upgrades write a `pg_dump` copy first.** A start with pending migrations
  writes `data/pre-migrate-<migration>-<time>.pgdump` into
  `/appdata/trek/data` and keeps the newest 3. If it cannot be written, TREK
  refuses to migrate and does not start — usually a full disk.
* **Backups and restores** go through **Admin → Backup** as before. A restore
  replaces the current database and every `trek_plugin_*` schema the role owns,
  after keeping `data/pre-restore-<time>.pgdump`. `pg_restore` expands the dump
  to a SQL script in the data directory first, so it needs free space there;
  the limit is `BACKUP_MAX_DECOMPRESSED_MB` (5 GB).
* **Restores only go to the same or a newer PostgreSQL major.** A backup from a
  newer major is refused.
* **`scripts/apps.yaml`** tracks `mauriceboe/trek` against
  `.spec.template.spec.containers[0].image` in `apps/utilities/trek/deployment.yaml`.
  The Postgres container is in `db.yaml`, so the version check is unaffected
  and `postgres:18` stays pinned by hand — which is what you want.
* **Resetting the admin account** works as on SQLite:
  `kubectl -n utilities exec -it deploy/trek -- node server/reset-admin.js`.

## Known gaps

* `trek-pv` (`/appdata/trek`) still has no `nodeAffinity`, because a PV's
  `nodeAffinity` is immutable once bound and recreating the PV was not worth it.
  The trek Deployment carries a `nodeSelector` for `k3s-worker` instead, which
  closes the same hole from the other side: without it TREK could be scheduled
  onto `k3s-cp` and come up on an empty `/appdata/trek` — on Postgres that
  means a database holding all your data with no uploads and no
  `.encryption_key` / `.jwt_secret` beside it. Drop that `nodeSelector` only
  together with a PV that pins the volume itself. `trek-db-pv` is pinned at the
  PV, so `trek-db` needs no `nodeSelector`.
* `sslmode=disable` is right for pod-to-pod traffic in this cluster. If TREK
  and `trek-db` ever land on different nodes the connection crosses the flannel
  VXLAN unencrypted; both are pinned to `k3s-worker` today.
