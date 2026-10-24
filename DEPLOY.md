# Running a public Wisp relay

Wisp has two parts you ship separately:

- **The relay** (`wisp-relay`): a small server you run once, on a machine with a
  public address and a TLS certificate.
- **The desktop app**: an installer people download. It is built to talk to *your*
  relay.

Registration is open, so anyone who finds the relay can create an account. Read
[Open registration](README.md#open-registration) first for what protects it and
what does not.

> Wisp has had no independent security review. Running it publicly means
> strangers are trusting it with their messages. Say so wherever you publish the
> download.

## 1. The relay

### Build

On the server (or in CI, then copy the binaries). You need the Rust toolchain and
[`protoc`](https://github.com/protocolbuffers/protobuf/releases):

```bash
cargo build --release -p wisp-server --bin wisp-relay -p wisp-admin
# -> target/release/wisp-relay, target/release/wisp-admin
```

### Run it behind a TLS proxy

The relay speaks plain HTTP and expects a proxy to terminate TLS. Bind it to
loopback so the proxy is the only way in, and tell it to trust the proxy's
address header:

```bash
WISP_DB=/var/lib/wisp/wisp.db \
WISP_BIND=127.0.0.1:8080 \
WISP_TRUST_PROXY=1 \
  wisp-relay
```

**`WISP_TRUST_PROXY=1` is only safe when nothing but the proxy can reach the
relay.** It makes the relay believe the last `X-Forwarded-For` entry. If clients
can connect to the relay directly, they can send any header they like and pick
their own rate-limit bucket, which defeats every limit below. Keep the relay's
port closed to the internet and open only 80 and 443.

Without `WISP_TRUST_PROXY`, every visitor appears to come from the proxy's
address and shares one rate-limit bucket: five signups an hour for the whole
site, and one person's typos could lock everyone out. The relay prints a warning
at startup if it is bound to a non-loopback address without the flag.

**Caddy** (obtains and renews the certificate itself; WebSockets just work):

```text
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**nginx** needs the upgrade headers for the WebSocket and must *set*, not
append to, the forwarded address:

```text
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 1h;
}
```

### Keep it running (systemd)

Create the service user first (`sudo useradd --system --home /var/lib/wisp wisp`).

```ini
# /etc/systemd/system/wisp-relay.service
[Unit]
Description=Wisp relay
After=network.target

[Service]
User=wisp
ExecStart=/usr/local/bin/wisp-relay
Environment=WISP_DB=/var/lib/wisp/wisp.db
Environment=WISP_BIND=127.0.0.1:8080
Environment=WISP_TRUST_PROXY=1
Restart=on-failure
StateDirectory=wisp
StateDirectoryMode=0700
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/wisp

[Install]
WantedBy=multi-user.target
```

Check it from outside: `curl https://relay.example.com/health` should print `ok`.

### Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `WISP_DB` | `wisp.db` | SQLite database path |
| `WISP_BIND` | `127.0.0.1:8080` | Listen address |
| `WISP_TRUST_PROXY` | off | Believe the proxy's `X-Forwarded-For` (see above) |
| `WISP_CLIENT_IP_HEADER` | unset | Take the caller's address from this header instead (`cf-connecting-ip` behind Cloudflare). Wins over `WISP_TRUST_PROXY`. |
| `PORT` | unset | Used as `0.0.0.0:$PORT` when `WISP_BIND` is not set. Hosting platforms provide it. |
| `WISP_SIGNUPS_PER_ADDRESS` | `5` | Accounts one address may create per window |
| `WISP_SIGNUPS_GLOBAL` | `500` | Accounts the whole relay creates per window |
| `WISP_SIGNUP_WINDOW_SECS` | `3600` | Length of that window |
| `WISP_MAX_PENDING` | `1000` | Undelivered messages held per recipient |
| `WISP_MAX_ENVELOPE_BYTES` | `262144` | Largest message the relay will queue |

A value that is set but is not a number stops the relay from starting, rather
than being ignored, so a typo cannot leave you believing a limit is in force.

Tune `WISP_SIGNUPS_GLOBAL` to your expected traffic. It is a safety valve: when it
is hit, real visitors are turned away until the window resets. Too low and a
good day looks like an attack; too high and it stops protecting the disk.

### What the database holds

`wisp.db` contains public keys, hashed usernames, undelivered *encrypted*
messages, and **the relay's sealed-sender signing keys**. Anyone who obtains the
file can issue sender certificates as your relay, so treat it and every backup of
it as a secret: mode `0700` directory, encrypted backups, never in a repository.

Back it up with SQLite's own tool, not a file copy (it runs in WAL mode):

```bash
sqlite3 /var/lib/wisp/wisp.db ".backup '/secure/place/wisp-$(date +%F).db'"
```

Losing the database loses every account on the relay. Clients keep their own
identities on their USB drives, but the relay would no longer know them.

### Moderating

Registration is open, so expect to use this. Usernames are hashed and cannot be
listed; accounts are identified by public key, which is the fingerprint a user
can read out to you.

```bash
wisp-admin --db /var/lib/wisp/wisp.db accounts
wisp-admin --db /var/lib/wisp/wisp.db lock <public-key-hex> --for 7d
wisp-admin --db /var/lib/wisp/wisp.db unlock <public-key-hex>
```

A locked account's session tokens stop working immediately. It does not stop the same person registering a new account; the
per-address limit is what slows that down.

## Running the relay locally with Docker

The simplest way to run a relay on your own computer: no Rust toolchain needed to
*run* it, and nothing reachable from outside the machine. The repository's
`Dockerfile` builds just the relay, and `docker-compose.yml` runs it with a
persistent data volume.

```bash
docker compose up -d --build
curl http://127.0.0.1:8080/health
```

The first build compiles the Signal library inside Docker and takes several
minutes; later builds reuse the cache. The app's default relay address is already
`http://127.0.0.1:8080`, so it needs no configuration.

- **The port is local only.** Compose publishes `127.0.0.1:8080`, so only this
  computer can reach the relay. To let other devices on your network use it, change
  the mapping to `"8080:8080"` and allow it through the firewall.
- **Every request appears to come from Docker's gateway address**, so all callers
  share one signup allowance. Compose raises `WISP_SIGNUPS_PER_ADDRESS` to 100 for
  that reason. This is fine for one person; it is not a public setup.
- **Data lives in a Docker volume** (`wispdesktop_wisp-data`). `docker compose
  down` keeps it. `docker compose down -v` **deletes it**, along with every account
  and the relay's signing keys.
- **Back it up** by stopping the relay first, so nothing is half-written:

  ```bash
  docker compose stop
  docker cp wispdesktop-relay-1:/data/wisp.db ./wisp-backup.db
  docker compose start
  ```
- **After changing the code:** `docker compose up -d --build`.
- **Logs:** `docker compose logs -f`.
- **Starts with Docker Desktop**, because the service is set to `restart:
  unless-stopped`.
- A database from running the relay directly (`wisp.db` in the project folder) is
  not used: the container starts empty. Identities created against the old relay
  will not exist on the new one, so recreate them, or stop the container and copy
  the old file into the volume.

This image was built and tested: a fresh container accepted a signup, a login, and
messages both ways, kept idle sockets open, shut down in half a second on `docker
stop`, and kept its data after the container was removed and recreated.
## Running from your own PC with Cloudflare Tunnel

For a personal project this is the simplest honest setup: the relay stays on your
machine, and Cloudflare is the only thing the internet can reach. The relay binds
to loopback, so there is no open port and no home IP address exposed. You need a
free Cloudflare account and a **domain whose nameservers are at Cloudflare** (the
domain itself costs a few dollars a year). The domain is also what lets you change
hosts later without rebuilding the installer.

1. **Install and sign in** (`cloudflared` is a single program; `winget install
   Cloudflare.cloudflared` on Windows):

   ```bash
   cloudflared tunnel login
   cloudflared tunnel create wisp
   cloudflared tunnel route dns wisp relay.YOURDOMAIN.com
   ```
2. **Point the tunnel at the relay.** Create `config.yml` in your `.cloudflared`
   folder, using the credentials file `create` printed:

   ```yaml
   tunnel: wisp
   credentials-file: C:\Users\YOU\.cloudflared\TUNNEL-ID.json
   ingress:
     - hostname: relay.YOURDOMAIN.com
       service: http://127.0.0.1:8080
     - service: http_status:404
   ```
3. **Run the relay, telling it where the caller's address lives:**

   ```bash
   WISP_CLIENT_IP_HEADER=cf-connecting-ip wisp-relay
   ```

   (On Windows PowerShell: `$env:WISP_CLIENT_IP_HEADER = "cf-connecting-ip"; cargo
   run --release -p wisp-server --bin wisp-relay`.)
4. **Run the tunnel:** `cloudflared tunnel run wisp`. To keep it running without a
   terminal, `cloudflared service install` makes it a Windows service. The relay
   needs the same treatment (Task Scheduler "at startup" works).
5. **Check it from outside**, then build the installer:

   ```bash
   curl https://relay.YOURDOMAIN.com/v1/whoami
   node tools/build-installer.mjs https://relay.YOURDOMAIN.com
   ```

What was tested through a real Cloudflare tunnel, and what it showed:

- **The relay sees the real caller.** `/v1/whoami` returned the same public address
  Cloudflare itself reported for the machine, so the per-address signup limit works
  per person, not per tunnel.
- **The address can't be faked.** A forged `CF-Connecting-IP` is rejected by
  Cloudflare before it reaches the relay, and forged `X-Forwarded-For` and
  `X-Real-IP` headers are ignored.
- **Silent WebSockets are dropped after about two minutes.** A connection sending
  nothing was cut at roughly 125 seconds (close code 1006). The relay therefore
  pings every connected client every 30 seconds, and the app reconnects on its own
  with a growing delay if a connection is lost anyway.
- **With pings, idle connections survive.** Two authenticated sockets stayed open
  through 210 seconds of silence and then delivered a message.
- **Half-open connections are cut.** A connection that never authenticates is
  closed after 10 seconds, so it can't be held open for free.

You can repeat the full check against any deployed relay (this registers two
throwaway accounts on it):

```bash
WISP_TEST_RELAY_URL=https://relay.YOURDOMAIN.com WISP_TEST_IDLE_SECS=210 \
  cargo test -p wisp-server --test end_to_end -- --ignored --nocapture
```

Cloudflare's dashboard also has bot protection and rate-limiting rules you can turn
on in front of the relay; check what the free plan includes before relying on them.
The relay's own limits still apply behind them.

For a quick demo, `cloudflared tunnel --url http://127.0.0.1:8080` needs no account
or domain but gives a random address that changes on every run, so never build an
installer against it.
## 2. The desktop installer

The relay has to be online **first**. The installer is built to talk to one
specific relay address, and a build pointed at a relay that is down or
misconfigured is an installer you cannot ship. `tools/build-installer.mjs` makes
that order impossible to get wrong:

```bash
node tools/build-installer.mjs https://YOUR-DOMAIN
```

It refuses to build unless:

- the address is `https://` and not a local one,
- `GET /health` answers `ok`, so the relay is really up,
- `GET /v1/whoami` returns a **public** address for this machine. A private or
  proxy address means the relay is reading the wrong header and the signup limits
  would apply to everyone at once.

Then it runs `cargo tauri build` with the relay address compiled in, and checks
that the finished app actually contains it. People never set environment
variables. Add `--check-only` to run the checks without building.

You need the Tauri CLI once: `cargo install tauri-cli --version "^2"`. Installers
land in `target/release/bundle/`. `WISP_RELAY_URL` at runtime still overrides the
compiled-in address, which is what you want for development.
**Use `https://`.** With `http://` everything the client sends, including who is
registering and when, crosses the network in the clear. Only the message
contents are protected by Signal; the transport is not Wisp's job.

Notes for shipping it:

- **Windows only is real.** macOS has never been compiled or run, and Touch ID is
  not implemented. Say "Windows" in the download page rather than "Windows and
  macOS" until a Mac build has been tested.
- **Unsigned installers trigger SmartScreen warnings** on Windows ("unknown
  publisher"). Code signing needs a certificate you buy. Until then, tell users
  to expect the warning and publish a checksum for each installer.
- Tell users they need **a USB drive of their own**. It becomes their key, there
  is no recovery, and a drive that reports no serial number gives weaker binding.
  `cargo run -p wisp-usb --example list_volumes` shows what a given stick reports.

## 3. Before you announce it

- [ ] `cargo test --workspace` passes on a machine with the MSVC build tools and
      `protoc`
- [ ] The relay is deployed, `/health` answers `ok`, and `/v1/whoami` showed two
      different public addresses from two different networks
- [ ] The relay's volume is mounted and a backup has been taken
- [ ] `node tools/build-installer.mjs https://YOUR-DOMAIN` completed
- [ ] You installed the result on a clean machine and tested end to end: signup,
      lock, unlock, switch drive, send a message to a second account
- [ ] The download page says Windows only, and mentions the SmartScreen warning- [ ] You have a way to be contacted about abuse and about vulnerabilities (see
      [SECURITY.md](SECURITY.md))

## Known gaps for a public relay

These are not handled, and you should decide how you feel about them before
opening the door:

- **No CAPTCHA, email check, or proof of work.** Bulk signup is slowed, not
  prevented. See the README for the exact limits.
- **No per-account send rate limit.** Mailbox depth and message size are capped,
  but one account can still send as fast as the connection allows.
- **One-time prekeys can be drained.** Any account can fetch another's prekeys,
  and with open registration "any account" is anyone. Sessions still work without
  a one-time prekey, with slightly weaker forward secrecy for the first message.
- **No operator-side account deletion.** `lock` refuses service but the row stays.
- **You are hosting traffic you cannot read.** Decide what you will do when
  someone reports abuse: the relay can lock an account, but it cannot see or
  remove content.
