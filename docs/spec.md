# go-echolot: spec draft (yamn-only pinger)

> Earlier draft. Where it differs from [design.md](design.md), the design wins.

Source read: github.com/crooks/echolot @ 40676ca (2020-09-26, Echolot 2.1.9 plus
two regex fixes). Only the parts that matter for yamn are described here. Type I
(cypherpunk/PGP) handling is left out.

## 1. What Echolot does

### 1.1 Remailer list

Each known remailer address has a state:

| State | Meaning | Leaves the state when |
|---|---|---|
| active | requests and pings are sent | ttl reaches 0 → ttl timeout |
| ttl timeout | no conf reply for a while; checked weekly | a reply arrives → active; 8 weekly checks fail → dead |
| dead | nothing is sent | a reply arrives → active |
| disabled | someone replied "not a remailer" | operator only |

- `ttl` starts at 5 and drops by one for each remailer-conf request sent. Any
  valid conf or key reply resets it to 5. The result is that a remailer is
  disabled after about 5 days of silence.
- The flags `fetch`, `pingit` and `showit` decide whether Echolot requests
  data, pings, and lists the remailer. For new remailers all three are on by
  default.

### 1.2 Discovery of new remailers

- A remailer-conf reply contains a `SUPPORTED MIXMASTER (TYPE II) REMAILERS`
  section. Every address in it becomes a *prospective* address.
- Prospective addresses are reviewed every 8 hours. One becomes a remailer:
  - when at least **6** different remailers listed it within the last 5 days;
  - **immediately** when a known remailer's own conf or key reply names a
    different address.
- The operator can also add addresses by hand (`commands.txt`).

### 1.3 Requests (key and conf collection)

- For every active remailer, Echolot mails `remailer-conf`, `remailer-key`,
  `remailer-help`, `remailer-stats` and `remailer-adminkey` **once a day** each.
  Requests go out at a slot spread over the day by hashing address, type and
  day.
- Every request is sent from a unique address, and the reply's To address
  carries the token back:
  `<localpart>+<type>.<id>=<unixtime>=<hash8>@<domain>`
  - `hash8` is the first 8 hex digits of MD5(`<type>.<id>=<unixtime>` + secret).
  - Incoming mail whose token doesn't verify is dropped, as a probable bounce.
- Every reply is saved as-is in the "thesaurus" (`thesaurus/NN.key`, `.conf`,
  …). Old entries expire after 21 days.

**remailer-conf** parsing:
- `Remailer-Type: ...`
- The caps line `$remailer{"nick"} = "<addr> caps...";`. The address in it must
  match the remailer's own address, otherwise it only becomes a prospective
  address.
- The supported-remailers list (see 1.2).

**remailer-key** parsing:
- The summary line:
  `nick addr keyid(32 hex) version caps created(YYYY-MM-DD) expires(YYYY-MM-DD)`
- The key block:
  `-----Begin Mix Key-----`, keyid line, **a digits-only length line**,
  base64 lines, `-----End Mix Key-----`.
- A key is rejected if:
  - its created date is in the future;
  - its expires date has passed;
  - the summary has no matching key block;
  - the address doesn't match the remailer.
- A key is stored under (address, keyid) with `last_update` = time of the
  reply. If that keyid is already stored, the summary and key text are simply
  replaced (only logged).
- There is **no** check that the keyid belongs to the key.

### 1.4 Pings

- A scheduler tick runs every 5 minutes. Each key of each pinged remailer is
  pinged **once every 2 hours** (24 ticks), at a slot hashed from address, key
  and session.
- The ping body:
  ```
  remailer: <addr>
  type: mix
  key: <keyid>
  with_from: 0|1
  sent: <unixtime>
  mac: MD5(addr:type:key:with_from:sent + secret)
  -----BEGIN GARBAGE-----  0..4096 random bytes as hex, 64 per line
  ```
  The whole body is GPG-encrypted symmetrically with the secret.
- The ping is sent as a **single hop** through that remailer. Echolot writes a
  one-key `pubring.mix`, `type2.list` and `mix.cfg` into `mixhome`, then runs
  `$mixmaster -m -S -l <nick>` with `To: <localpart>+ping=<time>=<hash8>@<domain>`
  on stdin.
- `with_from` switches every 2 hours. When it is 1, a `From: Echolot Pinger
  <addr>` header is added. Echolot uses this to record whether the remailer
  honours From lines (the "fromlines" pages).
- On arrival, Echolot decrypts the body and checks the MAC. It then records
  `sent latency` in that key's `done` file and removes `sent` from the key's
  `out` file.

### 1.5 Statistics (rebuilt every 5 minutes)

All pings for all keys of an address from the last **12 days** count.

- **Latency** is the median latency of all returned pings. There is also one
  median per day of age (day 0 = last 24 h).
- **Reliability** is a weighted ratio of received to sent pings.
  - Weight by age in days, 0..11:
    `0.5 1.0 1.0 1.0 1.0 0.9 0.8 0.5 0.3 0.2 0.2 0.1`.
    Very fresh pings count half, since they may simply not be back yet.
  - A returned ping adds `weight` to both sent and received.
  - An outstanding ping sent `age` seconds ago adds `weight` to sent and
    `weight × p` to received.
    - `p` is the fraction of returned pings whose latency is greater than
      `(age − 15 min) / 0.8`.
    - In other words: the longer a ping has been out compared to how fast this
      remailer usually answers, the less it still counts as "probably coming".
  - Per-day reliability is computed the same way, without weights.

**Sort order:** reliability descending, then nick. Optionally latency second.

### 1.6 mlist2.txt

```
Stats-Version: 2.0
Generated: Tue 20 Oct 2026 21:05:01 GMT
Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options
------------------------------------------------------------------------
%-12s        %-12s         %6s     %-12s         %5.1f%%  %s
```

The columns are nick, latency history, latency (`hh:mm`, or `  :mm` under an
hour), uptime history, uptime, and options.

- **Latency history** has one character per day, the oldest on the left:
  - `0` <20 min, `1` <1 h, … `9` <9 h;
  - `A` <12 h, `B` <18 h, `C` <24 h, `D` <30 h, `E` <36 h, `F` <42 h, `G` <48 h, `H` beyond that;
  - `?` no data.
- **Uptime history** has one character per day: `+` ≥99.99 %, otherwise the
  tenths digit, `?` no data.
- **Options** is a 15-character flag string built from the caps. `D` = middle,
  `P` = post, `M`/`R`/`2` = mix/remix/remix2, `E`/`e` = ek, and so on.
- Then come optional sections: "Groups of remailers sharing a machine or
  operator", "Broken type-I remailer chains", "Broken type-II remailer chains".
- Then `Remailer-Capabilities:`, the caps lines sorted.

**yamn itself reads only:** `Generated:`, then per row the nick, latency
(`hh:mm`) and uptime (`xx.x%`) (`keymgr/public.go` ImportStats).

### 1.7 pubring.mix (rebuilt every 8 hours)

- Each address contributes the key with the newest `last_update`, provided
  there is a nick and `showit` is set and the caps don't contain `testing`.
- Entries are sorted by summary line. Each one is the summary line, a blank
  line, the key block and another blank line.
- Every output file gets a `.meta` file with an `Expires:` header.
- Echolot writes a public and a private variant of every file. The private one
  includes hidden remailers.

### 1.8 Chain pings

- A ping goes through two hops `(A B)`. Each pair is pinged once a week; pairs
  under suspicion ("intensive care") are pinged daily.
- Over 10 days, a pair is **broken** if:
  - at least 3 pings were sent;
  - returned/sent < 0.3 × rel(A) × rel(B).
- Pings that are younger than 1.5 × (lat A + lat B) don't count yet.
- If at least half of all pairs `(A x)` are broken, Echolot lists `(A *)`
  instead.
- The operator can add broken chains by hand (`broken2.txt`).
- yamn ignores this section.

### 1.9 Expiry (daily)

| What | Expires after |
|---|---|
| keys | 5 days since last seen; the key's pings are deleted with it |
| confs | 5 days |
| pings | 12 days |
| chain pings | 12 days |
| fromlines | 5 days |
| thesaurus | 21 days |

## 2. Findings for yamn

1. **The published Echolot can't read yamn keys.**
   - yamn's key block is keyid, then 64 hex characters of public key. There is
     no digits-only length line, so Echolot's regex (`Conf.pm` lines 285–289)
     matches nothing: tested against mixmin's `thesaurus/65.key`, 0 matches.
   - Echolot's ping call writes `mix.cfg` and sets `MIXPATH`, both of which
     yamn ignores.
   - The yamn pingers therefore run **modified, unpublished** Echolot code or
     a wrapper. Two exist (2026-10-20): mixmin.net/yamn/ and
     echolot.virebent.art ("Victor Yamn Pinger", 7 remailers including
     `middleman`, which mixmin.net doesn't list). Nobody has published their
     changes.
2. **The key-rotation lag is by design.**
   - remailer-key is requested once a day, and `pubring.mix` is rebuilt every
     8 hours, so a new key can take up to about **32 hours** to appear.
   - An old key stays in the store until it hasn't been seen for 5 days.
   - The keyring uses whichever key has the newest `last_update`. If a reply
     lists two keys during rotation, both get the same timestamp, and which
     one wins is down to hash order.
3. **Trust gaps (Y-03).**
   - Every reply is unsigned mail.
   - Echolot doesn't check keyid = blake2s(public key). (yamn clients now
     check this, Y-03 part 1.)
   - It silently replaces the key text stored for a known keyid.
   - It adds any address that a known remailer's reply names.
   - Its MACs are MD5(data + secret): fine for this purpose, but HMAC-SHA256
     would be the obvious choice today.
4. **Interaction with our recent changes:**
   - **Y-19** (one remailer-* reply per address per day): no conflict, because
     each Echolot request comes from a unique address.
   - **Y-20** (client strips headers): yamn reduces `From: Echolot Pinger
     <addr>` to the bare address. That only affects the fromlines test.
   - **Y-15** (num_copies 2): every ping is sent twice to the same exit, which
     delivers one. A pinger should pass `--copies=1`.

## 3. Proposed go-echolot (yamn only)

### 3.1 How it creates packets

No library split is needed. go-echolot runs:

```
yamn -m --stdout -c 1 -l <nick> --config <pinger.yml>
```

- `<pinger.yml>` points at a one-key pubring and has `urls.fetch: false`.
- yamn returns the encrypted mail as mbox (from PR #26), and go-echolot sends
  it with its own SMTP code.

This is the same model Echolot uses with `mix`, only with yamn's real flags.
The cost is one process per ping. With about 20 remailers, each pinged every
2 hours, that is about 10 processes an hour, which doesn't matter.

### 3.2 Components (estimate)

| Part | What | Lines |
|---|---|---|
| store | remailers, keys, pings, prospective addresses; LevelDB (already a yamn dependency) or JSON files | 350 |
| mailin | read Maildir, verify token, dispatch | 150 |
| mailout | requests and pings via SMTP (adapted from yamn mail.go) | 150 |
| conf/key parsing | caps line, supported list, summary + yamn key block, checks | 250 |
| pinger | schedule, body, secretbox instead of GPG, receive, MAC | 200 |
| stats | the algorithm in 1.5, mlist2.txt writer | 300 |
| keyring | pubring.mix writer (+ signature, phase 4) | 100 |
| scheduler, config, CLI, logging | | 250 |
| **MVP total** | | **≈1,750** + tests |
| chain pings, HTML pages, thesaurus | later | +600 |

### 3.3 Phases

1. **Keys:**
   - collect conf and key replies and write `pubring.mix`;
   - check keyid = blake2s(public key), the dates and the address;
   - pin the address→nick binding: a nick or address change needs the operator;
   - write the thesaurus as plain files.
2. **Pings:**
   - single-hop pings, and `mlist2.txt` using the 1.5 algorithm exactly, so
     clients see the same numbers as from Echolot;
   - run it next to mixmin's and compare.
3. **Chain pings, and HTML pages** like mixmin.net/yamn/.
4. **Y-03:**
   - an Ed25519 key per pinger; it publishes `pubring.mix.sig` and
     `mlist2.txt.sig`;
   - yamn gets `urls.pubring_sig` and a pinned pinger public key, and refuses
     unsigned or wrongly signed downloads when configured;
   - optionally require two pingers to agree on each key.

### 3.4 Open decisions

1. Separate repo `go-while/go-echolot` (keeps yamn untouched; uses yamn as an
   external binary) vs. `yamn --pinger` inside this repo (one binary, shared
   code, but grows yamn).
2. Storage: LevelDB vs. plain files (plain files are easy to inspect, as with
   Echolot).
3. Whether phase 1 should reproduce Echolot's auto-discovery (6
   recommendations) or only use an operator-maintained address list. The list
   is safer and enough for a network of about 20 remailers.
