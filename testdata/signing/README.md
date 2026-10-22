# Signing test vectors (design §9.5)

Shared by go-echolot's tests and yamn's verifier tests. **`pinger.key` is a
test key, published on purpose. Never use it for anything else.**

| File | What |
|---|---|
| `pinger.key` | minisign secret key without a password (`minisign -G -W` format) |
| `pinger.pub` | its public key, minisign's two-line format; the base64 line is what yamn's config takes |
| `pubring.mix` | a real keyring (`testdata/pubrings/mixmin.mix`) |
| `mlist2.txt` | stats with broken chains (`testdata/golden/chain1/pub/mlist2.txt`) |
| `<file>.minisig` | go-echolot's signature |
| `<file>.minisign-tool.minisig` | the reference minisign 0.12 tool's signature of the same file, with the same key and trusted comment |

The signatures were made at 2026-10-22 12:00:00 UTC (`timestamp:1792670400`):

```
timestamp:1792670400 file:pubring.mix pinger:test expires:1792843200   (+48 h)
timestamp:1792670400 file:mlist2.txt pinger:test expires:1792692000    (+6 h)
```

Ed25519 is deterministic, so both signatures of a file are the same bytes;
only the untrusted comment differs. Verify with the reference tool:

```
minisign -Vm pubring.mix -p pinger.pub
minisign -Vm pubring.mix -x pubring.mix.minisign-tool.minisig -p pinger.pub
minisign -Vm mlist2.txt -P RWQgENJbJTXyiQw5YbtIXa2d+EMCmLkZ0ieF/LCB9BchV8xal3NYeg9J
```

How they were made:

```
go test ./internal/minisign -run TestVectors -update      # pinger.pub, <file>.minisig
tc=$(sed -n 3p pubring.mix.minisig | sed 's/^trusted comment: //')
minisign -S -s pinger.key -m pubring.mix -x pubring.mix.minisign-tool.minisig -t "$tc"
```

and the same for `mlist2.txt`. `TestVectors` checks that go-echolot still
writes `pinger.pub` and the `.minisig` files byte for byte, and that the
reference tool's signatures verify.
