# Generates the input of a golden case for harness.pl: python3 gen.py <case>
# Every case is deterministic.
#   1  random data (seed 1): 6 remailers, 2 keys each
#   2  hand-made edge cases (docs/design.md §11), with all three sections
#   3  the remailers of case 2, sort_by_latency on, empty broken sections
#   4  random data (seed 4) with stats_days 7 and other weights
#   5  no remailers at all
import json, random, sys

NOW = 1792560000 + 12345  # a fixed instant
DAY = 86400


def random_case(seed):
    random.seed(seed)
    now = NOW
    rems = {}
    specs = [("alpha", 0.99, 600, "middle v2"), ("bravo", 0.80, 3000, "v2"), ("charlie", 0.50, 20000, "v2"),
             ("delta", 1.0, 90, "middle v2"), ("echo", 0.0, 0, "v2"), ("foxtrot", 0.95, 400000, "v2")]
    for nick, rel, lat, caps in specs:
        addr = nick + "@example.org"
        keys = {}
        for k in range(2):
            out, done = [], []
            t = now - 12*86400 + k*6*86400 + random.randint(0, 7200)
            while t < now - 60 and t < now - 12*86400 + (k+1)*7*86400:
                if random.random() < rel:
                    l = max(1, int(random.expovariate(1.0/lat))) if lat else 1
                    if t + l < now:
                        done.append([t, l])
                    else:
                        out.append(t)
                else:
                    out.append(t)
                t += 7200 + random.randint(-300, 300)
            keys["%032x" % random.getrandbits(128)] = {"out": out, "done": done}
        rems[addr] = {"nick": nick, "caps": '$remailer{"%s"} = "<%s> %s";' % (nick, addr, caps), "keys": keys}
    return {"now": now, "rems": rems}


def at(day, sec=3600):
    """A sent time in the given day (by age), sec into it."""
    return NOW - day*DAY - sec


def edge_rems():
    rems = {}
    serial = [0]

    def rem(nick, words="v2", keys=None, caps=True, showit=None):
        addr = nick + "@example.org"
        r = {"nick": nick, "keys": {}}
        for k in keys if keys is not None else [{}]:
            serial[0] += 1
            r["keys"]["%032x" % (0xec401 * serial[0])] = {"out": k.get("out", []), "done": k.get("done", [])}
        if caps:
            r["caps"] = '$remailer{"%s"} = "<%s> %s";' % (nick, addr, words)
        if showit is not None:
            r["showit"] = showit
        rems[addr] = r

    # No pings at all, and only outstanding ones (no done).
    rem("nopings")
    rem("outonly", keys=[{"out": [at(d, 600 + 3*d) for d in range(12)] + [NOW - 300]}])
    # Even and odd medians: day 1 even (150.5), day 2 odd, day 3 even
    # (2.5), 10 in all (8.5, which min_hr truncates).
    rem("evenodd", keys=[{"done": [[at(1), 100], [at(1, 7200), 201], [at(2), 10], [at(2), 20], [at(2), 30]]},
                         {"done": [[at(3), 1], [at(3), 2], [at(3), 3], [at(3), 4], [at(4), 7]]}])
    # One done ping per day, on and next to the bucket edges of both
    # latency alphabets.
    edges2 = [1199, 1200, 3599, 3600, 7199, 7200, 32399, 32400, 43200, 64800, 172799, 172800]
    rem("edges", keys=[{"done": [[at(d), l] for d, l in enumerate(edges2)]}])
    edges1 = [299, 300, 3599, 3600, 14399, 14400, 86399, 86400, 172799, 172800, 107999, 108000]
    rem("edgesone", keys=[{"done": [[at(d), l] for d, l in enumerate(edges1)]}])
    # min_hr: 99:00:59 is shown, 100 h is 99:59.
    rem("slowmin", keys=[{"done": [[at(5), 356459]]}])
    rem("tooslow", keys=[{"done": [[at(6), 360000]]}])
    # Nicks of 12, 13 and 15 characters; reliability 1.0 ties with others.
    rem("twelvechars1", keys=[{"done": [[at(2), 61]]}])
    rem("thirteenchar5", keys=[{"done": [[at(2), 62]]}])
    rem("fifteencharnick", keys=[{"done": [[at(2), 63]]}])
    # Ties in reliability with different latencies (sort_by_latency).
    rem("zulu", keys=[{"done": [[at(3), 60]]}])
    rem("mike", keys=[{"done": [[at(3), 600]]}])
    rem("alpha", "middle v2", keys=[{"done": [[at(3), 3000]]}])
    # Day 0 at 0.99985 ('9', not '+') and 0.99995 ('+'): 99 done and one
    # out whose percentile is 197/200 or 199/200.
    for nick, small in (("rel99985", 3), ("rel99995", 1)):
        done = [[at(0, 2000 + i), 3000] for i in range(99)]
        done += [[at(2, 100 + i), 60] for i in range(small)]
        done += [[at(2, 200 + i), 3000] for i in range(101 - small)]
        rem(nick, keys=[{"done": done, "out": [NOW - 1000]}])
    # Exact ties for %5.1f and %6.2f: reliability 1/16 (6.25), 3/16
    # (18.75), 1/32 (3.125), 5/32 (15.625); all in days of weight 1.0.
    for nick, k, n in (("tie16a", 1, 16), ("tie16b", 3, 16), ("tie32a", 1, 32), ("tie32c", 5, 32)):
        rem(nick, keys=[{"done": [[at(2, 100 + i), 60] for i in range(k)],
                         "out": [at(1 + i % 4, 200 + i) for i in range(n - k)]}])
    # Near ties: 7/80 and 33/400.
    for nick, k, n in (("near80", 7, 80), ("near400", 33, 400)):
        rem(nick, keys=[{"done": [[at(1 + i % 4, 100 + i), 60] for i in range(k)],
                         "out": [at(1 + i % 4, 1000 + i) for i in range(n - k)]}])
    # Pings "in the future" by less than a day count as day 0.
    rem("future", keys=[{"done": [[NOW + 3600, 60], [at(2), 120]], "out": [NOW + 7200, at(3)]}])
    # The 12-day cutoff is strict; the day boundary.
    rem("cutoff", keys=[{"done": [[NOW - 12*DAY, 10], [NOW - 12*DAY + 1, 20], [NOW - DAY, 30], [NOW - DAY + 1, 40]],
                         "out": [NOW - 12*DAY, NOW - 12*DAY + 1]}])
    # Options; a hidden one; one asking not to be listed; one without conf.
    rem("opts1", "middle post remix2 hybrid repgp2 pgponly ext max test latent ekx esub inflt50 rhop5 klen1024",
        keys=[{"done": [[at(1), 100]], "out": [at(1)]}])
    rem("opts2", "anon-post-to remix repgp ek klen0250 Mix",
        keys=[{"done": [[at(1), 100]], "out": [at(1), at(2)]}])
    rem("hidden", keys=[{"done": [[at(1), 100]]}], showit=0)
    rem("tester", "MIX Testing klen099", keys=[{"done": [[at(1), 100]]}])
    rem("noconf", keys=[{"done": [[at(1), 100]]}], caps=False)
    return rems


def main():
    case = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    if case == 1:
        d = random_case(1)
    elif case == 2:
        d = {"now": NOW, "rems": edge_rems(),
             "files": {"sameop": "alpha mike\nzulu edges", "broken1": "(alpha zulu)", "broken2": "(mike *)\n(* zulu)"}}
    elif case == 3:
        d = {"now": NOW, "rems": edge_rems(), "config": {"stats_sort_by_latency": 1},
             "files": {"broken1": "", "broken2": ""}}
    elif case == 4:
        d = random_case(4)
        d["config"] = {"stats_days": 7, "pings_weight": [0.5, 1.0, 1.0, 0.9, 0.8, 0.5, 0.2]}
    elif case == 5:
        d = {"now": NOW, "rems": {}}
    else:
        sys.exit("no case %d" % case)
    json.dump(d, sys.stdout, indent=1)


main()
