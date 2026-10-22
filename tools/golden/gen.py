# Generates the input of a golden case for harness.pl: python3 gen.py <case>
# Every case is deterministic.
#   1  random data (seed 1): 6 remailers, 2 keys each
#   2  hand-made edge cases (docs/design.md §11), with all three sections
#   3  the remailers of case 2, sort_by_latency on, empty broken sections
#   4  random data (seed 4) with stats_days 7 and other weights
#   5  no remailers at all
#   chain1  chain pings: hand-made edge cases of the evaluation and the
#           compression, with broken1 and broken2 files
#   chain2  chain pings: random data (seed 2) on the remailers of case 1
#   chain3  chain pings on but none sent, no files; compress_broken_chain
#           alone on hand-made lists
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


def chain_edge_case():
    """Remailers with simple stats, and chain pings for each rule of
    E:Stats.pm:557-622.  10 remailers count (hotel has no conf), so the
    compression threshold is 5."""
    rems = {}

    def rem(nick, done=(), out=(), words="v2", caps=True, showit=None):
        addr = nick + "@example.org"
        r = {"nick": nick, "keys": {"%032x" % (0xc4a1 * (len(rems) + 1)): {"out": list(out), "done": [list(x) for x in done]}}}
        if caps:
            r["caps"] = '$remailer{"%s"} = "<%s> %s";' % (nick, addr, words)
        if showit is not None:
            r["showit"] = showit
        rems[addr] = r

    ok600 = [[at(1), 600], [at(2), 600], [at(3), 600]]  # reliability 1, latency 600
    rem("alpha", ok600)
    rem("bravo", ok600)
    rem("charlie", [[at(1), 1200], [at(2), 1200]], words="middle v2")  # latency 1200
    rem("delta", [[at(2), 600]], [at(2, 7200)])  # reliability exactly 0.5
    rem("echo", out=[at(1), at(2)])  # reliability 0, no latency
    rem("fox", ok600, showit=0)  # not listed publicly
    rem("golf", ok600, words="testing v2")  # not listed publicly
    rem("hotel", ok600, caps=False)  # not a row at all
    rem("india", ok600)
    rem("juliet", ok600)
    rem("kilo", ok600)

    pings = []

    def ping(a, b, sent, lat=None):
        pings.append([sent, a + "@example.org", b + "@example.org", lat])

    def old(a, b, n, done=0):
        """n pings a day or more old, the first done of them back."""
        for i in range(n):
            ping(a, b, at(2 + i % 5, 100 + 37 * i), 3000 if i < done else None)

    old("alpha", "bravo", 3)            # exactly 3 out, none back: broken
    old("bravo", "alpha", 2)            # 2 out: intensive care
    old("alpha", "charlie", 1)          # 1 out: "only 1 sample"
    old("charlie", "alpha", 2)          # grace (1200+600)*1.5 = 2700 s:
    ping("charlie", "alpha", NOW - 2699)  # too young, not counted: 2 out
    old("charlie", "bravo", 2)
    ping("charlie", "bravo", NOW - 2700)  # just old enough: 3 out, broken
    old("bravo", "charlie", 1, done=1)  # back: fine
    old("alpha", "delta", 20, done=3)   # 3/20 = 0.15 = 0.3 * 1 * 0.5: broken
    old("delta", "alpha", 20, done=4)   # 4/20 > 0.15: fine
    old("bravo", "india", 10, done=3)   # 3/10 = 0.3 * 1 * 1: broken
    old("india", "bravo", 10, done=4)   # fine
    # The 10-day window keeps a ping sent exactly 10 days ago.
    for t in (NOW - 864000, NOW - 864001, at(2), at(3)):
        ping("delta", "bravo", t)       # 3 counted: broken
    for t in (NOW - 864001, at(2), at(3)):
        ping("delta", "charlie", t)     # 2 counted: intensive care
    old("juliet", "alpha", 2)
    ping("juliet", "alpha", NOW - 864001, 100)  # back, but outside the window
    # A ping back counts, however young: 1/4.
    old("india", "alpha", 3)
    ping("india", "alpha", NOW - 60, 50)
    # Remailers that aren't rows are ignored.
    old("hotel", "alpha", 5)
    old("alpha", "hotel", 5)
    # Not public.
    old("fox", "alpha", 3)
    old("golf", "bravo", 3)
    # echo is dead: 5 broken chains from it, (echo *) at the threshold 5.
    for b in ("alpha", "bravo", "charlie", "delta", "india"):
        old("echo", b, 3)
    ping("echo", "juliet", NOW - 1)     # grace (0+600)*1.5: not counted
    ping("echo", "kilo", NOW)
    # kilo: 5 broken chains to it privately, 3 publicly.
    for a in ("alpha", "bravo", "charlie", "fox", "golf"):
        old(a, "kilo", 3)
    # bravo ends up with 5 broken chains to it privately, 4 publicly.
    return {"now": NOW, "rems": rems, "chainpings": pings,
            "files": {"broken1": "(alpha zulu)\n(* bravo)\n",
                      "broken2": "(juliet *)\n(* lima)\n\n(alpha bravo)\nnot a chain\n(kilo  x)\n"}}


def chain_random_case(seed):
    """The remailers of random_case(1); chain pings between every pair,
    returned with probability rel(A) * rel(B), except for a few pairs that
    lose (almost) everything."""
    d = random_case(1)
    random.seed(seed)
    rels = {"alpha": 0.99, "bravo": 0.80, "charlie": 0.50, "delta": 1.0, "echo": 0.0, "foxtrot": 0.95}
    lats = {"alpha": 600, "bravo": 3000, "charlie": 20000, "delta": 90, "echo": 0, "foxtrot": 400000}
    nicks = sorted(rels)
    bad = {("alpha", "bravo"), ("delta", "alpha"), ("bravo", "delta"), ("delta", "charlie")}
    pings = []
    for a in nicks:
        for b in nicks:
            if a == b or random.random() < 0.1:
                continue
            for _ in range(random.randint(0, 14)):
                t = NOW - random.randint(0, 11 * DAY)
                p = rels[a] * rels[b] * (0.05 if (a, b) in bad else 1)
                lat = None
                if random.random() < p:
                    lat = sum(max(1, int(random.expovariate(1.0 / max(lats[x], 1)))) for x in (a, b))
                    if t + lat >= NOW:
                        lat = None
                pings.append([t, a + "@example.org", b + "@example.org", lat])
    d["chainpings"] = pings
    return d


def compress_cases():
    """[num, list] for compress_broken_chain alone."""
    return [
        [4, ["(a b)", "(c b)"]],              # 2 >= 2: (* b)
        [5, ["(a b)", "(c b)"]],              # 2 < 2.5: kept
        [4, ["(* b)", "(a b)"]],              # (* b) counts 1 + 4
        [2, ["(* b)", "(* c)"]],              # "*" as a left nick: (* *)
        [1, ["(* *)"]],
        [0, ["(a b)", "(c d)"]],              # threshold 0: everything
        [0, []],
        [3, ["(a b)", "(a b)", "(a c)"]],     # duplicates count once
        [3, ["(a b)", "(c b)", "(a d)"]],
        [10, ["((a b))", "x(a b)y", "(a b) (c d)", "(a\tb)", "(a\u000bb)", "(a  b)", "(a b", "", " ", "(a b)\r"]],
        [10, ["(b a)", "(a b)", "(A b)", "(a *)", "(* a)"]],
    ]


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "1"
    if arg.startswith("chain"):
        case = int(arg[5:])
        if case == 1:
            d = chain_edge_case()
        elif case == 2:
            d = chain_random_case(2)
        elif case == 3:
            d = random_case(1)
            d["chainpings"] = []
            d["compress"] = compress_cases()
        else:
            sys.exit("no case %s" % arg)
        json.dump(d, sys.stdout, indent=1)
        return
    case = int(arg)
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
