# Generates a synthetic ping data set for harness.pl (deterministic seed).
import json, random, sys
random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
now = 1792560000 + 12345  # a fixed instant
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
json.dump({"now": now, "rems": rems}, sys.stdout, indent=1)
