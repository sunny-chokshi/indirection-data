"""CryptoBench v2b: within-pair counterparts. Each item renders an existing v2 pair in the
opposite name-visibility form (plain pairs 01-05 -> obscured; obscured pairs 06-10 -> plain).
80 of 90 pairs; 10 pairs with no well-known name to reveal or hide are excluded
(iv06 iv08 iv09 iv10 pr06 pr09 sk10 bc08 bc09 ns07)."""
import snippets_v2, cp_a, cp_b, cp_c
SRC = {p["pid"]: p for p in snippets_v2.PAIRS}
def samples():
    out = []
    for c in cp_a.CP + cp_b.CP + cp_c.CP:
        p = SRC[c["src"]]
        for label, code in (("vuln", c["vuln"]), ("secure", c["secure"])):
            out.append(dict(id=f'{c["src"]}x_{"v" if label == "vuln" else "s"}', pair=c["src"], cwe=p["cwe"],
                            category=p["category"], variant=c["variant"], label=label, code=code))
    return out
