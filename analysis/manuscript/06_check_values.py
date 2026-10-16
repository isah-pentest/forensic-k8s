"""Step 6. Compare every recomputed value with the value printed in the manuscript.

expected_values.csv lists each number as printed (transcribed from the
manuscript's LaTeX source) and where it appears. A value passes when the
recomputed quantity, rounded to the printed number of decimals, equals the
printed value (percentages are compared after multiplying by 100).
Exit status 0 = all pass.
"""
import csv, json, sys
from decimal import Decimal, ROUND_HALF_UP
from common import OUT

V = json.load(open(f"{OUT}/manuscript_values.json"))
fails, n = [], 0
for row in csv.DictReader(open(__file__.replace("06_check_values.py", "expected_values.csv"))):
    n += 1
    name, printed = row["name"], row["printed"].strip()
    if name not in V:
        fails.append((name, printed, "MISSING", row["location"])); continue
    pct = printed.endswith("%")
    p = printed.rstrip("%")
    dec = len(p.split(".")[1]) if "." in p else 0
    val = float(V[name]) * (100 if pct else 1)
    got = Decimal(repr(val)).quantize(Decimal(1).scaleb(-dec), rounding=ROUND_HALF_UP)
    if Decimal(p) != got:
        fails.append((name, printed, f"{val:.6g}", row["location"]))
with open(f"{OUT}/check_report.txt", "w") as fh:
    fh.write(f"Manuscript value check: {n - len(fails)}/{n} pass\n")
    for f in fails:
        fh.write("FAIL  %-34s printed=%-8s recomputed=%-12s (%s)\n" % f)
print(open(f"{OUT}/check_report.txt").read())
sys.exit(1 if fails else 0)
