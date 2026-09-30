"""Total the displayed Run costs in Receiver logs fed on stdin.

    docker compose logs --no-log-prefix demo | python3 -m grafana_jsm_sandbox.run_costs

Only log_formatter's result lines with costs are counted. Failed Runs and results
without a cost are not accounted for here; doctor --with-model runs outside the
Receiver and must be added separately. This is an estimate, not a billing total.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Iterator
from decimal import Decimal

from grafana_jsm_sandbox.log_formatter import RESULT

RESULT_COST = re.compile(rf"{re.escape(RESULT)}\s+[^\n]*, \$(\d+\.\d{{4}})\s*$")


def cost_lines(lines: Iterable[str]) -> Iterator[str]:
    """Each priced result as logged, followed by the sum of its displayed dollar cost."""
    total = Decimal(0)
    for line in lines:
        match = RESULT_COST.search(line)
        if match is None:
            continue
        total += Decimal(match[1])
        yield line.rstrip("\r\n")
    yield f"Total: ${total:.4f} (Receiver result lines only)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    for line in cost_lines(sys.stdin):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
