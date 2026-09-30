"""Build the closed fixed-client worker from an explicit operator-trusted source allowlist."""

from __future__ import annotations

import base64
import json
import zlib
from pathlib import Path

TIMING_SCENARIOS = frozenset({'timing_rehearsal', 'timing_unknown', 'timing_wait'})
MODULES = ('__init__.py', 'executor.py', 'outcomes.py', 'fixture_evidence.py',
           'timing_queries.py', 'timing_incidents.py', 'timing_snapshot.py',
           'timing_binding.py', '_timing_rehearsal_worker.py')
DATA = ('notification.json', 'metrics.json', 'logs.jsonl', 'traces.json', 'changes.json')
FILES = MODULES + tuple('timing_data/' + name for name in DATA)
MAX_SOURCE_BYTES = 512 * 1024
MAX_WORKER_BYTES = 64 * 1024

# Only the fixed builder below supplies payload/names. No request selects code or file names.
BOOTSTRAP = '''"""Captured trusted fixed timing client; no native model or security sandbox."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import zlib

payload = PAYLOAD_LITERAL
names = NAMES_LITERAL
if set(os.environ) - {"HOME", "TMPDIR", "LC_ALL", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}:
    raise SystemExit(91)
if len(sys.argv) != 2 or sys.argv[1] not in SCENARIOS_LITERAL:
    raise SystemExit(92)
source = json.loads(zlib.decompress(base64.b64decode(payload)))
if set(source) != set(names):
    raise SystemExit(93)
root = Path(__file__).absolute().parent
bundle = root / "timing_bundle"
bundle.mkdir(mode=0o700)
(bundle / "timing_data").mkdir(mode=0o700)
for name in names:
    entry = source[name]
    raw = entry["data"].encode("utf-8")
    if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise SystemExit(94)
    target = bundle / name
    with target.open("xb") as handle:
        handle.write(raw)
    target.chmod(0o400)
sys.dont_write_bytecode = True
sys.path.insert(0, str(root))
from timing_bundle._timing_rehearsal_worker import main
raise SystemExit(main(sys.argv[1], root))
'''


def build_rehearsal_worker() -> bytes:
    """Freeze only fixed local sources. Result's normal worker digest covers every embedded byte."""
    import hashlib

    root = Path(__file__).parent
    sources = {}
    total = 0
    for name in FILES:
        raw = (root / name).read_bytes()
        total += len(raw)
        if total > MAX_SOURCE_BYTES:
            raise ValueError('fixed rehearsal source capacity exceeded')
        sources[name] = {'data': raw.decode('utf-8'), 'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest()}
    raw = json.dumps(sources, sort_keys=True, separators=(',', ':')).encode()
    payload = base64.b64encode(zlib.compress(raw, level=9)).decode('ascii')
    worker = (BOOTSTRAP.replace('PAYLOAD_LITERAL', repr(payload))
              .replace('NAMES_LITERAL', repr(FILES))
              .replace('SCENARIOS_LITERAL', repr(tuple(sorted(TIMING_SCENARIOS))))).encode()
    if len(worker) > MAX_WORKER_BYTES:
        raise ValueError('fixed rehearsal worker capacity exceeded')
    return worker
