"""Fixed trusted process fixtures. Launched with isolated Python, never a shell."""

import json
import os
import signal
import sys
import time


def emit(payload):
    print(json.dumps(payload), flush=True)


def main():
    signal.signal(signal.SIGINT, signal.default_int_handler)
    scenario = sys.argv[1]
    # Test the actual inherited environment without printing its values.
    allowed = {"HOME", "TMPDIR", "LC_ALL", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    if set(os.environ) - allowed:
        return 91
    emit({"type": "assistant", "message": {"model": "fixture-only", "content": []}})
    if scenario == "malformed":
        print("not JSON", flush=True)
    elif scenario == "stderr_noise":
        os.write(2, b"stderr-is-not-json\n")
    elif scenario == "stderr_json":
        os.write(2, b'{"channel":"stderr"}\n')
    elif scenario == "flood":
        while True:
            os.write(2, b"x" * 8192)
    elif scenario == "oversized_line":
        os.write(1, b"x" * 70000)
    elif scenario in ("silence", "ignore_interrupt"):
        if scenario == "ignore_interrupt":
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        while True:
            time.sleep(0.05)
    elif scenario in ("held_pipe", "held_pipe_ignore", "closed_pipes_alive"):
        pid = os.fork()
        if pid == 0:
            if scenario in ("held_pipe_ignore", "closed_pipes_alive"):
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            else:
                signal.signal(signal.SIGINT, lambda *_: os._exit(0))
            if scenario == "closed_pipes_alive":
                os.close(1)
                os.close(2)
            # A final backstop prevents a fixture becoming indefinite if its supervisor dies.
            signal.alarm(10)
            while True:
                time.sleep(0.05)
        # Give the child time to install its handler before the parent closes.
        time.sleep(0.05)
    result = {"type": "result", "subtype": "success", "is_error": False}
    if scenario == "result_error":
        result["is_error"] = True
    emit(result)
    if scenario == "duplicate":
        emit(result)
    return 7 if scenario == "nonzero" else 0


if __name__ == "__main__":
    raise SystemExit(main())
