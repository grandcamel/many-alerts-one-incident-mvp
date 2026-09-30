"""Temporary, synthetic TLS material for the isolated loopback harness.

Nothing is installed into system trust. All keys are test-only and remain in the
caller-owned temporary directory. This is not deployment CA tooling.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass(frozen=True)
class FixtureCertificates:
    ca_cert: Path
    server_cert: Path
    server_key: Path
    expired_cert: Path
    wrong_hostname_cert: Path
    wrong_ca_cert: Path


def create_certificates(directory: Path) -> FixtureCertificates:
    """Create short-lived certificates in an empty temporary directory.

    OpenSSL is an explicit fixture prerequisite; an unavailable executable fails
    visibly rather than silently skipping TLS validation. Existing files are
    never overwritten. The caller owns cleanup, including after a generation error.
    """
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("fixture certificate directory must not be a symlink")
    directory.mkdir(mode=0o700, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError("fixture certificate directory must be empty")
    directory.chmod(0o700)
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("OpenSSL is required for local TLS fixtures")
    directory = directory.resolve()

    def run(*arguments: str) -> None:
        try:
            completed = subprocess.run(
                [executable, *arguments], cwd=directory, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10,
                check=False, umask=0o077,
                env={"PATH": os.defpath, "LC_ALL": "C", "OPENSSL_CONF": os.devnull},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("OpenSSL fixture generation failed") from exc
        if completed.returncode or len(completed.stderr) > 65536:
            raise RuntimeError("OpenSSL fixture generation failed")

    for name, subject in (("ca", "MAOI local fixture CA"),
                          ("wrong-ca", "MAOI unrelated fixture CA")):
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", name + ".key", "-out", name + ".pem", "-subj", "/CN=" + subject,
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key",
        "-out", "server.csr", "-subj", "/CN=localhost")
    (directory / "issued").mkdir(mode=0o700)
    (directory / "index.txt").write_text("")
    (directory / "serial").write_text("1000\n")
    (directory / "ca.cnf").write_text("""[ca]
default_ca = fixture_ca
[fixture_ca]
database = index.txt
serial = serial
new_certs_dir = issued
certificate = ca.pem
private_key = ca.key
default_md = sha256
default_days = 1
policy = fixture_policy
unique_subject = no
x509_extensions = fixture_server
[fixture_policy]
commonName = supplied
[fixture_server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
[wrong_hostname]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:wrong.invalid
""")
    now = datetime.now(UTC)
    valid_start = (now - timedelta(minutes=5)).strftime("%Y%m%d%H%M%SZ")
    valid_end = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%SZ")
    for name, start, end, extension in (
        ("server", valid_start, valid_end, "fixture_server"),
        ("expired", "20200101000000Z", "20200102000000Z", "fixture_server"),
        ("wrong-hostname", valid_start, valid_end, "wrong_hostname"),
    ):
        run("ca", "-batch", "-notext", "-config", "ca.cnf", "-in", "server.csr",
            "-out", name + ".pem", "-startdate", start, "-enddate", end,
            "-extensions", extension)
    # Key files already inherit 0600 from the child umask; assert the final state
    # explicitly so fixture use never depends on the parent process's umask.
    for name in ("ca.key", "wrong-ca.key", "server.key"):
        (directory / name).chmod(0o600)
    return FixtureCertificates(
        directory / "ca.pem", directory / "server.pem", directory / "server.key",
        directory / "expired.pem", directory / "wrong-hostname.pem",
        directory / "wrong-ca.pem",
    )
