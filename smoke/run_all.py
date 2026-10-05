"""One-shot verification entry point for the ``verify`` service.

Stages, each contributing to the final exit code:

1. unit/integration test suite (``unittest discover``)
2. build confirmation (when run inside the image the image clearly built;
   with ``--docker-build`` the image and compose stack are built on the host)
3. smoke suite against a live gateway: signing, gzip and concurrent
   anti-replay (``smoke.test_smoke``)

Exit status: 0 only when every stage passed; non-zero aggregates failures.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def stage_unit_tests() -> bool:
    print("\n=== stage 1/3: unit & integration tests ===", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
    )
    return proc.returncode == 0


def stage_build_check(do_docker_build: bool) -> bool:
    print("\n=== stage 2/3: build check ===", flush=True)
    if do_docker_build:
        print("[build] docker compose build gateway", flush=True)
        if subprocess.run(["docker", "compose", "build", "gateway"], cwd=ROOT).returncode != 0:
            return False
        print("[build] image built successfully", flush=True)
        return True
    if os.environ.get("RUNNING_IN_IMAGE") == "1":
        marker = Path("/app/app/server.py")
        print(f"[build] executing inside built image (artifact {marker} exists={marker.exists()})", flush=True)
        return marker.exists()
    # Local source run: byte-compile every module as a minimal build sanity check.
    proc = subprocess.run([sys.executable, "-m", "compileall", "-q", "app", "smoke", "tests"], cwd=ROOT)
    print("[build] source compileall passed (use --docker-build to build the image)", flush=True)
    return proc.returncode == 0


def _wait_healthy(url: str, attempts: int = 30, delay: float = 0.5) -> bool:
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except OSError:
            time.sleep(delay)
    return False


def stage_smoke(smoke_url: str, spawn: bool) -> bool:
    print("\n=== stage 3/3: signing / gzip / concurrency anti-replay smoke ===", flush=True)
    proc_server = None
    tmpdir = None
    try:
        if spawn:
            tmpdir = tempfile.TemporaryDirectory()
            port = _free_port()
            env = dict(os.environ)
            env.update(
                {
                    "HOST": "127.0.0.1",
                    "PORT": str(port),
                    "TELEMETRY_DB": f"{tmpdir.name}/nonces.db",
                    "TELEMETRY_KEYS_FILE": str(ROOT / "config" / "keys.json"),
                }
            )
            proc_server = subprocess.Popen(
                [sys.executable, "-m", "app.server"], cwd=ROOT, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            smoke_url = f"http://127.0.0.1:{port}"
            if not _wait_healthy(smoke_url):
                output = proc_server.stdout.read() if proc_server.stdout else ""
                print(f"[smoke] gateway failed to start:\n{output}", flush=True)
                return False
            print(f"[smoke] spawned local gateway on {smoke_url}", flush=True)
        elif not _wait_healthy(smoke_url, attempts=5):
            print(f"[smoke] gateway at {smoke_url} is not healthy", flush=True)
            return False

        from smoke.test_smoke import run as run_smoke

        run_smoke(smoke_url, os.environ.get("TELEMETRY_KEYS_FILE") or str(ROOT / "config" / "keys.json"))
        return True
    except Exception as exc:  # noqa: BLE001 - aggregate any failure into the exit code
        print(f"[smoke] FAILED: {exc}", flush=True)
        return False
    finally:
        if proc_server is not None:
            proc_server.terminate()
            try:
                proc_server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc_server.kill()
        if tmpdir is not None:
            tmpdir.cleanup()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-url", default=os.environ.get("GATEWAY_URL", "http://gateway:8080"))
    parser.add_argument("--spawn", action="store_true", help="spawn a local gateway for the smoke stage")
    parser.add_argument("--docker-build", action="store_true", help="build the docker image as the build stage")
    parser.add_argument("--skip-smoke", action="store_true")
    args = parser.parse_args()

    results = {
        "unit tests": stage_unit_tests(),
        "build": stage_build_check(args.docker_build),
    }
    if not args.skip_smoke:
        results["smoke (sign/gzip/concurrency)"] = stage_smoke(args.smoke_url, args.spawn)

    print("\n=== verification summary ===")
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
