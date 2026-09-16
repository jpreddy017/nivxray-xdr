#!/usr/bin/env python3
"""Generate ONE fresh, real, physical endpoint event on this Linux box.

P0-3 acceptance requires a post-recovery event that the sensor observes
from /proc, not a seed, replay or DB insert. So this creates a real
executable with a unique name in the watched directory and really runs
it. Everything the platform later shows about it was read from the kernel
by the sensor.
"""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

WATCH = Path(os.environ.get("NIVXFORGE_SENSOR_WATCH",
                            "/var/tmp/nivxforge-watch"))


def main() -> None:
    WATCH.mkdir(parents=True, exist_ok=True)
    name = f"nivx-p03-proof-{int(time.time())}"
    path = WATCH / name
    shutil.copy2("/bin/sleep", path)
    path.chmod(0o755)
    p = subprocess.Popen([str(path), "240"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    print(f"{name} {p.pid}")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
