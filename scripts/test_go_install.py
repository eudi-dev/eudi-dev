#!/usr/bin/env python3
"""Install a v3 release from a local Go proxy without publishing a tag."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    root = Path(__file__).resolve().parent.parent
    module = "github.com/eudi-dev/eudi-dev/v3"
    version = "v3.0.0"
    files = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=root
    ).decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="eudi-go-install-") as directory:
        work = Path(directory)
        proxy = work / "proxy"
        versions = proxy / module / "@v"
        versions.mkdir(parents=True)
        (versions / "list").write_text(version + "\n")
        (versions / f"{version}.info").write_text(json.dumps({
            "Version": version, "Time": "2026-01-01T00:00:00Z",
        }))
        (versions / f"{version}.mod").write_bytes((root / "go.mod").read_bytes())
        with zipfile.ZipFile(versions / f"{version}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            for name in files:
                if name and (root / name).is_file():
                    archive.write(root / name, f"{module}@{version}/{name}")

        env = os.environ.copy()
        env.update({
            "GOBIN": str(work / "bin"),
            "GOMODCACHE": str(work / "modcache"),
            "GOPROXY": proxy.as_uri() + ",https://proxy.golang.org",
            "GONOSUMDB": module,
            "GONOPROXY": "none",
            "GOWORK": "off",
            "GOFLAGS": "",
        })
        for requested in (version, "latest"):
            subprocess.run(
                ["go", "install", f"{module}@{requested}"],
                cwd=work, env=env, check=True,
            )
            output = subprocess.check_output(
                [str(work / "bin" / "eudi-dev"), "version"], text=True, env=env,
            ).strip()
            if output != f"eudi {version} (eudi-dev)":
                raise RuntimeError(f"unexpected installed version: {output}")
            print(f"Installed {module}@{requested}: {output}", flush=True)


if __name__ == "__main__":
    main()
