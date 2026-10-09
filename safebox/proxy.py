from __future__ import annotations

import os
import shlex
from pathlib import Path


def find_real_executable(
    command_name: str,
    proxy_dir: Path,
) -> Path | None:
    proxy_dir_resolved = proxy_dir.resolve()

    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue

        directory_path = Path(directory)

        try:
            if directory_path.resolve() == proxy_dir_resolved:
                continue
        except OSError:
            pass

        candidate = directory_path / command_name

        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    return None


def create_proxy(
    command_name: str,
    proxy_dir: Path,
) -> Path:
    proxy_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    proxy_path = proxy_dir / command_name

    quoted_command = shlex.quote(command_name)
    quoted_proxy_dir = shlex.quote(str(proxy_dir))

    script = f"""#!/bin/sh
command_string={quoted_command}
proxy_dir={quoted_proxy_dir}

for arg in "$@"; do
    command_string="$command_string $(printf '%s' "$arg" | sed "s/'/'\\\\\\\\''/g")"
done

clean_path=""

old_ifs="$IFS"
IFS=:

for directory in $PATH; do
    if [ "$directory" != "$proxy_dir" ]; then
        if [ -z "$clean_path" ]; then
            clean_path="$directory"
        else
            clean_path="$clean_path:$directory"
        fi
    fi
done

IFS="$old_ifs"

PATH="$clean_path" exec safebox run "$command_string"
"""

    proxy_path.write_text(script)
    proxy_path.chmod(0o755)

    return proxy_path
