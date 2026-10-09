import os
import subprocess

from safebox.proxy import (
    DEFAULT_PROXY_COMMANDS,
    create_proxy,
    find_real_executable,
    setup_proxies,
)


def test_create_proxy_creates_executable(tmp_path):
    proxy_path = create_proxy(
        command_name="terraform",
        proxy_dir=tmp_path,
    )

    assert proxy_path == tmp_path / "terraform"
    assert proxy_path.exists()
    assert proxy_path.is_file()

    mode = proxy_path.stat().st_mode
    assert mode & 0o111


def test_proxy_invokes_safebox(tmp_path):
    proxy_path = create_proxy(
        command_name="terraform",
        proxy_dir=tmp_path,
    )

    content = proxy_path.read_text()

    assert "safebox" in content
    assert "terraform" in content


def test_create_aws_proxy(tmp_path):
    proxy_path = create_proxy(
        command_name="aws",
        proxy_dir=tmp_path,
    )

    assert proxy_path == tmp_path / "aws"
    assert proxy_path.exists()


def test_setup_proxies_creates_default_commands(tmp_path):
    result = setup_proxies(
        proxy_dir=tmp_path,
    )

    assert result.proxy_dir == tmp_path
    assert len(result.proxies) == len(DEFAULT_PROXY_COMMANDS)

    for command_name in DEFAULT_PROXY_COMMANDS:
        proxy_path = tmp_path / command_name

        assert proxy_path.exists()
        assert proxy_path.is_file()
        assert proxy_path.stat().st_mode & 0o111


def test_find_real_executable_skips_proxy_dir(tmp_path, monkeypatch):
    proxy_dir = tmp_path / "proxy"
    real_dir = tmp_path / "real"

    proxy_dir.mkdir()
    real_dir.mkdir()

    proxy = proxy_dir / "terraform"
    proxy.write_text("#!/bin/sh\n")
    proxy.chmod(0o755)

    real = real_dir / "terraform"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)

    monkeypatch.setenv(
        "PATH",
        f"{proxy_dir}:{real_dir}",
    )

    resolved = find_real_executable(
        "terraform",
        proxy_dir=proxy_dir,
    )

    assert resolved == real


def test_find_real_executable_returns_none_when_missing(tmp_path, monkeypatch):
    proxy_dir = tmp_path / "proxy"
    proxy_dir.mkdir()

    monkeypatch.setenv(
        "PATH",
        str(proxy_dir),
    )

    resolved = find_real_executable(
        "terraform",
        proxy_dir=proxy_dir,
    )

    assert resolved is None


def test_proxy_blocks_dangerous_command_end_to_end(
    tmp_path,
    monkeypatch,
):
    proxy_dir = tmp_path / "proxy"
    real_dir = tmp_path / "real"

    proxy_dir.mkdir()
    real_dir.mkdir()

    real = real_dir / "terraform"
    real.write_text(
        "#!/bin/sh\n"
        'echo "REAL TERRAFORM EXECUTED: $*"\n'
    )
    real.chmod(0o755)

    create_proxy(
        command_name="terraform",
        proxy_dir=proxy_dir,
    )

    current_path = os.environ.get("PATH", "")

    monkeypatch.setenv(
        "PATH",
        f"{proxy_dir}:{real_dir}:{current_path}",
    )

    result = subprocess.run(
        ["terraform", "destroy"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "BLOCK" in result.stdout
    assert "REAL TERRAFORM EXECUTED" not in result.stdout


def test_proxy_allows_safe_command_end_to_end(
    tmp_path,
    monkeypatch,
):
    proxy_dir = tmp_path / "proxy"
    real_dir = tmp_path / "real"

    proxy_dir.mkdir()
    real_dir.mkdir()

    real = real_dir / "terraform"
    real.write_text(
        "#!/bin/sh\n"
        'echo "REAL TERRAFORM EXECUTED: $*"\n'
    )
    real.chmod(0o755)

    create_proxy(
        command_name="terraform",
        proxy_dir=proxy_dir,
    )

    current_path = os.environ.get("PATH", "")

    monkeypatch.setenv(
        "PATH",
        f"{proxy_dir}:{real_dir}:{current_path}",
    )

    result = subprocess.run(
        ["terraform", "plan"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "REAL TERRAFORM EXECUTED: plan" in result.stdout


def test_proxy_preserves_original_directory_spelling(tmp_path):
    real_proxy_dir = tmp_path / "real-proxy"
    alias_proxy_dir = tmp_path / "alias-proxy"

    real_proxy_dir.mkdir()
    alias_proxy_dir.symlink_to(
        real_proxy_dir,
        target_is_directory=True,
    )

    proxy_path = create_proxy(
        command_name="terraform",
        proxy_dir=alias_proxy_dir,
    )

    content = proxy_path.read_text()

    assert f"proxy_dir={alias_proxy_dir}" in content
    assert f"proxy_dir={real_proxy_dir}" not in content
