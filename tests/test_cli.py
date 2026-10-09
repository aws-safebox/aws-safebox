from safebox.cli import main


def test_run_safe_command_executes(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "safebox",
            "run",
            'python -c "print(\'cli-test\')"',
        ],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "cli-test" in captured.out


def test_run_blocked_command_does_not_execute(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "safebox",
            "run",
            "terraform destroy",
        ],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "BLOCK" in captured.out
    assert "terraform_destroy" in captured.out


def test_run_preserves_command_failure_exit_code(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "safebox",
            "run",
            'python -c "import sys; sys.exit(7)"',
        ],
    )

    exit_code = main()

    assert exit_code == 7


def test_setup_creates_default_proxies(
    tmp_path,
    monkeypatch,
    capsys,
):
    proxy_dir = tmp_path / "safebox-bin"

    monkeypatch.setattr(
        "sys.argv",
        [
            "safebox",
            "setup",
            "--proxy-dir",
            str(proxy_dir),
        ],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0

    assert (proxy_dir / "terraform").exists()
    assert (proxy_dir / "aws").exists()
    assert (proxy_dir / "kubectl").exists()

    assert "SafeBox proxies created:" in captured.out
    assert str(proxy_dir) in captured.out
    assert "export PATH=" in captured.out
    assert "does not modify your shell configuration" in captured.out
