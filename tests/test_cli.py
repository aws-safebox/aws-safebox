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