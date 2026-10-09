from safebox.executor import execute


def test_safe_command_executes():
    result = execute("python -c \"print('safebox-test')\"")

    assert result.allowed is True
    assert result.executed is True
    assert result.returncode == 0
    assert result.stdout.strip() == "safebox-test"


def test_blocked_command_does_not_execute():
    result = execute("terraform destroy")

    assert result.allowed is False
    assert result.executed is False
    assert result.rule == "terraform_destroy"


def test_safe_command_return_code_is_preserved():
    result = execute(
        "python -c \"import sys; sys.exit(7)\""
    )

    assert result.allowed is True
    assert result.executed is True
    assert result.returncode == 7


def test_safe_command_stderr_is_captured():
    result = execute(
        "python -c \"import sys; print('error-test', file=sys.stderr)\""
    )

    assert result.allowed is True
    assert result.executed is True
    assert result.returncode == 0
    assert result.stderr.strip() == "error-test"


def test_unsupported_shell_construct_does_not_execute():
    result = execute(
        "terraform plan | terraform destroy"
    )

    assert result.allowed is False
    assert result.executed is False
    assert result.rule == "unsupported_shell"