from pathlib import Path

from safebox.policy import decide, load_rules


def test_policy_file_loads_expected_rules():
    rules = load_rules()

    rule_ids = {rule.id for rule in rules}

    assert rule_ids == {
        "terraform_destroy",
        "kubectl_delete",
        "aws_ec2_terminate",
        "aws_rds_delete",
        "aws_s3_recursive_delete",
        "aws_cloudformation_delete_stack",
    }


def test_policy_rules_have_expected_metadata():
    rules = {rule.id: rule for rule in load_rules()}

    assert rules["terraform_destroy"].severity == "critical"
    assert rules["kubectl_delete"].severity == "high"
    assert rules["aws_ec2_terminate"].action == "block"


def test_s3_rule_requires_recursive_flag():
    rules = {rule.id: rule for rule in load_rules()}

    assert rules["aws_s3_recursive_delete"].requires_any == (
        "--recursive",
        "-r",
    )


def test_safe_command_is_allowed():
    result = decide("terraform plan")
    assert result.allowed is True


def test_terraform_destroy_is_blocked():
    result = decide("terraform destroy")
    assert result.allowed is False
    assert result.rule == "terraform_destroy"
    assert result.severity == "critical"


def test_destroy_with_other_arguments_is_blocked():
    result = decide("terraform -chdir=infra destroy")
    assert result.allowed is False


def test_destroy_with_auto_approve_is_blocked():
    result = decide("terraform destroy -auto-approve")
    assert result.allowed is False


def test_destroy_with_long_auto_approve_is_blocked():
    result = decide("terraform destroy --auto-approve")
    assert result.allowed is False


def test_kubectl_delete_is_blocked():
    result = decide("kubectl delete pod example")
    assert result.allowed is False
    assert result.rule == "kubectl_delete"


def test_kubectl_delete_namespace_is_blocked():
    result = decide("kubectl delete namespace production")
    assert result.allowed is False
    assert result.rule == "kubectl_delete"


def test_aws_ec2_terminate_is_blocked():
    result = decide(
        "aws ec2 terminate-instances --instance-ids i-1234567890abcdef0"
    )
    assert result.allowed is False
    assert result.rule == "aws_ec2_terminate"


def test_aws_rds_delete_is_blocked():
    result = decide(
        "aws rds delete-db-instance --db-instance-identifier production"
    )
    assert result.allowed is False
    assert result.rule == "aws_rds_delete"


def test_aws_s3_recursive_delete_is_blocked():
    result = decide("aws s3 rm s3://production-bucket --recursive")
    assert result.allowed is False
    assert result.rule == "aws_s3_recursive_delete"


def test_aws_s3_short_recursive_flag_is_blocked():
    result = decide("aws s3 rm s3://production-bucket -r")
    assert result.allowed is False
    assert result.rule == "aws_s3_recursive_delete"


def test_aws_s3_without_recursive_flag_is_allowed():
    result = decide("aws s3 rm s3://production-bucket")
    assert result.allowed is True


def test_aws_cloudformation_delete_stack_is_blocked():
    result = decide(
        "aws cloudformation delete-stack --stack-name production"
    )
    assert result.allowed is False
    assert result.rule == "aws_cloudformation_delete_stack"


def test_unparseable_command_is_blocked():
    result = decide('terraform plan "unterminated')
    assert result.allowed is False

def test_custom_policy_can_block_a_command(tmp_path: Path):
    policy_file = tmp_path / "custom-policy.toml"

    policy_file.write_text(
        """
[[rules]]
id = "block_terraform_plan"
description = "Testing custom policy"
action = "block"
severity = "high"
command = ["terraform", "plan"]
""".strip()
    )

    rules = load_rules(policy_file)
    result = decide("terraform plan", rules=rules)

    assert result.allowed is False
    assert result.rule == "block_terraform_plan"
    assert result.severity == "high"


def test_custom_policy_does_not_change_default_policy():
    result = decide("terraform plan")

    assert result.allowed is True
