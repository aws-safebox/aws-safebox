from safebox.policy import decide


def test_safe_command_is_allowed():
    result = decide("terraform plan")
    assert result.allowed is True


def test_terraform_destroy_is_blocked():
    result = decide("terraform destroy")
    assert result.allowed is False
    assert result.rule == "terraform_destroy"


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


def test_aws_cloudformation_delete_stack_is_blocked():
    result = decide(
        "aws cloudformation delete-stack --stack-name production"
    )
    assert result.allowed is False
    assert result.rule == "aws_cloudformation_delete_stack"


def test_unparseable_command_is_blocked():
    result = decide('terraform plan "unterminated')
    assert result.allowed is False