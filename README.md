# AWS SafeBox

**Local safety guardrails for AI agents and AI-assisted infrastructure work.**

AWS SafeBox puts a deterministic policy layer between an AI coding agent and
infrastructure tools such as Terraform and the AWS CLI.

The goal is simple:

> Before an AI agent can execute a dangerous infrastructure command, make it
> pass through a safety policy first.

SafeBox can allow normal read and planning operations while blocking known
destructive commands before they reach the real executable.

## Why SafeBox?

AI coding agents are increasingly capable of running shell commands and
operating infrastructure directly.

That creates a new failure mode: an agent can make a technically valid but
destructive infrastructure decision.

Examples include:

```text
terraform destroy
kubectl delete ...
aws ec2 terminate-instances ...
aws rds delete-db-instance ...
aws s3 rm ... --recursive
aws cloudformation delete-stack ...
```

SafeBox adds a deterministic enforcement layer in front of those tools.

It does not ask an AI model whether a command looks safe. The decision is made
by explicit local policy.

## How it works

Without SafeBox:

```text
AI agent
   |
   v
terraform / aws / kubectl
   |
   v
Infrastructure
```

With SafeBox:

```text
AI agent
   |
   v
SafeBox executable proxy
   |
   v
Policy engine
   |
   +---- BLOCK ----> command never executes
   |
   +---- ALLOW
          |
          v
   real executable
          |
          v
   Infrastructure
```

The proxy can sit earlier in `PATH` than the real infrastructure executable.

For example, when `terraform` is proxied:

```text
terraform plan
```

can be allowed through to the real Terraform binary, while:

```text
terraform destroy
```

can be stopped by SafeBox before Terraform executes it.

## Current Community Edition

SafeBox 0.1.0 currently provides:

- deterministic TOML-based policy rules
- command normalization
- destructive-command detection
- compound-command evaluation
- fail-closed handling for unsupported shell syntax
- policy-enforced command execution
- executable proxy support
- custom policy files
- packaged CLI entry point
- automated test coverage

The default policy currently blocks:

| Tool | Dangerous operation |
| --- | --- |
| Terraform | `terraform destroy` |
| Kubernetes | `kubectl delete` |
| AWS EC2 | `aws ec2 terminate-instances` |
| AWS RDS | `aws rds delete-db-instance` |
| AWS S3 | recursive `aws s3 rm` |
| AWS CloudFormation | `aws cloudformation delete-stack` |

Safe operations such as Terraform planning and common AWS read operations are
not blocked by these rules.

## Requirements

- Python 3.11+
- macOS (currently tested)
- Git for development installation
- the infrastructure tools you want SafeBox to protect

The current proxy implementation is POSIX-oriented and is expected to work on
Linux, but Community Edition 0.1.0 has not yet been manually verified on Linux.

SafeBox itself does not require AWS credentials merely to evaluate commands.

## Installation for development

Clone the repository and create a virtual environment:

```bash
git clone <repository-url>
cd aws-safebox-mvp

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -U pip
python -m pip install -e ".[dev]"
```

Verify the installation:

```bash
safebox --help
```

Run the test suite:

```bash
python -m pytest -q
```

## Quick start

### Check a command without executing it

```bash
safebox check "terraform plan"
```

Expected result:

```text
ALLOW: Command allowed by policy.
```

Now check a destructive command:

```bash
safebox check "terraform destroy"
```

Expected result:

```text
BLOCK: Blocked by policy rule: terraform_destroy
```

Checking a command does not execute it.

## Policy-enforced execution

SafeBox can also evaluate a command and execute it only when policy allows it.

Example:

```bash
safebox run "terraform plan"
```

SafeBox evaluates the command first. If allowed, it invokes the executable
without using a shell.

A blocked command:

```bash
safebox run "terraform destroy"
```

returns:

```text
BLOCK: Blocked by policy rule: terraform_destroy
```

and Terraform is not executed.

## Executable proxy enforcement

SafeBox also contains executable-proxy support.

The intended enforcement model is:

```text
PATH
 |
 +-- SafeBox proxy directory
 |
 +-- real Terraform / AWS CLI / kubectl
```

When a protected command is invoked normally, the proxy sends it through the
SafeBox policy engine. If allowed, SafeBox invokes the real executable using a
PATH with the proxy directory removed.

This allows software that simply runs:

```bash
terraform plan
```

to pass through SafeBox without changing the command to:

```bash
safebox run "terraform plan"
```

### Set up executable proxies

Create persistent SafeBox proxies with `safebox setup`.

By default, SafeBox creates proxies for `terraform`, `aws`, and `kubectl` in
`~/.safebox/bin`.

SafeBox deliberately does not modify your shell configuration automatically.
After setup, add the proxy directory to the front of PATH:

    export PATH="$HOME/.safebox/bin:$PATH"

You can then use the protected tools normally. For example:

    terraform plan
    terraform destroy

Commands allowed by policy are passed to the real executable. Blocked commands
are stopped before the real executable runs.

To make the PATH change persistent, add the same export command to the
appropriate shell configuration file for your environment.

To use a different proxy directory:

    safebox setup --proxy-dir /path/to/proxy-directory

## Custom policies

SafeBox policies are TOML rules.

Example:

```toml
[[rules]]
id = "terraform_destroy"
description = "Destroy Terraform-managed infrastructure"
action = "block"
severity = "critical"
command = ["terraform", "destroy"]
```

Rules can also require command arguments.

Example:

```toml
[[rules]]
id = "aws_s3_recursive_delete"
description = "Recursively delete S3 objects"
action = "block"
severity = "critical"
command = ["aws", "s3", "rm"]
requires_any = ["--recursive", "-r"]
```

A custom policy file can be supplied with:

```bash
safebox check "terraform destroy" --policy /path/to/policy.toml
```

or:

```bash
safebox run "terraform destroy" --policy /path/to/policy.toml
```

## Fail-closed behavior

SafeBox intentionally blocks command forms it cannot safely evaluate.

Unsupported shell constructs include forms such as:

```text
|
&
$()
`...`
```

SafeBox also evaluates supported compound commands separated by operators such
as:

```text
&&
||
;
```

The design principle is:

> SafeBox either understands a command sufficiently to evaluate it, or it
> blocks it.

## Security model and limitations

SafeBox Community Edition is a **local guardrail**, not a hardened security
sandbox.

The executable proxy improves enforcement for software and AI agents that
resolve infrastructure tools through `PATH`, but it is not an unbypassable
security boundary.

For example, a process capable of deliberately locating and invoking the real
executable by absolute path may bypass a PATH-based proxy.

SafeBox also does not currently:

- provide OS-level process isolation
- replace IAM least privilege
- replace AWS Organizations SCPs
- inspect Terraform plans semantically
- determine production versus non-production environments
- calculate infrastructure blast radius
- guarantee protection from every possible destructive command
- prevent a privileged process from intentionally bypassing local controls

SafeBox should therefore be used as an additional safety layer, not as a
replacement for AWS security controls, IAM, backups, review processes, or
environment isolation.

## Project direction

The Community Edition focuses on deterministic local command guardrails.

Potential future capabilities include deeper AWS-aware protections such as:

- AWS account and profile awareness
- production/non-production policies
- IAM privilege awareness
- Terraform plan inspection
- RDS deletion-protection checks
- S3 data-destruction safeguards
- CloudFormation protections
- EKS-aware policies
- blast-radius analysis
- cost-impact awareness

These capabilities are not part of the current Community Edition unless
explicitly documented as released.

## Development

Run all tests:

```bash
python -m pytest -q
```

Current development baseline:

```text
59 tests passing
```

## License

AWS SafeBox Community Edition is released under the MIT License.

See `LICENSE` for details.

## Disclaimer

AWS SafeBox is an independent project and is not affiliated with, endorsed by,
or sponsored by Amazon Web Services.

AWS and related service names are trademarks of their respective owners.
