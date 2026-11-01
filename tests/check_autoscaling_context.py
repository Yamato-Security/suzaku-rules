"""Check Auto Scaling rule pairs with synthetic events and a Suzaku executable.

Usage: python tests/check_autoscaling_context.py --suzaku /path/to/suzaku
Only local synthetic JSON is scanned; no AWS requests are made.
"""

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suzaku", required=True, type=Path)
    executable = parser.parse_args().suzaku.resolve()
    root = Path(__file__).resolve().parents[1]
    pairs = [
        (
            "RunInstances",
            "run_instances",
            "5baf3a88-3eda-596d-bffb-64adbda961ae",
            "e2cbdc03-8902-4fa1-b3ec-d1cf0c414e59",
        ),
        (
            "TerminateInstances",
            "terminate_instances",
            "24497139-870a-5c3e-8a6a-56e14cf9de6e",
            "73c92550-1d4a-448d-a751-e53e04122c20",
        ),
    ]
    arn = (
        "arn:aws:iam::111122223333:role/aws-service-role/"
        "autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    )
    issuer = "userIdentity.sessionContext.sessionIssuer"
    missing = object()
    cases = [
        ("default", {}, "informational"),
        ("suffix", {issuer + ".arn": arn + "_example-1"}, "informational"),
        (
            "suffix_with_underscore",
            {issuer + ".arn": arn + "_example_group"},
            "informational",
        ),
        ("suffix_punctuation", {issuer + ".arn": arn + "_a+=,.@-"}, "informational"),
        (
            "govcloud",
            {issuer + ".arn": arn.replace("arn:aws:", "arn:aws-us-gov:")},
            "informational",
        ),
        (
            "china",
            {issuer + ".arn": arn.replace("arn:aws:", "arn:aws-cn:")},
            "informational",
        ),
        ("human", {"userIdentity": {"type": "IAMUser"}}, "medium"),
        ("no_identity", {"userIdentity": missing}, "medium"),
        ("null_identity", {"userIdentity": None}, "medium"),
        ("no_identity_type", {"userIdentity.type": missing}, "medium"),
        ("wrong_identity_type", {"userIdentity.type": "AWSService"}, "medium"),
        ("no_invoker", {"userIdentity.invokedBy": missing}, "medium"),
        ("null_invoker", {"userIdentity.invokedBy": None}, "medium"),
        (
            "other_invoker",
            {"userIdentity.invokedBy": "eks-nodegroup.amazonaws.com"},
            "medium",
        ),
        ("no_session_context", {"userIdentity.sessionContext": missing}, "medium"),
        ("no_issuer", {issuer: missing}, "medium"),
        ("no_issuer_type", {issuer + ".type": missing}, "medium"),
        ("wrong_issuer_type", {issuer + ".type": "User"}, "medium"),
        ("no_arn", {issuer + ".arn": missing}, "medium"),
        ("null_arn", {issuer + ".arn": None}, "medium"),
        (
            "arbitrary_role",
            {
                issuer + ".arn": arn.replace(
                    "AWSServiceRoleForAutoScaling", "CustomRole"
                )
            },
            "medium",
        ),
        ("lookalike_role", {issuer + ".arn": arn + "Extra"}, "medium"),
        ("empty_suffix", {issuer + ".arn": arn + "_"}, "medium"),
        ("path_in_suffix", {issuer + ".arn": arn + "_example/other"}, "medium"),
        ("invalid_suffix", {issuer + ".arn": arn + "_example!"}, "medium"),
        (
            "wrong_path",
            {issuer + ".arn": arn.replace("aws-service-role/", "service-role/")},
            "medium",
        ),
        (
            "lookalike_service",
            {
                issuer + ".arn": arn.replace(
                    "autoscaling.amazonaws.com", "autoscalingXamazonawsXcom"
                )
            },
            "medium",
        ),
        (
            "invalid_account",
            {issuer + ".arn": arn.replace("111122223333", "123")},
            "medium",
        ),
        ("prefix", {issuer + ".arn": "prefix" + arn}, "medium"),
        (
            "wrong_resource_type",
            {issuer + ".arn": arn.replace(":role/", ":user/")},
            "medium",
        ),
        ("denied", {"errorCode": "AccessDenied"}, None),
        ("dry_run", {"errorCode": "Client.DryRunOperation"}, None),
        ("error_message", {"errorMessage": "Request failed"}, None),
        ("null_error_code", {"errorCode": None}, None),
        ("null_error_message", {"errorMessage": None}, None),
        (
            "outside_denied",
            {"userIdentity": missing, "errorCode": "AccessDenied"},
            None,
        ),
        (
            "outside_error_message",
            {"userIdentity": missing, "errorMessage": "Request failed"},
            None,
        ),
        ("other_operation", {"eventName": "DescribeInstances"}, None),
        ("other_service", {"eventSource": "ssm.amazonaws.com"}, None),
    ]
    events = []
    expected = {}
    for operation, _, outside_id, service_id in pairs:
        for name, changes, level in cases:
            event = {
                "eventID": operation + "_" + name,
                "eventTime": "2024-01-01T00:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": operation,
                "awsRegion": "us-east-1",
                "userIdentity": {
                    "type": "AssumedRole",
                    "invokedBy": "autoscaling.amazonaws.com",
                    "sessionContext": {"sessionIssuer": {"type": "Role", "arn": arn}},
                },
            }
            for path, value in changes.items():
                parts = path.split(".")
                parent = event
                for part in parts[:-1]:
                    parent = parent[part]
                if value is missing:
                    parent.pop(parts[-1])
                else:
                    parent[parts[-1]] = copy.deepcopy(value)
            events.append(event)
            expected[event["eventID"]] = (
                []
                if level is None
                else [(service_id if level == "informational" else outside_id, level)]
            )

    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory)
        fixture = scratch / "events.json"
        fixture.write_text(json.dumps({"Records": events}), encoding="utf-8")
        actual = {name: [] for name in expected}
        for _, filename, _, _ in pairs:
            for suffix in ["", "_autoscaling"]:
                rule = f"aws_cloudtrail_{filename}{suffix}.yml"
                output = scratch / (rule + ".jsonl")
                subprocess.run(
                    [
                        str(executable),
                        "aws-ct-timeline",
                        "-f",
                        str(fixture),
                        "-r",
                        str(root / "suzaku/aws/cloudtrail" / rule),
                        "-o",
                        str(output),
                        "-t",
                        "jsonl",
                        "-q",
                        "-K",
                        "-N",
                    ],
                    cwd=executable.parent,
                    check=True,
                    capture_output=True,
                )
                for line in output.read_text(encoding="utf-8").splitlines():
                    hit = json.loads(line)
                    actual[hit["EventID"]].append((hit["RuleID"], hit["Level"]))
        for name, matches in expected.items():
            if actual[name] != matches:
                raise AssertionError(f"{name}: expected {matches}, got {actual[name]}")
    print(
        f"Passed {len(events)} synthetic controls: correct rule/severity, no overlaps or gaps."
    )


if __name__ == "__main__":
    main()
