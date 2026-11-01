"""Run synthetic snapshot-rule regression checks against a Suzaku executable.

Usage: python tests/check_snapshot_backup_context.py --suzaku /path/to/suzaku
Only local synthetic JSON is scanned; no AWS requests or commands are executed.
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
    args = parser.parse_args()
    executable = args.suzaku.resolve()
    root = Path(__file__).resolve().parents[1]
    outside = "1f743dbe-94c8-506d-af05-bf1be563d466"
    backup = "232909a5-3301-41b7-9e56-7af2c587cecc"
    missing = object()
    base = {
        "eventTime": "2024-01-01T00:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "CreateSnapshot",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "type": "AssumedRole",
            "invokedBy": "backup.amazonaws.com",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "arn": "arn:aws:iam::111122223333:role/service-role/AWSBackupDefaultServiceRole",
                }
            },
        },
    }
    issuer = "userIdentity.sessionContext.sessionIssuer"
    cases = [
        ("default_backup", {}, backup),
        (
            "govcloud",
            {
                issuer
                + ".arn": "arn:aws-us-gov:iam::444455556666:role/service-role/AWSBackupDefaultServiceRole"
            },
            backup,
        ),
        (
            "china",
            {
                issuer
                + ".arn": "arn:aws-cn:iam::777788889999:role/service-role/AWSBackupDefaultServiceRole"
            },
            backup,
        ),
        (
            "human",
            {
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::111122223333:user/example",
                }
            },
            outside,
        ),
        ("no_identity", {"userIdentity": missing}, outside),
        ("null_identity", {"userIdentity": None}, outside),
        ("no_invoker", {"userIdentity.invokedBy": missing}, outside),
        ("other_invoker", {"userIdentity.invokedBy": "ec2.amazonaws.com"}, outside),
        ("no_identity_type", {"userIdentity.type": missing}, outside),
        ("wrong_identity_type", {"userIdentity.type": "IAMUser"}, outside),
        ("no_session_context", {"userIdentity.sessionContext": missing}, outside),
        ("no_issuer", {issuer: missing}, outside),
        ("no_issuer_type", {issuer + ".type": missing}, outside),
        ("wrong_issuer_type", {issuer + ".type": "User"}, outside),
        ("no_issuer_arn", {issuer + ".arn": missing}, outside),
        (
            "custom_backup_role",
            {
                issuer
                + ".arn": "arn:aws:iam::111122223333:role/service-role/CustomBackupRole"
            },
            outside,
        ),
        (
            "lookalike_role",
            {
                issuer
                + ".arn": "arn:aws:iam::111122223333:role/service-role/AWSBackupDefaultServiceRoleExtra"
            },
            outside,
        ),
        (
            "wrong_role_path",
            {
                issuer
                + ".arn": "arn:aws:iam::111122223333:role/other/AWSBackupDefaultServiceRole"
            },
            outside,
        ),
        (
            "malformed_arn",
            {
                issuer
                + ".arn": "not-an-arn:role/service-role/AWSBackupDefaultServiceRole"
            },
            outside,
        ),
        (
            "invalid_account",
            {
                issuer
                + ".arn": "arn:aws:iam::123:role/service-role/AWSBackupDefaultServiceRole"
            },
            outside,
        ),
        ("backup_denied", {"errorCode": "AccessDenied"}, None),
        ("backup_error_message", {"errorMessage": "Request failed"}, None),
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
        ("other_operation", {"eventName": "DeleteSnapshot"}, None),
        ("other_service", {"eventSource": "ssm.amazonaws.com"}, None),
    ]
    events = []
    expected = {}
    for name, changes, rule_id in cases:
        event = copy.deepcopy(base)
        event["eventID"] = name
        for path, value in changes.items():
            parts = path.split(".")
            parent = event
            for part in parts[:-1]:
                parent = parent[part]
            if value is missing:
                parent.pop(parts[-1])
            else:
                parent[parts[-1]] = value
        events.append(event)
        expected[name] = (
            []
            if rule_id is None
            else [(rule_id, "informational" if rule_id == backup else "medium")]
        )

    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory)
        fixture = scratch / "events.json"
        fixture.write_text(json.dumps({"Records": events}), encoding="utf-8")
        actual = {name: [] for name in expected}
        for filename in [
            "aws_cloudtrail_create_snapshot.yml",
            "aws_cloudtrail_create_snapshot_aws_backup.yml",
        ]:
            output = scratch / (filename + ".jsonl")
            subprocess.run(
                [
                    str(executable),
                    "aws-ct-timeline",
                    "-f",
                    str(fixture),
                    "-r",
                    str(root / "suzaku/aws/cloudtrail" / filename),
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
        f"Passed {len(cases)} synthetic controls: correct severity, no overlaps, no dropped accepted events."
    )


if __name__ == "__main__":
    main()
