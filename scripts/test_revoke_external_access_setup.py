"""Offline tests: the revoke-external-access setups fail when the public seed state is missing."""
import json
import unittest

import verifier_fakes as vf

TASKS = ["aws/revoke-external-access-metrics-collector", "aws/revoke-external-access-subsidiary-workspace",
         "aws/revoke-external-access-trial-integration"]
SETUP = "environment/lifecycle/setup.sh"
ACCOUNT = "123456789012"
TOPIC = "arn:aws:sns:us-east-1:%s:vera2-signals-1" % ACCOUNT
APP = "arn:aws:serverlessrepo:us-east-1:%s:applications/vera2-bridge-1" % ACCOUNT
PUBLIC_TOPIC = {"Version": "2012-10-17", "Statement": [
    {"Sid": "Pub", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "SNS:Subscribe", "Resource": TOPIC}]}
DEFAULT_TOPIC = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "SNS:Subscribe", "Resource": TOPIC,
     "Condition": {"StringEquals": {"AWS:SourceOwner": ACCOUNT}}}]}


def denied(*argv):
    return vf.aws_error(*argv, code="AccessDeniedException", operation="Seed")


def seeding(**overrides):
    steps = {
        "account": vf.aws_rule("sts", "get-caller-identity", stdout=ACCOUNT + "\n"),
        "topic": vf.aws_rule("sns", "create-topic", stdout=TOPIC + "\n"),
        "topic_policy": vf.aws_rule("sns", "set-topic-attributes"),
        "app": vf.aws_rule("serverlessrepo", "create-application", stdout=APP + "\n"),
        "app_policy": vf.aws_rule("serverlessrepo", "put-application-policy"),
        "topic_readback": vf.aws_rule("sns", "get-topic-attributes", stdout=json.dumps(PUBLIC_TOPIC) + "\n"),
        "app_readback": vf.aws_rule("serverlessrepo", "get-application-policy",
                                    stdout=[{"StatementId": "s1", "Principals": ["*"], "Actions": ["Deploy"]}]),
    }
    steps.update(overrides)
    cleanup = [vf.aws_rule("sns", "list-topics"), vf.aws_rule("serverlessrepo", "list-applications")]
    return cleanup + list(steps.values())


FAILURES = {
    "account lookup fails": dict(account=denied("sts", "get-caller-identity")),
    "create-topic fails": dict(topic=denied("sns", "create-topic")),
    "create-topic returns None": dict(topic=vf.aws_rule("sns", "create-topic", stdout="None\n")),
    "topic policy cannot be set": dict(topic_policy=denied("sns", "set-topic-attributes")),
    "create-application fails": dict(app=denied("serverlessrepo", "create-application")),
    "application policy never applies": dict(app_policy=denied("serverlessrepo", "put-application-policy")),
    "topic is not public on read-back": dict(
        topic_readback=vf.aws_rule("sns", "get-topic-attributes", stdout=json.dumps(DEFAULT_TOPIC) + "\n")),
    "application is not public on read-back": dict(
        app_readback=vf.aws_rule("serverlessrepo", "get-application-policy", stdout=[])),
}


class RevokeExternalAccessSetupTests(unittest.TestCase):
    def test_full_success_writes_both_identifiers(self):
        for task in TASKS:
            with self.subTest(task):
                result = vf.run_script(task, SETUP, aws=seeding())
                self.assertEqual(0, result.returncode, result.stderr)
                seed = json.loads(result.files["seed_state.json"])
                self.assertEqual((ACCOUNT, TOPIC, APP),
                                 (seed["account"], seed["sns_topic_arn"], seed["sar_app_id"]))

    def test_incomplete_seeding_fails(self):
        for task in TASKS:
            for name, overrides in FAILURES.items():
                with self.subTest(task=task, case=name):
                    result = vf.run_script(task, SETUP, aws=seeding(**overrides))
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertIn("setup failed", result.stderr)
                    self.assertNotIn("seed_state.json", result.files)


if __name__ == "__main__":
    unittest.main()
