"""Offline tests: the revoke-external-access graders raise on unreadable policies instead of passing."""
import json
import unittest

import verifier_fakes as vf

TASKS = ["aws/revoke-external-access-metrics-collector", "aws/revoke-external-access-subsidiary-workspace",
         "aws/revoke-external-access-trial-integration"]
ACCOUNT = "123456789012"
TOPIC = "arn:aws:sns:us-east-1:%s:vera2-signals-1" % ACCOUNT
APP = "arn:aws:serverlessrepo:us-east-1:%s:applications/vera2-bridge-1" % ACCOUNT
SEED = {"region": "us-east-1", "account": ACCOUNT, "sns_topic_arn": TOPIC, "sar_app_id": APP}


def topic_policy(principal):
    return {"Attributes": {"Policy": json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "SNS:Subscribe", "Resource": TOPIC}]})}}


PUBLIC_TOPIC, OWNER_TOPIC = topic_policy("*"), topic_policy(ACCOUNT)
PUBLIC_APP, PRIVATE_APP = {"Statements": [{"Principals": ["*"], "Actions": ["Deploy"]}]}, {"Statements": []}
CASES = [
    ("both locked down", OWNER_TOPIC, PRIVATE_APP, vf.PASS),
    ("both still public", PUBLIC_TOPIC, PUBLIC_APP, vf.FAIL),
    ("application still public", OWNER_TOPIC, PUBLIC_APP, vf.FAIL),
    ("both deleted", vf.client_error("NotFound", "GetTopicAttributes"),
     vf.client_error("NotFoundException", "GetApplicationPolicy"), vf.PASS),
    ("application policy read denied", OWNER_TOPIC,
     vf.client_error("AccessDeniedException", "GetApplicationPolicy"), vf.ERROR),
    ("topic read throttled", vf.client_error("Throttling", "GetTopicAttributes"), PRIVATE_APP, vf.ERROR),
    ("topic policy is malformed", {"Attributes": {"Policy": "{not json"}}, PRIVATE_APP, vf.ERROR),
]


def grade(task, topic_read=None, app_read=None, seed=SEED):
    sns, sar = vf.StrictClient("sns"), vf.StrictClient("serverlessrepo")
    if topic_read is not None:
        sns = vf.StrictClient("sns", get_topic_attributes=topic_read)
    if app_read is not None:
        sar = vf.StrictClient("serverlessrepo", get_application_policy=app_read)
    return vf.run_grader(task, seed=seed, clients={"sns": sns, "serverlessrepo": sar})


class RevokeExternalAccessVerifierTests(unittest.TestCase):
    def test_policy_states(self):
        for task in TASKS:
            for name, topic_read, app_read, verdict in CASES:
                with self.subTest(task=task, case=name):
                    result = grade(task, topic_read, app_read)
                    self.assertEqual(verdict, result.verdict, result.stderr)
                    if name == "application still public":
                        self.assertIn("Still public: SAR application", result.stderr)

    def test_seed_without_identifiers_is_an_evaluation_error(self):
        for task in TASKS:
            with self.subTest(task):
                result = grade(task, seed={**SEED, "sns_topic_arn": "", "sar_app_id": ""})
                self.assertEqual(vf.ERROR, result.verdict, result.stderr)


if __name__ == "__main__":
    unittest.main()
