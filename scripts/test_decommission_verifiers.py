"""Offline tests: the decommission graders treat a failed read as an error, not as a deletion."""
import unittest

import verifier_fakes as vf

PRIMARY, SECONDARY = "us-east-1", "us-west-2"
REGIONS = {"primary_region": PRIMARY, "secondary_region": SECONDARY}
ANALYTICS, PIPELINE, EVENTS = "aaq-7c21", "adt-1a2b", "aeb-" + PRIMARY


def listing(region, *args, stdout=""):
    return vf.aws_rule(*args, "--output", "json", "--region", region, stdout=stdout)


def failing(region, *args, code="AccessDeniedException"):
    return vf.aws_error(*args, "--output", "json", "--region", region, code=code, operation="Read")


def analytics_inventory(region):
    return [listing(region, "athena", "list-work-groups", stdout={"WorkGroups": [{"Name": "primary"}]}),
            listing(region, "secretsmanager", "list-secrets", stdout={"SecretList": []}),
            listing(region, "ssm", "describe-parameters", stdout={"Parameters": []}),
            listing(region, "sqs", "list-queues", "--queue-name-prefix", ANALYTICS)]


def pipeline_inventory(region):
    return [listing(region, "dynamodb", "list-tables", stdout={"TableNames": ["orders"]}),
            listing(region, "kinesis", "list-streams", stdout={"StreamNames": []}),
            listing(region, "ecr", "describe-repositories", stdout={"repositories": []}),
            listing(region, "sqs", "list-queues", "--queue-name-prefix", PIPELINE)]


def events_inventory(region):
    billing = {"TopicArn": "arn:aws:sns:%s:123456789012:billing" % region}
    return [listing(region, "events", "list-rules", "--name-prefix", EVENTS, stdout={"Rules": []}),
            listing(region, "sqs", "list-queues", "--queue-name-prefix", EVENTS),
            listing(region, "sns", "list-topics", stdout={"Topics": [billing]})]


CASES = {
    "aws/decommission-analytics-environment": dict(
        seed={"prefix": ANALYTICS, "run_id": "7c21", **REGIONS}, inventory=analytics_inventory,
        survivor=[listing(SECONDARY, "athena", "list-work-groups",
                          stdout={"WorkGroups": [{"Name": ANALYTICS + "-wg"}]})],
        broken=failing(SECONDARY, "athena", "list-work-groups"), command="athena list-work-groups"),
    "aws/decommission-data-pipeline": dict(
        seed={"prefix": PIPELINE, **REGIONS}, inventory=pipeline_inventory,
        survivor=[listing(SECONDARY, "kinesis", "list-streams", stdout={"StreamNames": [PIPELINE + "-events"]}),
                  listing(SECONDARY, "kinesis", "describe-stream-summary", "--stream-name", PIPELINE + "-events",
                          stdout={"StreamDescriptionSummary": {"StreamStatus": "ACTIVE"}})],
        broken=failing(SECONDARY, "ecr", "describe-repositories"), command="ecr describe-repositories"),
    "aws/decommission-event-driven-workload": dict(
        seed={"prefix": EVENTS, **REGIONS}, inventory=events_inventory,
        survivor=[listing(SECONDARY, "sns", "list-topics",
                          stdout={"Topics": [{"TopicArn": "arn:aws:sns:%s:123456789012:%s-alerts"
                                              % (SECONDARY, EVENTS)}]})],
        broken=failing(SECONDARY, "events", "list-rules", "--name-prefix", EVENTS), command="events list-rules"),
}


def grade(task, overrides=(), seed=True):
    case = CASES[task]
    rules = list(overrides) + case["inventory"](PRIMARY) + case["inventory"](SECONDARY)
    return vf.run_grader(task, seed=case["seed"] if seed else None, aws=rules, region=PRIMARY)


class DecommissionVerifierTests(unittest.TestCase):
    def test_clean_inventory_passes(self):
        for task in CASES:
            with self.subTest(task):
                result = grade(task)
                self.assertEqual(vf.PASS, result.verdict, result.stderr)

    def test_surviving_resource_fails(self):
        for task, case in CASES.items():
            with self.subTest(task):
                result = grade(task, case["survivor"])
                self.assertEqual(vf.FAIL, result.verdict, result.stderr)
                self.assertIn("Cross-region orphans", result.stderr)

    def test_failed_listing_is_an_evaluation_error(self):
        for task, case in CASES.items():
            with self.subTest(task):
                result = grade(task, [case["broken"]])
                self.assertEqual(vf.ERROR, result.verdict, result.stderr)
                self.assertIn(case["command"], str(result.error))

    def test_missing_seed_is_an_evaluation_error(self):
        for task in CASES:
            with self.subTest(task):
                self.assertEqual(vf.ERROR, grade(task, seed=False).verdict)

    def test_pipeline_describe_outcomes(self):
        table = PIPELINE + "-orders"
        listed = listing(SECONDARY, "dynamodb", "list-tables", stdout={"TableNames": [table]})
        describe = ("dynamodb", "describe-table", "--table-name", table)
        cases = [
            ("deleted after listing", failing(SECONDARY, *describe, code="ResourceNotFoundException"), vf.PASS),
            ("still deleting", listing(SECONDARY, *describe, stdout={"Table": {"TableStatus": "DELETING"}}), vf.PASS),
            ("still active", listing(SECONDARY, *describe, stdout={"Table": {"TableStatus": "ACTIVE"}}), vf.FAIL),
            ("describe throttled", failing(SECONDARY, *describe, code="ThrottlingException"), vf.ERROR),
        ]
        for name, rule, verdict in cases:
            with self.subTest(name):
                result = grade("aws/decommission-data-pipeline", [listed, rule])
                self.assertEqual(verdict, result.verdict, result.stderr)


if __name__ == "__main__":
    unittest.main()
