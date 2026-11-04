"""Offline tests: the canary guardrail grader and teardown trust only the private task context."""
import unittest

import verifier_fakes as vf

TASK = "aws/repair-lambda-canary-rollback-guardrail"
REGION = "us-east-1"
ACCOUNT = "123456789012"
PREFIX = "vera-canary-0123456789"
FUNCTION_ARN = "arn:aws:lambda:%s:%s:function:%s-function" % (REGION, ACCOUNT, PREFIX)
CONTEXT = {
    "region": REGION, "account_id": ACCOUNT, "task_tag": PREFIX, "owner": "vera",
    "function_name": PREFIX + "-function", "function_arn": FUNCTION_ARN,
    "code_sha256": "seeded-code-sha", "alias_name": "live", "alias_arn": FUNCTION_ARN + ":live",
    "stable_version": "1", "candidate_version": "2",
    "execution_role_name": PREFIX + "-execution", "execution_role_id": "AROASEEDEDEXECUTION",
    "execution_role_arn": "arn:aws:iam::%s:role/%s-execution" % (ACCOUNT, PREFIX),
    "deploy_role_name": PREFIX + "-codedeploy", "deploy_role_id": "AROASEEDEDDEPLOY",
    "deploy_role_arn": "arn:aws:iam::%s:role/%s-codedeploy" % (ACCOUNT, PREFIX),
    "application_name": PREFIX + "-app", "application_id": "seeded-app-id",
    "deployment_group_name": PREFIX + "-group", "deployment_group_id": "seeded-group-id",
    "alarm_name": PREFIX + "-errors", "sentinel": PREFIX,
    "function_configuration": {
        "Runtime": "python3.12", "Handler": "index.handler", "Timeout": 15, "MemorySize": 128,
        "Description": "Vera sentinel: " + PREFIX,
        "Environment": {"Variables": {"TASK_SENTINEL": PREFIX, "DEPLOYMENT_MODE": "candidate"}},
    },
}


def context(**changes):
    return {**CONTEXT, **changes}


def repaired(ctx):
    """Clients for a fully repaired guardrail whose identities are the ones in ctx."""
    alias = ctx["function_arn"] + ":" + ctx["alias_name"]
    tags = {"CloudOpTask": ctx["task_tag"], "Owner": ctx["owner"],
            "SecurityProfile": "secure-canary-rollback-v1"}
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}
    roles = {ctx["deploy_role_name"]: {"RoleId": ctx["deploy_role_id"], "AssumeRolePolicyDocument": trust},
             ctx["execution_role_name"]: {"RoleId": ctx["execution_role_id"]}}

    def get_role(RoleName):
        return {"Role": roles[RoleName]} if RoleName in roles else vf.client_error("NoSuchEntity", "GetRole")

    return {
        "lambda": vf.StrictClient(
            "lambda",
            get_function_configuration={**ctx["function_configuration"],
                                        "FunctionArn": ctx["function_arn"], "CodeSha256": ctx["code_sha256"]},
            get_alias={"AliasArn": ctx["alias_arn"], "FunctionVersion": ctx["stable_version"]},
            get_function=lambda FunctionName, Qualifier: {"Configuration": {"Version": Qualifier}},
            list_tags={"Tags": tags}),
        "codedeploy": vf.StrictClient(
            "codedeploy",
            get_deployment_group={"deploymentGroupInfo": {
                "deploymentGroupId": ctx["deployment_group_id"], "serviceRoleArn": ctx["deploy_role_arn"],
                "deploymentConfigName": "CodeDeployDefault.LambdaCanary10Percent5Minutes",
                "deploymentStyle": {"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"},
                "autoRollbackConfiguration": {"enabled": True,
                                              "events": ["DEPLOYMENT_FAILURE", "DEPLOYMENT_STOP_ON_ALARM"]},
                "alarmConfiguration": {"enabled": True, "ignorePollAlarmFailure": False,
                                       "alarms": [{"name": ctx["alarm_name"]}]}}},
            get_application={"application": {"applicationId": ctx["application_id"]}}),
        "cloudwatch": vf.StrictClient("cloudwatch", describe_alarms={"MetricAlarms": [{
            "Namespace": "AWS/Lambda", "MetricName": "Errors", "Statistic": "Sum", "Period": 60,
            "EvaluationPeriods": 1, "Threshold": 1.0, "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching",
            "Dimensions": [{"Name": "FunctionName", "Value": ctx["function_name"]},
                           {"Name": "Resource", "Value": ctx["function_name"] + ":" + ctx["alias_name"]}]}]}),
        "iam": vf.StrictClient(
            "iam", get_role=get_role, list_role_policies={"PolicyNames": ["deploy"]},
            get_role_policy={"PolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["lambda:UpdateAlias", "lambda:GetAlias"], "Resource": alias},
                {"Effect": "Allow", "Action": "cloudwatch:DescribeAlarms", "Resource": "*"}]}},
            list_attached_role_policies={"AttachedPolicies": []},
            list_role_tags={"Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}),
    }


def grade(state, private=None, workspace=None):
    files = {}
    if private is not None:
        files["task_context.json"] = private
    if workspace is not None:
        files["workspace/task_context.json"] = workspace
    return vf.run_grader(TASK, files=files, clients=repaired(state), region=REGION,
                         env={"AGENT_WORKSPACE": "{work}/workspace"})


def teardown_rules(ctx):
    region = ["--region", ctx["region"]]
    return [
        vf.aws_rule("deploy", "delete-deployment-group", *region, "--application-name",
                    ctx["application_name"], "--deployment-group-name", ctx["deployment_group_name"]),
        vf.aws_rule("deploy", "delete-application", *region, "--application-name", ctx["application_name"]),
        vf.aws_rule("cloudwatch", "delete-alarms", *region, "--alarm-names", ctx["alarm_name"]),
        vf.aws_rule("lambda", "delete-alias", *region, "--function-name", ctx["function_name"],
                    "--name", ctx["alias_name"]),
        vf.aws_rule("lambda", "delete-function", *region, "--function-name", ctx["function_name"]),
        vf.aws_rule("iam", "detach-role-policy", "--role-name", ctx["deploy_role_name"]),
        vf.aws_rule("iam", "delete-role", "--role-name", ctx["deploy_role_name"]),
        vf.aws_rule("iam", "delete-role-policy", "--role-name", ctx["execution_role_name"]),
        vf.aws_rule("iam", "delete-role", "--role-name", ctx["execution_role_name"]),
    ]


class CanaryContextTests(unittest.TestCase):
    def test_repaired_guardrail_passes(self):
        result = grade(CONTEXT, private=CONTEXT, workspace=CONTEXT)
        self.assertEqual(vf.PASS, result.verdict, result.stdout + result.stderr)

    def test_edited_workspace_copy_cannot_hide_replaced_resources(self):
        replaced = context(code_sha256="agent-code-sha", deploy_role_id="AROAAGENTDEPLOY")
        result = grade(replaced, private=CONTEXT, workspace=replaced)
        self.assertEqual(vf.FAIL, result.verdict, result.stdout + result.stderr)
        self.assertIn("The seeded function code was changed", result.stdout)
        self.assertIn("Seeded CodeDeploy role was replaced", result.stdout)

    def test_missing_private_copy_is_an_evaluation_error(self):
        result = grade(CONTEXT, workspace=CONTEXT)
        self.assertEqual(vf.ERROR, result.verdict, result.stdout + result.stderr)
        self.assertIsInstance(result.error, FileNotFoundError)

    def test_teardown_deletes_only_the_seeded_resources(self):
        victim = context(function_name="payments-api", application_name="payments",
                         deployment_group_name="payments-prod", alarm_name="payments-5xx",
                         deploy_role_name="payments-deploy", execution_role_name="payments-api-role")
        result = vf.run_script(TASK, "environment/lifecycle/teardown.sh",
                               files={"task_context.json": CONTEXT, "workspace/task_context.json": victim},
                               env={"AGENT_WORKSPACE": "{work}/workspace"}, aws=teardown_rules(CONTEXT))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(9, len(result.aws_calls))


if __name__ == "__main__":
    unittest.main()
