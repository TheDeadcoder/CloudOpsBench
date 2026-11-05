"""Offline tests: deleting a seeded resource scores a failure instead of crashing the grader."""
from datetime import datetime, timezone
import unittest

import verifier_fakes as vf

HOME, OTHER, ACCOUNT = "us-east-1", "us-west-2", "123456789012"

EVENTS_SEED = {
    "home_region": HOME, "other_region": OTHER, "regions": [HOME, OTHER],
    "intake": [{"name": "intake-orders", "region": HOME, "bus": "default"},
               {"name": "intake-returns", "region": HOME, "bus": "default"},
               {"name": "fwd-claims", "region": OTHER, "bus": "mesh-ops"}],
    "decoy": {"name": "drill-replay", "region": HOME, "bus": "default"},
    "others": [{"name": "billing-nightly", "region": HOME, "bus": "default", "state": "ENABLED"}],
}
EVENT_RULES = {
    (HOME, "default", "intake-orders"): ("ENABLED", "intake"),
    (HOME, "default", "intake-returns"): ("ENABLED", "intake"),
    (OTHER, "mesh-ops", "fwd-claims"): ("ENABLED", "intake"),
    (HOME, "default", "drill-replay"): ("DISABLED", "drill"),
    (HOME, "default", "billing-nightly"): ("ENABLED", None),
}


def rule_arn(region, bus, name):
    return "arn:aws:events:%s:%s:rule/%s" % (region, ACCOUNT, name if bus == "default" else bus + "/" + name)


def eventbridge(deleted=(), error=None):
    rules = {k: v for k, v in EVENT_RULES.items() if k[2] not in deleted}
    tags = {rule_arn(*k): v[1] for k, v in rules.items()}

    def client(region):
        def describe_rule(Name, EventBusName="default"):
            if (region, EventBusName, Name) not in rules:
                return error or vf.client_error("ResourceNotFoundException", "DescribeRule")
            return error or {"Name": Name, "State": rules[(region, EventBusName, Name)][0],
                             "Arn": rule_arn(region, EventBusName, Name)}

        def list_rules(EventBusName="default"):
            return {"Rules": [{"Name": n, "Arn": rule_arn(r, b, n), "State": state}
                              for (r, b, n), (state, _) in rules.items() if (r, b) == (region, EventBusName)]}

        def list_tags_for_resource(ResourceARN):
            return {"Tags": [{"Key": "App", "Value": tags[ResourceARN]}] if tags.get(ResourceARN) else []}

        buses = sorted({b for r, b, _ in EVENT_RULES if r == region} | {"default"})
        return vf.StrictClient("events", describe_rule=describe_rule, list_rules=list_rules,
                               list_tags_for_resource=list_tags_for_resource,
                               list_event_buses={"EventBuses": [{"Name": b} for b in buses]})

    return {("events", HOME): client(HOME), ("events", OTHER): client(OTHER),
            "ec2": vf.StrictClient("ec2", describe_regions={"Regions": []})}


NETWORK_SEED = {"prod_vpc_id": "vpc-prod", "shared_vpc_id": "vpc-shared", "peering_id": "pcx-1",
                "prod_rt_id": "rtb-prod", "shared_rt_id": "rtb-shared", "app_sg_id": "sg-app",
                "shared_rds_sg_id": "sg-rds"}
SUBNETS = {"prod-subnet-a": "rtb-prod", "prod-subnet-b": "rtb-prod",
           "shared-subnet-a": "rtb-shared", "shared-subnet-b": "rtb-shared"}


def network(deleted=(), error=None):
    routes = {"rtb-prod": "172.16.0.0/16", "rtb-shared": "10.0.0.0/16"}

    def describe_route_tables(RouteTableIds=None, Filters=None):
        if error:
            return error
        if Filters:
            return {"RouteTables": [{"RouteTableId": SUBNETS[s[len("subnet-"):]]} for s in Filters[0]["Values"]]}
        if RouteTableIds[0] in deleted:
            return vf.client_error("InvalidRouteTableID.NotFound", "DescribeRouteTables")
        return {"RouteTables": [{"RouteTableId": RouteTableIds[0], "Routes": [
            {"DestinationCidrBlock": routes[RouteTableIds[0]], "VpcPeeringConnectionId": "pcx-1", "State": "active"}]}]}

    def describe_vpc_peering_connections(VpcPeeringConnectionIds):
        if "pcx-1" in deleted:
            return vf.client_error("InvalidVpcPeeringConnectionID.NotFound", "DescribeVpcPeeringConnections")
        return {"VpcPeeringConnections": [{"Status": {"Code": "active"}}]}

    def describe_security_groups(GroupIds):
        if "sg-rds" in deleted:
            return vf.client_error("InvalidGroup.NotFound", "DescribeSecurityGroups")
        return {"SecurityGroups": [{"IpPermissions": [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                                                       "UserIdGroupPairs": [{"GroupId": "sg-app"}]}]}]}

    return {"ec2": vf.StrictClient(
        "ec2", describe_route_tables=describe_route_tables,
        describe_vpc_peering_connections=describe_vpc_peering_connections,
        describe_security_groups=describe_security_groups,
        describe_subnets=lambda Filters: {"Subnets": [{"SubnetId": "subnet-" + Filters[0]["Values"][0]}]})}


CREATED = datetime(2026, 1, 1, tzinfo=timezone.utc)
TABLE = "arn:aws:dynamodb:us-east-1:%s:table/%%s" % ACCOUNT
FILE_SYSTEM = "arn:aws:elasticfilesystem:us-east-1:%s:file-system/%%s" % ACCOUNT
BACKUP_SEED = {
    "region": HOME, "vault": "vera-vault-x", "plan_name": "vera-nightly-x", "plan_id": "plan-1",
    "table_orders": "vera-orders-x", "table_audit": "vera-audit-x",
    "table_ids": {"vera-orders-x": "tid-orders", "vera-audit-x": "tid-audit"},
    "fs_id": "fs-1", "fs2_id": "fs-2", "scratch_bucket": "vera-scratch-x",
    "scratch_created": CREATED.isoformat(), "vault_created": CREATED.isoformat(),
    "protected": [TABLE % "vera-orders-x", TABLE % "vera-audit-x", FILE_SYSTEM % "fs-1", FILE_SYSTEM % "fs-2"],
    "excluded": "arn:aws:s3:::vera-scratch-x",
}


def fleet(deleted=(), error=None):
    selection = {"SelectionName": "fleet", "IamRoleArn": "arn:aws:iam::%s:role/vera-backup" % ACCOUNT,
                 "Resources": BACKUP_SEED["protected"]}

    def tags(ResourceArn=None, ResourceId=None):
        if error:
            return error
        if (ResourceArn or "").rsplit("/", 1)[-1] in deleted:
            return vf.client_error("ResourceNotFoundException", "ListTagsOfResource")
        if ResourceId in deleted:
            return vf.client_error("FileSystemNotFound", "ListTagsForResource")
        return {"Tags": []}

    scratch_gone = "vera-scratch-x" in deleted
    return {
        "backup": vf.StrictClient(
            "backup", get_backup_plan={"BackupPlan": {"Rules": [{"TargetBackupVaultName": "vera-vault-x"}]}},
            describe_backup_vault={"CreationDate": CREATED},
            list_backup_selections={"BackupSelectionsList": [{"SelectionId": "sel-1"}]},
            get_backup_selection={"BackupSelection": selection},
            start_backup_job=lambda BackupVaultName, ResourceArn, IamRoleArn: {"BackupJobId": "job-" + ResourceArn},
            describe_backup_job={"State": "COMPLETED"},
            list_recovery_points_by_backup_vault=[{"RecoveryPoints": []}]),
        "dynamodb": vf.StrictClient(
            "dynamodb", list_tags_of_resource=tags,
            describe_table=lambda TableName: {"Table": {"TableId": BACKUP_SEED["table_ids"][TableName]}}),
        "efs": vf.StrictClient("efs", list_tags_for_resource=tags, describe_file_systems={"FileSystems": [{}]}),
        "s3": vf.StrictClient(
            "s3", get_bucket_tagging=vf.client_error("NoSuchBucket" if scratch_gone else "NoSuchTagSet", "GetBucketTagging"),
            list_buckets={"Buckets": [] if scratch_gone else [{"Name": "vera-scratch-x", "CreationDate": CREATED}]}),
    }


TASKS = {
    "aws/enable-tagged-eventbridge-rules": (EVENTS_SEED, eventbridge, [
        ("intake rule deleted", {"intake-orders"}, "missing intake rule: intake-orders"),
        ("decoy rule deleted", {"drill-replay"}, "decoy rule missing: drill-replay"),
        ("recorded rule deleted", {"billing-nightly"}, "a non-intake rule is missing: billing-nightly"),
    ], vf.client_error("ThrottlingException", "DescribeRule")),
    "aws/fix-cross-vpc-database-connectivity": (NETWORK_SEED, network, [
        ("route table deleted", {"rtb-prod"}, "prod-custom-rt (rtb-prod) no longer exists"),
        ("database security group deleted", {"sg-rds"}, "shared-rds-sg (sg-rds) no longer exists"),
        ("peering connection deleted", {"pcx-1"}, "VPC peering connection pcx-1 no longer exists"),
    ], vf.client_error("RequestLimitExceeded", "DescribeRouteTables")),
    "aws/restore-backup-plan-coverage": (BACKUP_SEED, fleet, [
        ("table deleted", {"vera-orders-x"}, "vera-orders-x, a fleet resource seeded for this task, is gone"),
        ("file system deleted", {"fs-1"}, "fs-1, a fleet resource seeded for this task, is gone"),
        ("scratch bucket deleted", {"vera-scratch-x"}, "the bucket vera-scratch-x seeded for this task is gone"),
    ], vf.client_error("ThrottlingException", "ListTagsOfResource")),
}


def grade(task, **state):
    seed, clients, _cases, _throttle = TASKS[task]
    return vf.run_grader(task, seed=seed, clients=clients(**state), region=HOME)


class SeededResourceDeletionTests(unittest.TestCase):
    def test_repaired_state_passes(self):
        for task in TASKS:
            with self.subTest(task):
                result = grade(task)
                self.assertEqual(vf.PASS, result.verdict, result.stderr)

    def test_deleted_seeded_resource_fails(self):
        for task, (_seed, _clients, cases, _throttle) in TASKS.items():
            for name, deleted, message in cases:
                with self.subTest(task=task, case=name):
                    result = grade(task, deleted=deleted)
                    self.assertEqual(vf.FAIL, result.verdict, result.stderr)
                    self.assertIn(message, result.stderr)

    def test_other_errors_still_raise(self):
        for task, (_seed, _clients, _cases, throttle) in TASKS.items():
            with self.subTest(task):
                self.assertEqual(vf.ERROR, grade(task, error=throttle).verdict)


if __name__ == "__main__":
    unittest.main()
