#!/usr/bin/env bash
# Creates an SNS topic and a Serverless Application Repository application, both named
# vera2-* and both shared with principal "*". Records their identifiers in
# seed_state.json. Fails unless both resources end up public.
set -euo pipefail
zone="us-east-1"
stamp="$(date +%s)${RANDOM}"
die() { echo "setup failed: $*" >&2; exit 1; }
valid() { [ -n "$1" ] && [ "$1" != "None" ]; }
who=$(aws sts get-caller-identity --query Account --output text) || die "cannot resolve the account id"
valid "$who" || die "cannot resolve the account id"

# Remove leftovers from earlier runs.
for old in $(aws sns list-topics --region "$zone" --query 'Topics[].TopicArn' --output text 2>/dev/null | tr '\t' '\n' | grep ':vera2-' || true); do
  aws sns delete-topic --topic-arn "$old" --region "$zone" 2>/dev/null || true
done
for old in $(aws serverlessrepo list-applications --region "$zone" --query "Applications[?starts_with(Name,'vera2-')].ApplicationId" --output text 2>/dev/null | tr '\t' '\n'); do
  aws serverlessrepo delete-application --application-id "$old" --region "$zone" 2>/dev/null || true
done

bus=$(aws sns create-topic --name "vera2-signals-${stamp}" --region "$zone" --query 'TopicArn' --output text) \
  || die "create-topic failed"
valid "$bus" || die "create-topic returned no topic ARN"
open_doc="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Pub\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"SNS:Subscribe\",\"Resource\":\"$bus\"}]}"
aws sns set-topic-attributes --topic-arn "$bus" --attribute-name Policy --region "$zone" --attribute-value "$open_doc" \
  || die "could not set the public topic policy"

work=$(mktemp -d)
tpl="$work/app.yaml"
cat > "$tpl" <<'YAML'
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  F:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      InlineCode: |
        def handler(event, context):
            return {"ok": True}
YAML
app=$(aws serverlessrepo create-application \
  --author vera2 --name "vera2-bridge-${stamp}" --description "vera2 analytics pilot bridge" \
  --template-body "$(cat "$tpl")" --license-body "MIT" \
  --semantic-version 1.0.0 --source-code-url "https://example.com/vera2" \
  --region "$zone" --query 'ApplicationId' --output text) || die "create-application failed"
valid "$app" || die "create-application returned no application id"

# The policy can only be set once version 1.0.0 has finished registering, which can
# lag the create call, so retry.
tries=0
while [ "$tries" -lt 20 ]; do
  if aws serverlessrepo put-application-policy --application-id "$app" \
      --statements '[{"Principals":["*"],"Actions":["Deploy"]}]' --region "$zone" >/dev/null 2>&1; then
    break
  fi
  tries=$((tries+1))
  sleep 3
done
[ "$tries" -lt 20 ] || die "put-application-policy kept failing"

topic_doc=$(aws sns get-topic-attributes --topic-arn "$bus" --region "$zone" --query 'Attributes.Policy' --output text) \
  || die "cannot read the topic policy back"
app_doc=$(aws serverlessrepo get-application-policy --application-id "$app" --region "$zone" --query 'Statements' --output json) \
  || die "cannot read the application policy back"
python3 - "$topic_doc" "$app_doc" <<'PY' || die "the seeded policies are not public"
import json, sys
def values(p):
    if isinstance(p, dict):
        return [x for v in p.values() for x in (v if isinstance(v, list) else [v])]
    return p if isinstance(p, list) else [p]
def public(statements, key):
    return any(s.get("Effect", "Allow") == "Allow" and not s.get("Condition") and "*" in values(s.get(key))
               for s in statements)
sys.exit(0 if public(json.loads(sys.argv[1]).get("Statement", []), "Principal")
         and public(json.loads(sys.argv[2]), "Principals") else 1)
PY

python3 - "$zone" "$who" "$bus" "$app" <<'PY'
import json,sys
zone,acct,topic,appid=sys.argv[1:5]
json.dump({"region":zone,"account":acct,"sns_topic_arn":topic,"sar_app_id":appid},open("seed_state.json","w"),indent=2)
PY
echo "seeded decoy public SNS topic + hidden public SAR app: $bus $app"
