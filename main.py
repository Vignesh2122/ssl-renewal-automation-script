import boto3
import time
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = "ap-south-1"
EVENT_RULE_NAME = "certbot-renewal-scheduler" 
TARGET_INSTANCES = [
    "i-0a026120248ec4e8e"
]

ec2 = boto3.client("ec2", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
events = boto3.client("events", region_name=REGION)

def validate_instances(instance_ids):
    valid_instances = []
    try:
        response = ec2.describe_instances(InstanceIds=instance_ids)
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["State"]["Name"] == "running":
                    valid_instances.append(instance["InstanceId"])
    except Exception as e:
        logger.error(str(e))
        return []
    return valid_instances

def get_unique_security_groups(instance_ids):
    try:
        response = ec2.describe_instances(InstanceIds=instance_ids)
        sg_set = set()
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                for sg in instance["SecurityGroups"]:
                    sg_set.add(sg["GroupId"])
        return list(sg_set)
    except Exception as e:
        logger.error(str(e))
        return []

def manage_port_80(sg_id, action):
    try:
        permission = [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        if action == "authorize":
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=permission)
        else:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=permission)
    except ec2.exceptions.ClientError:
        pass

def schedule_next_run(rule_name, days_ahead=64):
    try:
        future_date = datetime.now() + timedelta(days=days_ahead)
        cron_expression = "cron({} {} {} {} ? {})".format(
            future_date.minute,
            future_date.hour,
            future_date.day,
            future_date.month,
            future_date.year
        )
        logger.info(f"New Schedule: {cron_expression}")
        events.put_rule(
            Name=rule_name,
            ScheduleExpression=cron_expression,
            State='ENABLED'
        )
        return True
    except Exception as e:
        logger.error(str(e))
        return False

def run_ssm_command_and_wait(instance_ids, cmd):
    try:
        response = ssm.send_command(
            InstanceIds=instance_ids,
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [cmd]},
        )
        command_id = response["Command"]["CommandId"]
        
        time.sleep(20)
        
        for iid in instance_ids:
            try:
                output = ssm.get_command_invocation(CommandId=command_id, InstanceId=iid)
                logger.info(f"Output for {iid}: {output.get('StandardOutputContent', '')}")
                logger.error(f"Error for {iid}: {output.get('StandardErrorContent', '')}")
                
                if output['Status'] == 'Failed':
                    return False
            except Exception:
                pass
                
        return True
    except Exception as e:
        logger.error(str(e))
        return False

def lambda_handler(event, context):
    target_instances = validate_instances(TARGET_INSTANCES)
    if not target_instances:
        return {'statusCode': 200, 'body': json.dumps('No running instances.')}

    sg_ids = get_unique_security_groups(target_instances)
    
    for sg in sg_ids:
        manage_port_80(sg, "authorize")

    try:
        cmd = "sudo certbot renew && (sudo systemctl reload nginx || sudo systemctl reload apache2 || true)"
        
        if run_ssm_command_and_wait(target_instances, cmd):
            schedule_next_run(EVENT_RULE_NAME, days_ahead=64)
            return {'statusCode': 200, 'body': json.dumps('Success')}
        else:
            return {'statusCode': 500, 'body': json.dumps('Failed')}

    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps(str(e))}
        
    finally:
        for sg in sg_ids:
            manage_port_80(sg, "revoke")