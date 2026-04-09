import boto3
import time
import json
import logging
from datetime import datetime, timedelta
import socket
import ssl

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = "ap-south-1"
EVENT_RULE_NAME = "ssl-renwal"
TARGET_INSTANCES = [
    "i-0363b0a9f528c0b10"
]

ec2 = boto3.client("ec2", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
events = boto3.client("events", region_name=REGION)


def validate_instances(instance_ids):
    logger.info(f"[validate_instances] Checking instances: {instance_ids}")
    valid_instances = []
    try:
        response = ec2.describe_instances(InstanceIds=instance_ids)
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                state = instance["State"]["Name"]
                iid = instance["InstanceId"]
                logger.info(f"[validate_instances] {iid} → state: {state}")
                if state == "running":
                    valid_instances.append(iid)
    except Exception as e:
        logger.error(f"[validate_instances] Failed to describe instances: {e}")
        return []
    logger.info(f"[validate_instances] Valid running instances: {valid_instances}")
    return valid_instances


def get_unique_security_groups(instance_ids):
    logger.info(f"[get_unique_security_groups] Fetching SGs for: {instance_ids}")
    try:
        response = ec2.describe_instances(InstanceIds=instance_ids)
        sg_set = set()
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                for sg in instance["SecurityGroups"]:
                    sg_set.add(sg["GroupId"])
                    logger.info(f"[get_unique_security_groups] Found SG: {sg['GroupId']} ({sg['GroupName']})")
        sg_list = list(sg_set)
        logger.info(f"[get_unique_security_groups] Unique SGs: {sg_list}")
        return sg_list
    except Exception as e:
        logger.error(f"[get_unique_security_groups] Failed: {e}")
        return []


def manage_port_80(sg_id, action):
    logger.info(f"[manage_port_80] Action: {action} on SG: {sg_id}")
    try:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        rules = response['SecurityGroups'][0]['IpPermissions']
        rule_exists = any(
            r.get('IpProtocol') == 'tcp' and
            r.get('FromPort') == 80 and
            r.get('ToPort') == 80 and
            any(ip.get('CidrIp') == '0.0.0.0/0' for ip in r.get('IpRanges', []))
            for r in rules
        )
        permission = [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        if action == "authorize":
            if rule_exists:
                logger.info(f"[manage_port_80] Port 80 already open on {sg_id}, skipping")
                return
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=permission)
            logger.info(f"[manage_port_80] Port 80 OPENED on {sg_id}")
        elif action == "revoke":
            if not rule_exists:
                logger.info(f"[manage_port_80] Port 80 already closed on {sg_id}, skipping")
                return
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=permission)
            logger.info(f"[manage_port_80] Port 80 CLOSED on {sg_id}")
    except Exception as e:
        logger.error(f"[manage_port_80] {action} failed for {sg_id}: {e}")


def get_domains_from_instance(instance_ids):
    logger.info(f"[get_domains_from_instance] Fetching certbot domains from: {instance_ids}")
    try:
        response = ssm.send_command(
            InstanceIds=instance_ids,
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["sudo certbot certificates 2>/dev/null | grep 'Domains:' | awk '{print $2}'"]},
        )
        command_id = response["Command"]["CommandId"]

        for _ in range(10):
            time.sleep(3)
            output = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_ids[0])
            if output['Status'] in ('Success', 'Failed'):
                break

        stdout = output.get('StandardOutputContent', '').strip()
        domains = [d.strip() for d in stdout.splitlines() if d.strip()]
        logger.info(f"[get_domains_from_instance] Found domains: {domains}")
        return domains
    except Exception as e:
        logger.error(f"[get_domains_from_instance] Failed: {e}")
        return []


def check_ssl_expiry(domains):
    logger.info(f"[check_ssl_expiry] Checking SSL expiry for domains: {domains}")
    needs_renewal = False
    for domain in domains:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (expiry_date - datetime.utcnow()).days
                    logger.info(f"[check_ssl_expiry] {domain} → {days_remaining} days remaining")
                    if days_remaining <= 30:
                        logger.info(f"[check_ssl_expiry] {domain} needs renewal")
                        needs_renewal = True
        except Exception as e:
            logger.warning(f"[check_ssl_expiry] Could not check {domain}, will renew to be safe: {e}")
            needs_renewal = True
    return needs_renewal


def schedule_next_run(rule_name, domains):
    logger.info(f"[schedule_next_run] Calculating next run based on cert expiry")
    try:
        earliest_expiry = None
        for domain in domains:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        logger.info(f"[schedule_next_run] {domain} expires: {expiry_date.strftime('%Y-%m-%d')}")
                        if earliest_expiry is None or expiry_date < earliest_expiry:
                            earliest_expiry = expiry_date
            except Exception as e:
                logger.warning(f"[schedule_next_run] Could not check {domain}: {e}")

        if earliest_expiry is None:
            logger.warning("[schedule_next_run] Could not determine expiry, falling back to 50 days")
            next_run = datetime.utcnow() + timedelta(days=50)
        else:
            next_run = earliest_expiry - timedelta(days=5)
            logger.info(f"[schedule_next_run] Earliest expiry: {earliest_expiry.strftime('%Y-%m-%d')}")
            logger.info(f"[schedule_next_run] Next run (5 days before expiry): {next_run.strftime('%Y-%m-%d')}")

            if next_run < datetime.utcnow():
                logger.warning("[schedule_next_run] Next run date is in the past, scheduling 1 day from now")
                next_run = datetime.utcnow() + timedelta(days=1)

        cron_expression = "cron({} {} {} {} ? {})".format(
            next_run.minute,
            next_run.hour,
            next_run.day,
            next_run.month,
            next_run.year
        )
        logger.info(f"[schedule_next_run] Cron expression: {cron_expression}")
        logger.info(f"[schedule_next_run] Scheduled date: {next_run.strftime('%Y-%m-%d %H:%M UTC')}")

        events.put_rule(
            Name=rule_name,
            ScheduleExpression=cron_expression,
            State='ENABLED'
        )
        logger.info(f"[schedule_next_run] EventBridge rule '{rule_name}' updated successfully")
        return True
    except Exception as e:
        logger.error(f"[schedule_next_run] Failed to update rule: {e}")
        return False


def run_ssm_command_and_wait(instance_ids, cmd):
    logger.info(f"[run_ssm_command_and_wait] Sending SSM command to: {instance_ids}")
    logger.info(f"[run_ssm_command_and_wait] Command: {cmd}")
    try:
        response = ssm.send_command(
            InstanceIds=instance_ids,
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [cmd]},
        )
        command_id = response["Command"]["CommandId"]
        logger.info(f"[run_ssm_command_and_wait] Command ID: {command_id}")

        overall_success = True
        for iid in instance_ids:
            for attempt in range(36):  # max 180s (36 x 5s)
                time.sleep(5)
                output = ssm.get_command_invocation(CommandId=command_id, InstanceId=iid)
                status = output['Status']
                logger.info(f"[run_ssm_command_and_wait] [{iid}] Attempt {attempt+1} → Status: {status}")

                if status in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
                    stdout = output.get('StandardOutputContent', '').strip()
                    stderr = output.get('StandardErrorContent', '').strip()
                    if stdout:
                        logger.info(f"[run_ssm_command_and_wait] [{iid}] STDOUT:\n{stdout}")
                    if stderr:
                        logger.warning(f"[run_ssm_command_and_wait] [{iid}] STDERR:\n{stderr}")
                    if status != 'Success':
                        overall_success = False
                    break
            else:
                logger.error(f"[run_ssm_command_and_wait] [{iid}] Timed out waiting for command")
                overall_success = False

        return overall_success

    except Exception as e:
        logger.error(f"[run_ssm_command_and_wait] SSM send_command failed: {e}")
        return False


def lambda_handler(event, context):
    logger.info("=" * 60)
    logger.info("[lambda_handler] SSL Renewal Lambda started")
    logger.info(f"[lambda_handler] Event: {json.dumps(event)}")
    logger.info(f"[lambda_handler] Target instances: {TARGET_INSTANCES}")

    target_instances = validate_instances(TARGET_INSTANCES)
    if not target_instances:
        logger.warning("[lambda_handler] No running instances found. Exiting.")
        return {'statusCode': 200, 'body': json.dumps('No running instances.')}

    sg_ids = get_unique_security_groups(target_instances)

    # dynamically fetch domains from instance
    domains = get_domains_from_instance(target_instances)
    if not domains:
        logger.warning("[lambda_handler] No domains found, proceeding with renewal anyway")
    else:
        if not check_ssl_expiry(domains):
            logger.info("[lambda_handler] All certs healthy (>30 days), skipping renewal")
            # still update schedule based on actual expiry
            schedule_next_run(EVENT_RULE_NAME, domains)
            return {'statusCode': 200, 'body': json.dumps('All certs healthy, skipping.')}

    logger.info(f"[lambda_handler] Opening port 80 on SGs: {sg_ids}")
    for sg in sg_ids:
        manage_port_80(sg, "authorize")

    try:
        cmd = "sudo rm -f /var/lib/letsencrypt/.certbot.lock /tmp/.certbot.lock && sudo certbot renew && (sudo systemctl reload nginx || sudo systemctl reload apache2 || true)"
        logger.info("[lambda_handler] Running certbot renewal via SSM...")

        if run_ssm_command_and_wait(target_instances, cmd):
            logger.info("[lambda_handler] Certbot renewal SUCCESS")
            schedule_next_run(EVENT_RULE_NAME, domains)
            logger.info("[lambda_handler] Lambda completed successfully")
            return {'statusCode': 200, 'body': json.dumps('Success')}
        else:
            logger.error("[lambda_handler] Certbot renewal FAILED")
            return {'statusCode': 500, 'body': json.dumps('Failed')}

    except Exception as e:
        logger.error(f"[lambda_handler] Unexpected error: {e}")
        return {'statusCode': 500, 'body': json.dumps(str(e))}

    finally:
        logger.info(f"[lambda_handler] Closing port 80 on SGs: {sg_ids}")
        for sg in sg_ids:
            manage_port_80(sg, "revoke")
        logger.info("[lambda_handler] Port 80 cleanup done")
        logger.info("=" * 60)
