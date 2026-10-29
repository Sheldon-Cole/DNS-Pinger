from collections import Counter
from dns import resolver
import hostinger_api
import json
import logging
import os
import signal
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import yaml

# Configure logging
log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_name, logging.INFO)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("dns-pinger")

# Graceful shutdown event
shutdown_event = threading.Event()


def signal_handler(signum, frame):
    sig_name = signal.Signals(signum).name
    logger.info("Received %s. Shutting down gracefully...", sig_name)
    shutdown_event.set()


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def get_hostinger_config_path():
    if env_path := (os.getenv("HOSTINGER_CONFIG_PATH") or os.getenv("CONFIG_PATH")):
        if os.path.isfile(env_path):
            return env_path
        if os.path.isdir(env_path):
            for filename in ("hostinger-config.yaml", "hostinger.yaml", "firewall-config.yaml"):
                candidate = os.path.join(env_path, filename)
                if os.path.exists(candidate):
                    return candidate
        return env_path

    # Check common container mount points and local paths
    candidates = [
        "/app/config/hostinger-config.yaml",
        "/app/config/hostinger.yaml",
        "/app/config/firewall-config.yaml",
        "/app/config",  # In case a file was directly mounted to /app/config
        "./config/hostinger-config.yaml",
        "./config/hostinger.yaml",
        "./config/firewall-config.yaml",
        "./hostinger-config.yaml",
        "./hostinger.yaml",
        "./firewall-config.yaml",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    return "./config/hostinger-config.yaml"


def get_pangolin_config_path():
    if env_path := os.getenv("PANGOLIN_CONFIG_PATH"):
        if os.path.isfile(env_path):
            return env_path
        if os.path.isdir(env_path):
            for filename in ("pangolin-config.yaml", "pangolin.yaml"):
                candidate = os.path.join(env_path, filename)
                if os.path.exists(candidate):
                    return candidate
        return env_path

    candidates = [
        "/app/config/pangolin-config.yaml",
        "/app/config/pangolin.yaml",
        "./config/pangolin-config.yaml",
        "./config/pangolin.yaml",
        "./pangolin-config.yaml",
        "./pangolin.yaml",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    return "./config/pangolin-config.yaml"


def load_yaml_template(config_path, default_filename="hostinger-config.yaml"):
    try:
        if os.path.isdir(config_path):
            config_path = os.path.join(config_path, default_filename)
        with open(config_path, "r") as file:
            return yaml.safe_load(file)
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError) as e:
        logger.error(
            "Configuration error at '%s' (%s: %s). "
            "Please check your volume mount or copy the example file from 'config/'.",
            config_path,
            type(e).__name__,
            e,
        )
        return None
    except yaml.YAMLError as e:
        logger.error("Error parsing YAML from '%s': %s", config_path, e)
        return None


# Backwards-compatible helpers
get_config_path = get_hostinger_config_path
load_firewall_template = load_yaml_template


def build_firewall_rules(template_config, ip_records, firewall_id):
    final_rules = []
    for rule in template_config.get("rules", []):
        if rule.get("source_detail") == "{{ dns_record }}":
            for ip in ip_records:
                new_rule = rule.copy()
                new_rule["source_detail"] = ip
                final_rules.append(new_rule)
        else:
            final_rules.append(rule.copy())

    return {
        "name": template_config.get("name"),
        "id": firewall_id,
        "rules": final_rules,
    }


def rule_signature(r):
    return (
        str(r.get("action", "")).strip().lower(),
        str(r.get("protocol", "")).strip().upper(),
        str(r.get("port", "")).strip().lower(),
        str(r.get("source", "")).strip().lower(),
        str(r.get("source_detail", "")).strip().lower(),
    )


def should_update_firewall(target_firewall, desired_config):
    current_signatures = Counter(
        rule_signature(r) for r in target_firewall.get("rules", [])
    )
    desired_signatures = Counter(
        rule_signature(r) for r in desired_config.get("rules", [])
    )

    if current_signatures == desired_signatures:
        logger.info("Hostinger firewall rules match desired configuration. No updates necessary.")
        return False
    else:
        logger.info(
            "Hostinger firewall rules mismatch detected (DNS records or config file changed). Updating rules..."
        )
        return True


def get_hostinger_firewalls(api_key, pjson):
    configuration = hostinger_api.Configuration(access_token=api_key)

    with hostinger_api.ApiClient(configuration) as api_client:
        api_instance = hostinger_api.VPSFirewallApi(api_client)
        page = 1

        try:
            api_response = api_instance.get_firewall_list_v1(page=page)
            if pjson:
                logger.debug(
                    "VPSFirewallApi->get_firewall_list_v1 response:\n%s",
                    pretty_json(api_response.to_dict()),
                )
            else:
                logger.debug(
                    "VPSFirewallApi->get_firewall_list_v1 response: %s",
                    api_response,
                )
            return api_response
        except Exception as e:
            logger.error(
                "Exception when calling VPSFirewallApi->get_firewall_list_v1: %s",
                e,
            )
            return None


def update_firewall_rules(api_key, firewall_config, firewall_id, pjson):
    configuration = hostinger_api.Configuration(access_token=api_key)

    with hostinger_api.ApiClient(configuration) as api_client:
        api_instance = hostinger_api.VPSFirewallApi(api_client)
        vpsv1_firewall_rules_replace_request = (
            hostinger_api.VPSV1FirewallRulesReplaceRequest(
                rules=firewall_config["rules"], sync=False
            )
        )

        try:
            api_response = api_instance.replace_all_firewall_rules_in_group_v1(
                firewall_id, vpsv1_firewall_rules_replace_request
            )
            logger.info("Successfully updated Hostinger firewall rules (Firewall ID: %s).", firewall_id)
            if pjson:
                logger.debug(
                    "VPSFirewallApi->replace_all_firewall_rules_in_group_v1 response:\n%s",
                    pretty_json(api_response.to_dict()),
                )
            else:
                logger.debug(
                    "VPSFirewallApi->replace_all_firewall_rules_in_group_v1 response: %s",
                    api_response,
                )
        except Exception as e:
            logger.error(
                "Exception when calling VPSFirewallApi->replace_all_firewall_rules_in_group_v1: %s",
                e,
            )


def normalize_pangolin_url(url):
    base = url.strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    if not base.endswith("/v1"):
        base = f"{base}/v1"
    return base


def pangolin_api_request(base_url, api_key, method, endpoint, payload=None, pjson=False):
    url = f"{base_url}/{endpoint.lstrip('/')}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "User-Agent": "dns-pinger/0.3.0",
    }
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw_body = resp.read().decode("utf-8")
            parsed = json.loads(raw_body) if raw_body else {}
            if pjson:
                logger.debug("Pangolin API %s %s response:\n%s", method, endpoint, pretty_json(parsed))
            else:
                logger.debug("Pangolin API %s %s status: %s", method, endpoint, resp.status)
            return parsed
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8")
        except Exception:
            pass
        logger.error(
            "Pangolin API HTTP %s on %s %s: %s",
            e.code,
            method,
            endpoint,
            err_body or e.reason,
        )
        return None
    except Exception as e:
        logger.error("Error calling Pangolin API %s %s: %s", method, endpoint, e)
        return None


def resolve_pangolin_policy_id(base_url, api_key, org_id, policy_name, pjson=False):
    encoded_org = urllib.parse.quote(str(org_id), safe="")
    resp = pangolin_api_request(
        base_url,
        api_key,
        "GET",
        f"org/{encoded_org}/resource-policies?pageSize=100&page=1",
        pjson=pjson,
    )
    if not resp or not isinstance(resp.get("data"), dict):
        return None

    policies = resp["data"].get("policies", [])
    if not policies:
        logger.warning("No resource policies found in Pangolin org '%s'.", org_id)
        return None

    if not policy_name:
        return policies[0].get("resourcePolicyId")

    target = str(policy_name).strip().lower()
    for p in policies:
        p_name = str(p.get("name") or "").strip().lower()
        p_nice = str(p.get("niceId") or "").strip().lower()
        if target in (p_name, p_nice):
            return p.get("resourcePolicyId")

    available = []
    for p in policies:
        p_name = p.get("name")
        p_id = p.get("resourcePolicyId")
        p_nice = p.get("niceId")
        details = [f"id={p_id}"]
        if p_nice:
            details.append(f"niceId={p_nice}")
        available.append(f"'{p_name}' ({', '.join(details)})")

    logger.warning(
        "Resource policy '%s' not found in Pangolin org '%s'. Available policies: %s",
        policy_name,
        org_id,
        ", ".join(available),
    )
    return None


def get_pangolin_policy(base_url, api_key, policy_id, pjson=False):
    resp = pangolin_api_request(
        base_url,
        api_key,
        "GET",
        f"resource-policy/{policy_id}",
        pjson=pjson,
    )
    if not resp or not isinstance(resp.get("data"), dict):
        return None
    return resp["data"]


def build_pangolin_rules(template_config, ip_records):
    apply_rules = bool(
        template_config.get("apply_rules", template_config.get("applyRules", True))
    )
    final_rules = []
    for idx, rule in enumerate(template_config.get("rules", [])):
        default_priority = (idx + 1) * 10
        priority = int(rule.get("priority", default_priority))
        action = str(rule.get("action", "ACCEPT")).strip().upper()
        match_type = str(rule.get("match", "IP")).strip().upper()
        enabled = bool(rule.get("enabled", True))
        raw_value = str(rule.get("value", "")).strip()

        if raw_value == "{{ dns_record }}":
            for ip in ip_records:
                final_rules.append(
                    {
                        "action": action,
                        "match": match_type,
                        "value": ip,
                        "priority": priority,
                        "enabled": enabled,
                    }
                )
        else:
            final_rules.append(
                {
                    "action": action,
                    "match": match_type,
                    "value": raw_value,
                    "priority": priority,
                    "enabled": enabled,
                }
            )

    return {
        "applyRules": apply_rules,
        "rules": final_rules,
    }


def pangolin_rule_signature(r):
    return (
        str(r.get("action", "")).strip().upper(),
        str(r.get("match", "")).strip().upper(),
        str(r.get("value", "")).strip(),
        int(r.get("priority", 100)),
        bool(r.get("enabled", True)),
    )


def should_update_pangolin_policy(current_policy, desired_config):
    current_apply = bool(current_policy.get("applyRules", True))
    desired_apply = bool(desired_config.get("applyRules", True))

    current_signatures = Counter(
        pangolin_rule_signature(r) for r in current_policy.get("rules", [])
    )
    desired_signatures = Counter(
        pangolin_rule_signature(r) for r in desired_config.get("rules", [])
    )

    if current_apply == desired_apply and current_signatures == desired_signatures:
        logger.info("Pangolin policy rules match desired configuration. No updates necessary.")
        return False
    else:
        logger.info(
            "Pangolin policy rules mismatch detected (DNS records or config file changed). Updating rules..."
        )
        return True


def update_pangolin_policy_rules(base_url, api_key, policy_id, desired_config, pjson=False):
    resp = pangolin_api_request(
        base_url,
        api_key,
        "POST",
        f"resource-policy/{policy_id}/rules",
        payload=desired_config,
        pjson=pjson,
    )
    if resp and resp.get("success"):
        logger.info("Successfully updated Pangolin policy rules (Policy ID: %s).", policy_id)


def pretty_json(data):
    return json.dumps(data, indent=4, default=str)


def resolve_domain(domain, record_types=("A",)):
    ip_addresses = []
    for rtype in record_types:
        try:
            records = resolver.resolve(domain, rtype)
            for rdata in records:
                logger.info("%s - %s Record: %s", domain, rtype, rdata.address)
                ip_addresses.append(rdata.address)
        except resolver.NoAnswer:
            logger.debug("%s has no %s records", domain, rtype)
        except resolver.NXDOMAIN:
            logger.warning("Domain does not exist: %s", domain)
        except Exception as e:
            logger.error("Error fetching %s record for %s: %s", rtype, domain, e)
    return ip_addresses


def sync_hostinger(api_key, firewall_name, ip_records, pjson):
    config_path = get_hostinger_config_path()
    template = load_yaml_template(config_path, default_filename="hostinger-config.yaml")
    if template is None:
        logger.warning("Skipping Hostinger sync: configuration file issue with '%s'...", config_path)
        return

    api_response = get_hostinger_firewalls(api_key, pjson)
    if api_response is None:
        logger.warning("Hostinger API check failed. Skipping Hostinger sync this cycle...")
        return

    api_dict = api_response.to_dict()
    target_fw = None
    for fw in api_dict.get("data", []):
        if firewall_name is None or fw.get("name") == firewall_name:
            target_fw = fw
            break

    if target_fw is None:
        if firewall_name:
            available_fws = [
                f"'{fw.get('name')}' (id={fw.get('id')})"
                for fw in api_dict.get("data", [])
            ]
            logger.warning(
                "Firewall '%s' not found in Hostinger account. Available firewalls: %s. Skipping Hostinger sync...",
                firewall_name,
                ", ".join(available_fws) if available_fws else "none",
            )
        else:
            logger.warning("No firewalls found in Hostinger account. Skipping Hostinger sync...")
        return

    firewall_id = target_fw["id"]
    desired_config = build_firewall_rules(template, ip_records, firewall_id)

    if should_update_firewall(target_fw, desired_config):
        update_firewall_rules(api_key, desired_config, firewall_id, pjson)


def sync_pangolin(base_url, api_key, env_policy_id, env_org_id, env_policy_name, ip_records, pjson):
    config_path = get_pangolin_config_path()
    template = load_yaml_template(config_path, default_filename="pangolin-config.yaml")
    if template is None:
        logger.warning("Skipping Pangolin sync: configuration file issue with '%s'...", config_path)
        return

    policy_id = env_policy_id or template.get("policy_id") or template.get("id")
    if not policy_id:
        org_id = env_org_id or template.get("org_id")
        template_name = template.get("nice_id") or template.get("name")
        if template_name == "Example Shared Policy":
            template_name = None
        policy_name = env_policy_name or template_name
        if not org_id:
            logger.error(
                "Pangolin sync requires PANGOLIN_POLICY_ID (or PANGOLIN_ORG_ID to look up policy by name). Skipping Pangolin sync..."
            )
            return
        policy_id = resolve_pangolin_policy_id(base_url, api_key, org_id, policy_name, pjson=pjson)
        if not policy_id:
            return

    current_policy = get_pangolin_policy(base_url, api_key, policy_id, pjson=pjson)
    if current_policy is None:
        logger.warning(
            "Failed to retrieve Pangolin policy (ID: %s). Skipping Pangolin sync this cycle...",
            policy_id,
        )
        return

    desired_config = build_pangolin_rules(template, ip_records)
    if should_update_pangolin_policy(current_policy, desired_config):
        update_pangolin_policy_rules(base_url, api_key, policy_id, desired_config, pjson=pjson)


# Aliases for backwards compatibility
getHostingerFirewalls = get_hostinger_firewalls
updateFirewallRules = update_firewall_rules
resolveDomain = resolve_domain


def main():
    hostinger_api_key = os.getenv("HOSTINGER_API_KEY") or os.getenv("APIKEY")
    pangolin_url = os.getenv("PANGOLIN_URL")
    pangolin_api_key = os.getenv("PANGOLIN_API_KEY")

    hostinger_enabled = bool(hostinger_api_key)
    pangolin_enabled = bool(pangolin_url and pangolin_api_key)

    if bool(pangolin_url) != bool(pangolin_api_key):
        logger.warning(
            "Both PANGOLIN_URL and PANGOLIN_API_KEY must be set to enable Pangolin integration."
        )

    if not hostinger_enabled and not pangolin_enabled:
        logger.error(
            "No integration configured. Set HOSTINGER_API_KEY (or APIKEY) and/or PANGOLIN_URL + PANGOLIN_API_KEY. Exiting..."
        )
        sys.exit(1)

    if not (domains_env := os.getenv("DOMAINS")):
        logger.error("DOMAINS is missing. Exiting...")
        sys.exit(1)

    try:
        interval = int(os.getenv("INTERVAL", "300"))
    except ValueError:
        logger.warning("Invalid INTERVAL value. Using default of 300 seconds.")
        interval = 300

    firewall_name = os.getenv("FIREWALL_NAME")
    pangolin_policy_id = os.getenv("PANGOLIN_POLICY_ID")
    pangolin_org_id = os.getenv("PANGOLIN_ORG_ID")
    pangolin_policy_name = os.getenv("PANGOLIN_POLICY_NAME")
    pangolin_base_url = normalize_pangolin_url(pangolin_url) if pangolin_enabled else None

    record_types_env = os.getenv("RECORD_TYPES", "A")
    record_types = tuple(
        r.strip().upper() for r in record_types_env.split(",") if r.strip()
    )

    pjson = os.getenv("PRETTY_JSON", "").lower() == "true"
    domains = [d.strip() for d in domains_env.split(",") if d.strip()]

    logger.info("Starting DNS Pinger")
    logger.info("Monitoring domains: %s (types: %s)", domains, ", ".join(record_types))
    if hostinger_enabled:
        logger.info("Hostinger integration enabled (config: %s)", get_hostinger_config_path())
    if pangolin_enabled:
        logger.info(
            "Pangolin integration enabled (endpoint: %s, config: %s)",
            pangolin_base_url,
            get_pangolin_config_path(),
        )
    logger.info("Check interval: %d seconds", interval)

    while not shutdown_event.is_set():
        # 1. Resolve DNS records once per cycle for all enabled integrations
        ip_records = []
        for domain in domains:
            ip_records.extend(resolve_domain(domain, record_types))

        # Guard: do not wipe rules if DNS resolution failed
        if not ip_records:
            logger.warning(
                "DNS resolution returned no records. Skipping update to avoid wiping rules..."
            )
            shutdown_event.wait(interval)
            continue

        # 2. Sync Hostinger Firewall if enabled
        if hostinger_enabled:
            sync_hostinger(hostinger_api_key, firewall_name, ip_records, pjson)

        # 3. Sync Pangolin Shared Policy if enabled
        if pangolin_enabled:
            sync_pangolin(
                pangolin_base_url,
                pangolin_api_key,
                pangolin_policy_id,
                pangolin_org_id,
                pangolin_policy_name,
                ip_records,
                pjson,
            )

        shutdown_event.wait(interval)

    logger.info("DNS Pinger stopped.")


if __name__ == "__main__":
    main()
