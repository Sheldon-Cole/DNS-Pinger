from collections import Counter
from dns import resolver
import hostinger_api
import json
import logging
import os
import signal
import sys
import threading
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


def get_config_path():
    if env_path := os.getenv("CONFIG_PATH"):
        if os.path.isfile(env_path):
            return env_path
        if os.path.isdir(env_path):
            candidate = os.path.join(env_path, "firewall-config.yaml")
            if os.path.exists(candidate):
                return candidate
        return env_path

    # Check common container mount points and local paths
    candidates = [
        "/app/config/firewall-config.yaml",
        "/app/config",  # In case a file was directly mounted to /app/config
        "./config/firewall-config.yaml",
        "./firewall-config.yaml",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    return "./config/firewall-config.yaml"


def load_firewall_template(config_path):
    try:
        if os.path.isdir(config_path):
            config_path = os.path.join(config_path, "firewall-config.yaml")
        with open(config_path, "r") as file:
            return yaml.safe_load(file)
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError) as e:
        logger.error(
            "Configuration error at '%s' (%s: %s). "
            "Please check your volume mount or copy 'config/firewall-config.yaml.example'.",
            config_path,
            type(e).__name__,
            e,
        )
        return None
    except yaml.YAMLError as e:
        logger.error("Error parsing YAML from '%s': %s", config_path, e)
        return None


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
        logger.info("Firewall rules match desired configuration. No updates necessary.")
        return False
    else:
        logger.info(
            "Firewall rules mismatch detected (DNS records or config file changed). Updating rules..."
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
            logger.info("Successfully updated firewall rules (Firewall ID: %s).", firewall_id)
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


# Aliases for backwards compatibility
getHostingerFirewalls = get_hostinger_firewalls
updateFirewallRules = update_firewall_rules
resolveDomain = resolve_domain


def main():
    if not (api_key := os.getenv("APIKEY")):
        logger.error("APIKEY is missing. Exiting...")
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
    if not firewall_name:
        logger.info("FIREWALL_NAME is not set. Will use the first available firewall...")

    record_types_env = os.getenv("RECORD_TYPES", "A")
    record_types = tuple(
        r.strip().upper() for r in record_types_env.split(",") if r.strip()
    )

    pjson = os.getenv("PRETTY_JSON", "").lower() == "true"
    domains = [d.strip() for d in domains_env.split(",") if d.strip()]
    config_path = get_config_path()

    logger.info("Starting DNS Pinger")
    logger.info("Monitoring domains: %s (types: %s)", domains, ", ".join(record_types))
    logger.info("Using firewall config: %s", config_path)
    logger.info("Check interval: %d seconds", interval)

    while not shutdown_event.is_set():
        # 1. Load the firewall template dynamically on each check
        template = load_firewall_template(config_path)
        if template is None:
            logger.warning("Skipping cycle: configuration file issue with '%s'...", config_path)
            shutdown_event.wait(interval)
            continue

        # 2. Resolve DNS records
        ip_records = []
        for domain in domains:
            ip_records.extend(resolve_domain(domain, record_types))

        # Guard: do not wipe rules if DNS resolution failed
        if not ip_records:
            logger.warning(
                "DNS resolution returned no records. Skipping update to avoid wiping firewall rules..."
            )
            shutdown_event.wait(interval)
            continue

        # 3. Query Hostinger API
        api_response = get_hostinger_firewalls(api_key, pjson)
        if api_response is None:
            logger.warning("Hostinger API check failed. Skipping this cycle...")
            shutdown_event.wait(interval)
            continue

        api_dict = api_response.to_dict()

        # 4. Find target firewall ID
        target_fw = None
        for fw in api_dict.get("data", []):
            if firewall_name is None or fw.get("name") == firewall_name:
                target_fw = fw
                break

        if target_fw is None:
            if firewall_name:
                logger.warning(
                    "Firewall '%s' not found in Hostinger account. Skipping cycle...",
                    firewall_name,
                )
            else:
                logger.warning("No firewalls found in Hostinger account. Skipping cycle...")
            shutdown_event.wait(interval)
            continue

        firewall_id = target_fw["id"]

        # 5. Build desired rules using latest config template and resolved IPs
        desired_config = build_firewall_rules(template, ip_records, firewall_id)

        # 6. Check if current rules in Hostinger match our desired rules
        if should_update_firewall(target_fw, desired_config):
            update_firewall_rules(api_key, desired_config, firewall_id, pjson)

        shutdown_event.wait(interval)

    logger.info("DNS Pinger stopped.")


if __name__ == "__main__":
    main()
