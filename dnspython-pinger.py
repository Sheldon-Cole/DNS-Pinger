from collections import Counter
from dns import resolver
import hashlib
import hostinger_api
import json
import logging
import os
import re
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


_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")
_LAST_SYNCED_AUTH_DIGESTS = {}
_PANGOLIN_ROLE_CACHE = {}
_PANGOLIN_USER_CACHE = {}
_PANGOLIN_IDP_CACHE = {}


def expand_env_vars(value):
    if isinstance(value, str):
        def _replace(match):
            var_name = match.group(1)
            default_val = match.group(2)
            env_val = os.getenv(var_name)
            if env_val is not None:
                return env_val
            if default_val is not None:
                return default_val
            logger.warning("Environment variable '%s' referenced in config is not set.", var_name)
            return ""

        return _ENV_VAR_PATTERN.sub(_replace, value)
    elif isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    elif isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
    return value


def load_yaml_template(config_path, default_filename="hostinger-config.yaml"):
    try:
        if os.path.isdir(config_path):
            config_path = os.path.join(config_path, default_filename)
        with open(config_path, "r") as file:
            raw_data = yaml.safe_load(file)
            return expand_env_vars(raw_data)
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

_DNS_RECORD_TEMPLATE_RE = re.compile(
    r"^\{\{\s*(?:dns_record|cname|domain)(?:\s*:\s*(.+?))?\s*\}\}$",
    re.IGNORECASE,
)
_RULE_DOMAIN_KEYS = ("cname", "domain", "domains")


def _normalize_domain_list(raw):
    if isinstance(raw, str):
        return [d.strip() for d in raw.split(",") if d.strip()]
    if isinstance(raw, (list, tuple, set)):
        result = []
        for item in raw:
            if item is not None:
                result.extend(d.strip() for d in str(item).split(",") if d.strip())
        return result
    return []


def parse_rule_dns_targets(rule, detail_key="source_detail"):
    for k in _RULE_DOMAIN_KEYS:
        if k in rule and rule[k] is not None:
            domains = _normalize_domain_list(rule[k])
            if domains:
                return True, domains

    raw_detail = str(rule.get(detail_key, "")).strip()
    match = _DNS_RECORD_TEMPLATE_RE.match(raw_detail)
    if match:
        target_part = match.group(1)
        if target_part:
            domains = _normalize_domain_list(target_part)
            if domains:
                return True, domains
        return True, None

    return False, None


def resolve_domains_cached(target_domains, record_types=("A",), domain_ip_map=None):
    if domain_ip_map is None:
        domain_ip_map = {}

    resolved_ips = []
    for d in target_domains:
        clean_domain = d.strip()
        if not clean_domain:
            continue
        key = clean_domain.lower()
        if key not in domain_ip_map:
            domain_ip_map[key] = resolve_domain(clean_domain, record_types)
        for ip in domain_ip_map[key]:
            if ip not in resolved_ips:
                resolved_ips.append(ip)

    return resolved_ips


def build_firewall_rules(
    template_config, ip_records, firewall_id, record_types=("A",), domain_ip_map=None
):
    final_rules = []
    for rule in template_config.get("rules", []):
        is_dynamic, specific_domains = parse_rule_dns_targets(
            rule, detail_key="source_detail"
        )
        base_rule = {k: v for k, v in rule.items() if k not in _RULE_DOMAIN_KEYS}

        raw_source = str(base_rule.get("source", "")).strip().lower()
        raw_detail = str(base_rule.get("source_detail", "")).strip()
        if raw_source == "any" and ((raw_detail and raw_detail.lower() != "any") or is_dynamic):
            logger.warning(
                "Hostinger rule (%s %s port %s) has 'source: any' with 'source_detail: %s'. "
                "Replacing 'source: any' with 'source: custom'.",
                base_rule.get("action"),
                base_rule.get("protocol"),
                base_rule.get("port"),
                raw_detail or specific_domains,
            )
            base_rule["source"] = "custom"

        if not is_dynamic:
            final_rules.append(base_rule)
        elif specific_domains:
            rule_ips = resolve_domains_cached(
                specific_domains, record_types=record_types, domain_ip_map=domain_ip_map
            )
            if not rule_ips:
                logger.warning(
                    "DNS resolution for rule-specific domain(s) %s returned no records. "
                    "Skipping Hostinger sync this cycle to avoid dropping rules...",
                    specific_domains,
                )
                return None
            for ip in rule_ips:
                new_rule = base_rule.copy()
                new_rule["source_detail"] = ip
                final_rules.append(new_rule)
        else:
            for ip in ip_records:
                new_rule = base_rule.copy()
                new_rule["source_detail"] = ip
                final_rules.append(new_rule)

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


def build_pangolin_rules(
    template_config, ip_records, record_types=("A",), domain_ip_map=None
):
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

        is_dynamic, specific_domains = parse_rule_dns_targets(
            rule, detail_key="value"
        )

        if not is_dynamic:
            final_rules.append(
                {
                    "action": action,
                    "match": match_type,
                    "value": raw_value,
                    "priority": priority,
                    "enabled": enabled,
                }
            )
        elif specific_domains:
            rule_ips = resolve_domains_cached(
                specific_domains, record_types=record_types, domain_ip_map=domain_ip_map
            )
            if not rule_ips:
                logger.warning(
                    "DNS resolution for rule-specific domain(s) %s returned no records. "
                    "Skipping Pangolin rules sync this cycle to avoid dropping rules...",
                    specific_domains,
                )
                return None
            for ip in rule_ips:
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


def _sha256_digest(text):
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def resolve_pangolin_role_ids(
    base_url, api_key, org_id, current_policy, roles_input, role_ids_input, pjson=False
):
    resolved_ids = []
    seen = set()

    def _add_id(rid):
        rid_int = int(rid)
        if rid_int not in seen:
            seen.add(rid_int)
            resolved_ids.append(rid_int)

    for item in role_ids_input or []:
        if isinstance(item, int) or (isinstance(item, str) and item.strip().isdigit()):
            _add_id(item)
        elif item:
            roles_input = list(roles_input or []) + [item]

    pending_names = []
    for item in roles_input or []:
        if isinstance(item, int) or (isinstance(item, str) and item.strip().isdigit()):
            _add_id(item)
        elif isinstance(item, str) and item.strip():
            pending_names.append(item.strip())

    if not pending_names:
        return resolved_ids

    # Check roles already attached to the current policy or cached first
    current_roles_by_name = {
        str(r.get("name") or "").strip().lower(): r.get("roleId")
        for r in current_policy.get("roles", [])
        if r.get("name") and r.get("roleId") is not None
    }
    org_cache_prefix = str(org_id or "").strip().lower()

    still_unresolved = []
    for name in pending_names:
        key = name.lower()
        if key in current_roles_by_name:
            _add_id(current_roles_by_name[key])
        elif (org_cache_prefix, key) in _PANGOLIN_ROLE_CACHE:
            cached_id, is_admin = _PANGOLIN_ROLE_CACHE[(org_cache_prefix, key)]
            if not is_admin and cached_id is not None:
                _add_id(cached_id)
        else:
            still_unresolved.append(name)

    if not still_unresolved:
        return resolved_ids

    if not org_id:
        logger.error(
            "PANGOLIN_ORG_ID (or org_id in pangolin-config.yaml) is required to resolve role names %s.",
            still_unresolved,
        )
        return None

    encoded_org = urllib.parse.quote(str(org_id), safe="")
    resp = pangolin_api_request(
        base_url,
        api_key,
        "GET",
        f"org/{encoded_org}/roles?pageSize=100&page=1",
        pjson=pjson,
    )
    if not resp or not isinstance(resp.get("data"), dict):
        logger.error("Failed to fetch roles for Pangolin org '%s'.", org_id)
        return None

    org_roles = resp["data"].get("roles", [])
    org_roles_by_name = {
        str(r.get("name") or "").strip().lower(): r for r in org_roles if r.get("name")
    }

    for name in still_unresolved:
        key = name.lower()
        matched = org_roles_by_name.get(key)
        if not matched:
            available = [
                f"'{r.get('name')}' (id={r.get('roleId')})"
                for r in org_roles
                if not r.get("isAdmin")
            ]
            logger.warning(
                "Role '%s' not found in Pangolin org '%s'. Available roles: %s",
                name,
                org_id,
                ", ".join(available) if available else "none",
            )
            return None
        is_admin = bool(matched.get("isAdmin"))
        _PANGOLIN_ROLE_CACHE[(org_cache_prefix, key)] = (matched.get("roleId"), is_admin)
        if is_admin:
            logger.info(
                "Role '%s' is an organization Admin role (automatically granted access in Pangolin); omitting from explicit roleIds.",
                matched.get("name"),
            )
            continue
        _add_id(matched.get("roleId"))

    return resolved_ids


def resolve_pangolin_user_ids(
    base_url, api_key, org_id, current_policy, users_input, user_ids_input, pjson=False
):
    resolved_ids = []
    seen = set()

    def _add_uid(uid):
        uid_str = str(uid).strip()
        if uid_str and uid_str not in seen:
            seen.add(uid_str)
            resolved_ids.append(uid_str)

    for uid in user_ids_input or []:
        if uid is not None and str(uid).strip():
            _add_uid(uid)

    pending_users = [
        str(u).strip() for u in (users_input or []) if u is not None and str(u).strip()
    ]
    if not pending_users:
        return resolved_ids

    # Check users already attached to the current policy or cached first
    current_user_map = {}
    for u in current_policy.get("users", []):
        uid = u.get("userId") or u.get("id")
        if not uid:
            continue
        for field in ("userId", "id", "email", "username", "name"):
            val = str(u.get(field) or "").strip().lower()
            if val:
                current_user_map[val] = uid
    org_cache_prefix = str(org_id or "").strip().lower()

    still_unresolved = []
    for identifier in pending_users:
        key = identifier.lower()
        if key in current_user_map:
            _add_uid(current_user_map[key])
        elif (org_cache_prefix, key) in _PANGOLIN_USER_CACHE:
            _add_uid(_PANGOLIN_USER_CACHE[(org_cache_prefix, key)])
        else:
            still_unresolved.append(identifier)

    if not still_unresolved:
        return resolved_ids

    if not org_id:
        logger.error(
            "PANGOLIN_ORG_ID (or org_id in pangolin-config.yaml) is required to resolve user names/emails %s.",
            still_unresolved,
        )
        return None

    encoded_org = urllib.parse.quote(str(org_id), safe="")
    resp = pangolin_api_request(
        base_url,
        api_key,
        "GET",
        f"org/{encoded_org}/users?pageSize=100&page=1",
        pjson=pjson,
    )
    if not resp or not isinstance(resp.get("data"), dict):
        logger.error("Failed to fetch users for Pangolin org '%s'.", org_id)
        return None

    org_users = resp["data"].get("users", [])
    org_user_map = {}
    for u in org_users:
        uid = u.get("id") or u.get("userId")
        if not uid:
            continue
        for field in ("id", "userId", "email", "username", "name"):
            val = str(u.get(field) or "").strip().lower()
            if val:
                org_user_map[val] = uid

    for identifier in still_unresolved:
        key = identifier.lower()
        matched_uid = org_user_map.get(key)
        if not matched_uid:
            available = [
                f"'{u.get('email') or u.get('username') or u.get('name')}' (id={u.get('id') or u.get('userId')})"
                for u in org_users
            ]
            logger.warning(
                "User '%s' not found in Pangolin org '%s'. Available users: %s",
                identifier,
                org_id,
                ", ".join(available) if available else "none",
            )
            return None
        _PANGOLIN_USER_CACHE[(org_cache_prefix, key)] = matched_uid
        _add_uid(matched_uid)

    return resolved_ids


def resolve_pangolin_idp_id(base_url, api_key, idp_input, pjson=False):
    if idp_input is None or idp_input is False or str(idp_input).strip() == "":
        return True, None

    if isinstance(idp_input, int) or (
        isinstance(idp_input, str) and idp_input.strip().isdigit()
    ):
        return True, int(idp_input)

    target_name = str(idp_input).strip().lower()
    if target_name in _PANGOLIN_IDP_CACHE:
        return True, _PANGOLIN_IDP_CACHE[target_name]

    resp = pangolin_api_request(
        base_url,
        api_key,
        "GET",
        "idp?limit=1000&offset=0",
        pjson=pjson,
    )
    if not resp or not isinstance(resp.get("data"), dict):
        logger.error("Failed to fetch Identity Providers from Pangolin API.")
        return False, None

    idps = resp["data"].get("idps", [])
    for item in idps:
        if str(item.get("name") or "").strip().lower() == target_name:
            resolved_id = item.get("idpId")
            _PANGOLIN_IDP_CACHE[target_name] = resolved_id
            return True, resolved_id

    available = [f"'{i.get('name')}' (id={i.get('idpId')})" for i in idps]
    logger.warning(
        "Identity Provider '%s' not found in Pangolin. Available IdPs: %s",
        idp_input,
        ", ".join(available) if available else "none",
    )
    return False, None


def extract_pangolin_auth_config(template_config):
    auth_cfg = {}
    if isinstance(template_config.get("auth"), dict):
        auth_cfg.update(template_config["auth"])

    top_level_keys = (
        "sso",
        "access_control",
        "email_whitelist",
        "whitelist",
        "password",
        "pincode",
        "pin_code",
        "pin",
        "header_auth",
        "headerAuth",
        "mtls_enabled",
        "mtlsEnabled",
        "mtls",
    )
    for k in top_level_keys:
        if k in template_config and k not in auth_cfg:
            auth_cfg[k] = template_config[k]

    return auth_cfg


def sync_pangolin_sso(base_url, api_key, policy_id, org_id, current_policy, sso_cfg, pjson=False):
    current_sso = bool(current_policy.get("sso", False))
    current_role_ids = [
        int(r["roleId"])
        for r in current_policy.get("roles", [])
        if r.get("roleId") is not None
    ]
    current_user_ids = [
        str(u.get("userId") or u.get("id"))
        for u in current_policy.get("users", [])
        if u.get("userId") or u.get("id")
    ]
    current_idp_id = current_policy.get("idpId")

    if isinstance(sso_cfg, bool):
        desired_sso = sso_cfg
        desired_role_ids = current_role_ids
        desired_user_ids = current_user_ids
        desired_idp_id = current_idp_id
    elif isinstance(sso_cfg, dict):
        desired_sso = bool(sso_cfg.get("enabled", sso_cfg.get("sso", True)))

        if "roles" in sso_cfg or "role_ids" in sso_cfg or "roleIds" in sso_cfg:
            roles_in = sso_cfg.get("roles", [])
            role_ids_in = sso_cfg.get("role_ids", sso_cfg.get("roleIds", []))
            desired_role_ids = resolve_pangolin_role_ids(
                base_url,
                api_key,
                org_id,
                current_policy,
                roles_in,
                role_ids_in,
                pjson=pjson,
            )
            if desired_role_ids is None:
                logger.warning("Skipping Pangolin SSO access-control sync due to unresolved roles.")
                return
        else:
            desired_role_ids = current_role_ids

        if "users" in sso_cfg or "user_ids" in sso_cfg or "userIds" in sso_cfg:
            users_in = sso_cfg.get("users", [])
            user_ids_in = sso_cfg.get("user_ids", sso_cfg.get("userIds", []))
            desired_user_ids = resolve_pangolin_user_ids(
                base_url,
                api_key,
                org_id,
                current_policy,
                users_in,
                user_ids_in,
                pjson=pjson,
            )
            if desired_user_ids is None:
                logger.warning("Skipping Pangolin SSO access-control sync due to unresolved users.")
                return
        else:
            desired_user_ids = current_user_ids

        idp_keys = ("skip_to_idp_id", "skipToIdpId", "idp_id", "idpId", "idp")
        if any(k in sso_cfg for k in idp_keys):
            raw_idp = next((sso_cfg[k] for k in idp_keys if k in sso_cfg), None)
            ok, desired_idp_id = resolve_pangolin_idp_id(
                base_url, api_key, raw_idp, pjson=pjson
            )
            if not ok:
                logger.warning("Skipping Pangolin SSO access-control sync due to unresolved IdP.")
                return
        else:
            desired_idp_id = current_idp_id
    else:
        logger.warning("Invalid Pangolin 'sso' configuration format; expected boolean or mapping.")
        return

    if (
        current_sso == desired_sso
        and set(current_role_ids) == set(desired_role_ids)
        and set(current_user_ids) == set(desired_user_ids)
        and current_idp_id == desired_idp_id
    ):
        logger.debug("Pangolin SSO access-control settings match desired configuration.")
        return

    logger.info("Pangolin SSO access-control mismatch detected. Updating access-control...")
    payload = {
        "sso": desired_sso,
        "roleIds": desired_role_ids,
        "userIds": desired_user_ids,
        "skipToIdpId": desired_idp_id,
    }
    resp = pangolin_api_request(
        base_url,
        api_key,
        "POST",
        f"resource-policy/{policy_id}/access-control",
        payload=payload,
        pjson=pjson,
    )
    if resp and resp.get("success"):
        logger.info("Successfully updated Pangolin SSO access-control (Policy ID: %s).", policy_id)


def sync_pangolin_email_whitelist(base_url, api_key, policy_id, current_policy, wl_cfg, pjson=False):
    current_enabled = bool(current_policy.get("emailWhitelistEnabled", False))
    current_emails = {
        str(e.get("email") or "").strip().lower()
        for e in current_policy.get("emailWhiteList", [])
        if e.get("email")
    }

    if isinstance(wl_cfg, bool):
        desired_enabled = wl_cfg
        desired_emails = sorted(current_emails) if desired_enabled else []
    elif isinstance(wl_cfg, list):
        desired_enabled = len(wl_cfg) > 0
        desired_emails = [str(e).strip().lower() for e in wl_cfg if str(e).strip()]
    elif isinstance(wl_cfg, dict):
        raw_emails = wl_cfg.get("emails", []) or []
        desired_emails = [str(e).strip().lower() for e in raw_emails if str(e).strip()]
        desired_enabled = bool(
            wl_cfg.get(
                "enabled",
                wl_cfg.get("emailWhitelistEnabled", len(desired_emails) > 0),
            )
        )
    else:
        logger.warning("Invalid Pangolin 'email_whitelist' configuration format.")
        return

    if current_enabled == desired_enabled and (
        not desired_enabled or current_emails == set(desired_emails)
    ):
        logger.debug("Pangolin email whitelist settings match desired configuration.")
        return

    logger.info("Pangolin email whitelist mismatch detected. Updating email whitelist...")
    payload = {
        "emailWhitelistEnabled": desired_enabled,
        "emails": desired_emails if desired_enabled else [],
    }
    resp = pangolin_api_request(
        base_url,
        api_key,
        "POST",
        f"resource-policy/{policy_id}/whitelist",
        payload=payload,
        pjson=pjson,
    )
    if resp and resp.get("success"):
        logger.info("Successfully updated Pangolin email whitelist (Policy ID: %s).", policy_id)


def sync_pangolin_password(base_url, api_key, policy_id, current_policy, pw_cfg, pjson=False):
    has_current_pw = current_policy.get("passwordId") is not None
    cache_key = (str(policy_id), "password")

    if pw_cfg is None or pw_cfg is False:
        desired_enabled = False
        desired_pw = None
    elif isinstance(pw_cfg, str):
        desired_pw = pw_cfg
        desired_enabled = bool(desired_pw)
    elif isinstance(pw_cfg, dict):
        desired_pw = pw_cfg.get("value", pw_cfg.get("password"))
        desired_enabled = bool(pw_cfg.get("enabled", desired_pw is not None and desired_pw != ""))
        if not desired_enabled:
            desired_pw = None
    else:
        logger.warning("Invalid Pangolin 'password' configuration format.")
        return

    if not desired_enabled or not desired_pw:
        if not has_current_pw:
            _LAST_SYNCED_AUTH_DIGESTS.pop(cache_key, None)
            logger.debug("Pangolin policy password protection is already disabled.")
            return
        logger.info("Removing Pangolin policy password protection (Policy ID: %s)...", policy_id)
        resp = pangolin_api_request(
            base_url,
            api_key,
            "POST",
            f"resource-policy/{policy_id}/password",
            payload={"password": None},
            pjson=pjson,
        )
        if resp and resp.get("success"):
            _LAST_SYNCED_AUTH_DIGESTS.pop(cache_key, None)
            logger.info("Successfully removed Pangolin policy password (Policy ID: %s).", policy_id)
        return

    desired_pw_str = str(desired_pw)
    if not (4 <= len(desired_pw_str) <= 100):
        logger.error(
            "Pangolin policy password must be between 4 and 100 characters (got %d). Skipping password sync...",
            len(desired_pw_str),
        )
        return

    digest = _sha256_digest(desired_pw_str)
    if has_current_pw and _LAST_SYNCED_AUTH_DIGESTS.get(cache_key) == digest:
        logger.debug("Pangolin policy password matches last synced digest.")
        return

    logger.info("Synchronizing Pangolin policy password protection (Policy ID: %s)...", policy_id)
    resp = pangolin_api_request(
        base_url,
        api_key,
        "POST",
        f"resource-policy/{policy_id}/password",
        payload={"password": desired_pw_str},
        pjson=pjson,
    )
    if resp and resp.get("success"):
        _LAST_SYNCED_AUTH_DIGESTS[cache_key] = digest
        logger.info("Successfully updated Pangolin policy password (Policy ID: %s).", policy_id)


def sync_pangolin_pincode(base_url, api_key, policy_id, current_policy, pin_cfg, pjson=False):
    has_current_pin = current_policy.get("pincodeId") is not None
    cache_key = (str(policy_id), "pincode")

    if pin_cfg is None or pin_cfg is False:
        desired_enabled = False
        desired_pin = None
    elif isinstance(pin_cfg, (str, int)):
        desired_pin = str(pin_cfg).strip()
        desired_enabled = bool(desired_pin)
    elif isinstance(pin_cfg, dict):
        raw_val = pin_cfg.get("value", pin_cfg.get("pincode", pin_cfg.get("pin")))
        desired_pin = str(raw_val).strip() if raw_val is not None else None
        desired_enabled = bool(pin_cfg.get("enabled", desired_pin is not None and desired_pin != ""))
        if not desired_enabled:
            desired_pin = None
    else:
        logger.warning("Invalid Pangolin 'pincode' configuration format.")
        return

    if not desired_enabled or not desired_pin:
        if not has_current_pin:
            _LAST_SYNCED_AUTH_DIGESTS.pop(cache_key, None)
            logger.debug("Pangolin policy PIN code protection is already disabled.")
            return
        logger.info("Removing Pangolin policy PIN code protection (Policy ID: %s)...", policy_id)
        resp = pangolin_api_request(
            base_url,
            api_key,
            "POST",
            f"resource-policy/{policy_id}/pincode",
            payload={"pincode": None},
            pjson=pjson,
        )
        if resp and resp.get("success"):
            _LAST_SYNCED_AUTH_DIGESTS.pop(cache_key, None)
            logger.info("Successfully removed Pangolin policy PIN code (Policy ID: %s).", policy_id)
        return

    if not re.fullmatch(r"\d{6}", desired_pin):
        logger.error(
            "Pangolin policy pincode must be an exact 6-digit numeric string (e.g. '123456'). Skipping pincode sync..."
        )
        return

    digest = _sha256_digest(desired_pin)
    if has_current_pin and _LAST_SYNCED_AUTH_DIGESTS.get(cache_key) == digest:
        logger.debug("Pangolin policy PIN code matches last synced digest.")
        return

    logger.info("Synchronizing Pangolin policy PIN code protection (Policy ID: %s)...", policy_id)
    resp = pangolin_api_request(
        base_url,
        api_key,
        "POST",
        f"resource-policy/{policy_id}/pincode",
        payload={"pincode": desired_pin},
        pjson=pjson,
    )
    if resp and resp.get("success"):
        _LAST_SYNCED_AUTH_DIGESTS[cache_key] = digest
        logger.info("Successfully updated Pangolin policy PIN code (Policy ID: %s).", policy_id)


def sync_pangolin_header_auth(base_url, api_key, policy_id, current_policy, ha_cfg, pjson=False):
    current_ha = current_policy.get("headerAuth") or {}
    has_current_ha = current_ha.get("id") is not None
    current_ext = bool(
        current_ha.get(
            "extendedCompatibility",
            current_ha.get("extendedCompability", False),
        )
    )
    cache_key = (str(policy_id), "header_auth")

    if ha_cfg is None or ha_cfg is False:
        desired_enabled = False
        user_val = None
        pw_val = None
        ext_val = False
    elif isinstance(ha_cfg, dict):
        user_val = ha_cfg.get("user", ha_cfg.get("username"))
        pw_val = ha_cfg.get("password", ha_cfg.get("value"))
        ext_val = bool(
            ha_cfg.get(
                "extended_compatibility",
                ha_cfg.get("extendedCompatibility", False),
            )
        )
        desired_enabled = bool(
            ha_cfg.get("enabled", bool(user_val and pw_val))
        )
    else:
        logger.warning("Invalid Pangolin 'header_auth' configuration format.")
        return

    if not desired_enabled:
        if not has_current_ha:
            _LAST_SYNCED_AUTH_DIGESTS.pop(cache_key, None)
            logger.debug("Pangolin policy Header Authentication is already disabled.")
            return
        logger.info("Removing Pangolin policy Header Authentication (Policy ID: %s)...", policy_id)
        resp = pangolin_api_request(
            base_url,
            api_key,
            "POST",
            f"resource-policy/{policy_id}/header-auth",
            payload={"headerAuth": None},
            pjson=pjson,
        )
        if resp and resp.get("success"):
            _LAST_SYNCED_AUTH_DIGESTS.pop(cache_key, None)
            logger.info("Successfully removed Pangolin policy Header Authentication (Policy ID: %s).", policy_id)
        return

    user_str = str(user_val or "")
    pw_str = str(pw_val or "")
    if not (4 <= len(user_str) <= 100) or not (4 <= len(pw_str) <= 100):
        logger.error(
            "Pangolin header_auth 'user' and 'password' must each be between 4 and 100 characters. Skipping header_auth sync..."
        )
        return

    digest = _sha256_digest(f"{user_str}:{pw_str}:{ext_val}")
    if (
        has_current_ha
        and current_ext == ext_val
        and _LAST_SYNCED_AUTH_DIGESTS.get(cache_key) == digest
    ):
        logger.debug("Pangolin policy Header Authentication matches last synced digest.")
        return

    logger.info("Synchronizing Pangolin policy Header Authentication (Policy ID: %s)...", policy_id)
    payload = {
        "headerAuth": {
            "user": user_str,
            "password": pw_str,
            "extendedCompatibility": ext_val,
        }
    }
    resp = pangolin_api_request(
        base_url,
        api_key,
        "POST",
        f"resource-policy/{policy_id}/header-auth",
        payload=payload,
        pjson=pjson,
    )
    if resp and resp.get("success"):
        _LAST_SYNCED_AUTH_DIGESTS[cache_key] = digest
        logger.info("Successfully updated Pangolin policy Header Authentication (Policy ID: %s).", policy_id)


def sync_pangolin_mtls(base_url, api_key, policy_id, current_policy, mtls_cfg, pjson=False):
    current_mtls = bool(current_policy.get("mtlsEnabled", False))
    if isinstance(mtls_cfg, dict):
        desired_mtls = bool(mtls_cfg.get("enabled", mtls_cfg.get("mtlsEnabled", False)))
    else:
        desired_mtls = bool(mtls_cfg)

    if current_mtls == desired_mtls:
        logger.debug("Pangolin policy mTLS setting matches desired configuration.")
        return

    logger.info(
        "Pangolin policy mTLS mismatch detected (desired: %s). Updating policy...",
        desired_mtls,
    )
    resp = pangolin_api_request(
        base_url,
        api_key,
        "POST",
        f"resource-policy/{policy_id}",
        payload={"mtlsEnabled": desired_mtls},
        pjson=pjson,
    )
    if resp and resp.get("success"):
        logger.info("Successfully updated Pangolin policy mTLS setting (Policy ID: %s).", policy_id)


def sync_pangolin_auth(base_url, api_key, policy_id, org_id, current_policy, template_config, pjson=False):
    auth_cfg = extract_pangolin_auth_config(template_config)
    if not auth_cfg:
        return

    if "sso" in auth_cfg or "access_control" in auth_cfg:
        sso_cfg = auth_cfg.get("sso", auth_cfg.get("access_control"))
        sync_pangolin_sso(
            base_url, api_key, policy_id, org_id, current_policy, sso_cfg, pjson=pjson
        )

    if "email_whitelist" in auth_cfg or "whitelist" in auth_cfg:
        wl_cfg = auth_cfg.get("email_whitelist", auth_cfg.get("whitelist"))
        sync_pangolin_email_whitelist(
            base_url, api_key, policy_id, current_policy, wl_cfg, pjson=pjson
        )

    if "password" in auth_cfg:
        sync_pangolin_password(
            base_url, api_key, policy_id, current_policy, auth_cfg["password"], pjson=pjson
        )

    pin_keys = ("pincode", "pin_code", "pin")
    if any(k in auth_cfg for k in pin_keys):
        pin_cfg = next(auth_cfg[k] for k in pin_keys if k in auth_cfg)
        sync_pangolin_pincode(
            base_url, api_key, policy_id, current_policy, pin_cfg, pjson=pjson
        )

    ha_keys = ("header_auth", "headerAuth")
    if any(k in auth_cfg for k in ha_keys):
        ha_cfg = next(auth_cfg[k] for k in ha_keys if k in auth_cfg)
        sync_pangolin_header_auth(
            base_url, api_key, policy_id, current_policy, ha_cfg, pjson=pjson
        )

    mtls_keys = ("mtls_enabled", "mtlsEnabled", "mtls")
    if any(k in auth_cfg for k in mtls_keys):
        mtls_cfg = next(auth_cfg[k] for k in mtls_keys if k in auth_cfg)
        sync_pangolin_mtls(
            base_url, api_key, policy_id, current_policy, mtls_cfg, pjson=pjson
        )


def pretty_json(data):
    return json.dumps(data, indent=4, default=str)


def resolve_domain(domain, record_types=("A",)):
    ip_addresses = []
    clean_domain = domain.strip().rstrip(".")
    for rtype in record_types:
        try:
            records = resolver.resolve(clean_domain, rtype)
            canonical = getattr(records, "canonical_name", None)
            canonical_str = str(canonical).rstrip(".") if canonical else ""
            is_cname = bool(
                canonical_str and canonical_str.lower() != clean_domain.lower()
            )
            for rdata in records:
                address = getattr(rdata, "address", None)
                if address:
                    if is_cname:
                        logger.info(
                            "%s (CNAME -> %s) - %s Record: %s",
                            clean_domain,
                            canonical_str,
                            rtype,
                            address,
                        )
                    else:
                        logger.info("%s - %s Record: %s", clean_domain, rtype, address)
                    if address not in ip_addresses:
                        ip_addresses.append(address)
        except resolver.NoAnswer:
            logger.debug("%s has no %s records", clean_domain, rtype)
        except resolver.NXDOMAIN:
            logger.warning("Domain does not exist: %s", clean_domain)
        except Exception as e:
            logger.error("Error fetching %s record for %s: %s", rtype, clean_domain, e)
    return ip_addresses


def sync_hostinger(
    api_key, firewall_name, ip_records, pjson, record_types=("A",), domain_ip_map=None
):
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
    desired_config = build_firewall_rules(
        template,
        ip_records,
        firewall_id,
        record_types=record_types,
        domain_ip_map=domain_ip_map,
    )
    if desired_config is None:
        return

    if should_update_firewall(target_fw, desired_config):
        update_firewall_rules(api_key, desired_config, firewall_id, pjson)


def sync_pangolin(
    base_url,
    api_key,
    env_policy_id,
    env_org_id,
    env_policy_name,
    ip_records,
    pjson,
    record_types=("A",),
    domain_ip_map=None,
):
    config_path = get_pangolin_config_path()
    template = load_yaml_template(config_path, default_filename="pangolin-config.yaml")
    if not isinstance(template, dict):
        logger.warning("Skipping Pangolin sync: configuration file issue with '%s'...", config_path)
        return

    org_id = env_org_id or template.get("org_id") or template.get("orgId")
    policy_id = env_policy_id or template.get("policy_id") or template.get("id")
    if not policy_id:
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

    if any(k in template for k in ("rules", "apply_rules", "applyRules")):
        desired_config = build_pangolin_rules(
            template,
            ip_records,
            record_types=record_types,
            domain_ip_map=domain_ip_map,
        )
        if desired_config is not None and should_update_pangolin_policy(
            current_policy, desired_config
        ):
            update_pangolin_policy_rules(base_url, api_key, policy_id, desired_config, pjson=pjson)

    sync_pangolin_auth(
        base_url, api_key, policy_id, org_id, current_policy, template, pjson=pjson
    )


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
        domain_ip_map = {}
        for domain in domains:
            resolved = resolve_domain(domain, record_types)
            domain_ip_map[domain.lower()] = resolved
            for ip in resolved:
                if ip not in ip_records:
                    ip_records.append(ip)

        # Guard: do not wipe rules if DNS resolution failed
        if not ip_records:
            logger.warning(
                "DNS resolution returned no records. Skipping update to avoid wiping rules..."
            )
            shutdown_event.wait(interval)
            continue

        # 2. Sync Hostinger Firewall if enabled
        if hostinger_enabled:
            sync_hostinger(
                hostinger_api_key,
                firewall_name,
                ip_records,
                pjson,
                record_types=record_types,
                domain_ip_map=domain_ip_map,
            )

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
                record_types=record_types,
                domain_ip_map=domain_ip_map,
            )

        shutdown_event.wait(interval)

    logger.info("DNS Pinger stopped.")


if __name__ == "__main__":
    main()
