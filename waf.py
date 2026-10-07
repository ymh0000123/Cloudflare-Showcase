import requests
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv

load_dotenv()

API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')

# 支持多域名：ZONE_IDS 支持逗号分隔的多个 Zone ID，可带可选展示标签，如 "abc123:example.com,def456:foo.net"
# 兼容旧配置：未设置 ZONE_IDS 时回退到单域名变量 ZONE_ID
ZONE_IDS = os.getenv('ZONE_IDS') or os.getenv('ZONE_ID')

if not API_TOKEN or not ZONE_IDS:
    print("请设置环境变量 CLOUDFLARE_API_TOKEN 和 ZONE_IDS（多个 Zone ID 用英文逗号分隔，旧变量 ZONE_ID 仍兼容）")
    raise SystemExit(1)


def parse_zone_ids(raw):
    """解析 ZONE_IDS 配置，支持 zone_id 或 zone_id:标签 两种格式，返回 [(zone_id, label), ...]。"""
    zones = []
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if ':' in part:
            zone_id, label = part.split(':', 1)
            zone_id, label = zone_id.strip(), label.strip()
        else:
            zone_id, label = part, part
        if not zone_id:
            continue
        if not any(z[0] == zone_id for z in zones):
            zones.append((zone_id, label))
    return zones


zones = parse_zone_ids(ZONE_IDS)
if not zones:
    print("ZONE_IDS 中没有有效的 Zone ID")
    raise SystemExit(1)

# Zone ID 基本格式校验：Cloudflare Zone ID 是 32 位十六进制；带前导 = 或空格等常见配置错误在此快速暴露
for zone_id, label in zones:
    if len(zone_id) != 32 or not all(c in "0123456789abcdefABCDEF" for c in zone_id):
        print(f"Zone ID 格式无效: {zone_id!r}（标签 {label!r}）。请检查 ZONE_IDS 配置，确认没有多余的 = 或空格")
        raise SystemExit(1)

# 设置请求头
headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# 计算时间范围：过去 24 小时
now = datetime.now(timezone.utc)
start_time = now - timedelta(hours=24)
since = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
until = now.strftime("%Y-%m-%dT%H:%M:%SZ")

# 定义 GraphQL 查询
query = """
query GetWAFMitigatedRequests($zoneTag: String!, $since: DateTime!, $until: DateTime!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      zoneTag
      firewallEventsAdaptive(
        filter: {
          datetime_geq: $since,
          datetime_lt: $until,
          action_in: ["block", "challenge", "jschallenge", "managed_challenge", "managed_block"]
        }
        limit: 10000
      ) {
        action
        datetime
      }
    }
  }
}
"""

total_mitigated = 0
for zone_id, label in zones:
    variables = {"zoneTag": zone_id, "since": since, "until": until}
    response = requests.post(
        url="https://api.cloudflare.com/client/v4/graphql",
        headers=headers,
        json={"query": query, "variables": variables}
    )
    if response.status_code != 200:
        print(f"[{label}] 请求失败，状态码：{response.status_code}，响应内容：{response.text}")
        continue
    data = response.json()
    try:
        zone_list = data["data"]["viewer"]["zones"]
        matched = next((z for z in zone_list if z and z.get("zoneTag") == zone_id), zone_list[0] if zone_list else None)
        firewall_events = matched["firewallEventsAdaptive"] if matched else []
        count = len(firewall_events)
    except Exception:
        count = 0
    total_mitigated += count
    print(f"[{label}] 过去 24 小时通过 WAF 缓解的请求数：{count}")

print(f"全部 {len(zones)} 个域名合计：{total_mitigated}")
