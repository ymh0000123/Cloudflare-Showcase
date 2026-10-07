import requests
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
import sys
import json
from user_agent_parser import process_bot_stats, process_user_agent_stats

load_dotenv()

API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')

# 支持多域名：ZONE_IDS 支持逗号分隔的多个 Zone ID，可带可选展示标签，如 "abc123:example.com,def456:foo.net"
# 兼容旧配置：未设置 ZONE_IDS 时回退到单域名变量 ZONE_ID
ZONE_IDS = os.getenv('ZONE_IDS') or os.getenv('ZONE_ID')

if not API_TOKEN or not ZONE_IDS:
    sys.exit("请设置环境变量 CLOUDFLARE_API_TOKEN 和 ZONE_IDS（多个 Zone ID 用英文逗号分隔，旧变量 ZONE_ID 仍兼容）")


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
    sys.exit("ZONE_IDS 中没有有效的 Zone ID")

# Zone ID 基本格式校验：Cloudflare Zone ID 是 32 位十六进制；带前导 = 或空格等常见配置错误在此快速暴露
for zone_id, label in zones:
    if len(zone_id) != 32 or not all(c in "0123456789abcdefABCDEF" for c in zone_id):
        sys.exit(f"Zone ID 格式无效: {zone_id!r}（标签 {label!r}）。请检查 ZONE_IDS 配置，确认没有多余的 = 或空格")

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

traffic_query = """
query GetZoneAnalytics($zoneTag: String!, $since: DateTime!, $until: DateTime!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      zoneTag
      httpRequests1hGroups(
        limit: 1,
        filter: { datetime_geq: $since, datetime_lt: $until }
      ) {
        sum {
          requests
          bytes
        }
      }
    }
  }
}
"""

waf_query = """
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
        clientCountryName
      }
    }
  }
}
"""

normal_requests_query = """
query GetNormalUserAgentStats($zoneTag: String!, $since: DateTime!, $until: DateTime!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      zoneTag
      httpRequestsAdaptive(
        limit: 5000,
        filter: {
          datetime_geq: $since,
          datetime_lt: $until,
          edgeResponseStatus_in: [200, 201, 202, 204, 206, 301, 302, 304, 307, 308]
        }
      ) {
        userAgent
        clientCountryName
        datetime
        edgeResponseStatus
      }
    }
  }
}
"""


def fetch_graphql(query, variables):
    for attempt in range(2):
        try:
            response = requests.post(
                url="https://api.cloudflare.com/client/v4/graphql",
                headers=headers,
                json={"query": query, "variables": variables},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            if attempt == 0:
                print(f"请求失败，正在进行唯一一次重试: {e}")
                continue
            sys.exit(f"请求异常（重试后仍失败）: {e}")


def extract_zone(payload, zone_id):
    """从 GraphQL 响应中取出指定 zone 的数据容器；取不到时返回 None。"""
    try:
        zone_list = payload["data"]["viewer"]["zones"]
    except (KeyError, TypeError, IndexError):
        return None
    if not zone_list:
        return None
    matched = next((z for z in zone_list if z and z.get("zoneTag") == zone_id), None)
    return matched if matched is not None else zone_list[0]


def normalize_country(country):
    """将港澳台归为中国，并统一常见国家代码。"""
    if country in ["Taiwan", "Hong Kong", "Macao", "TW", "HK", "MO"]:
        return "China"
    if country == "CN":
        return "China"
    if country == "US":
        return "United States"
    return country


def count_countries(events):
    """按国家归一化统计事件数量，返回降序排行。"""
    counts = {}
    for event in events:
        country = normalize_country(event.get("clientCountryName", "Unknown"))
        counts[country] = counts.get(country, 0) + 1
    return [
        {"country": country, "requests": count}
        for country, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ]


def fetch_traffic(zone_id, since, until):
    data = fetch_graphql(traffic_query, {"zoneTag": zone_id, "since": since, "until": until})
    try:
        zone = extract_zone(data, zone_id)
        http_data = zone["httpRequests1hGroups"] if zone else None
        if http_data:
            return http_data[0]["sum"]["requests"], http_data[0]["sum"]["bytes"]
    except Exception:
        pass
    return 0, 0


def fetch_waf(zone_id, since, until):
    data = fetch_graphql(waf_query, {"zoneTag": zone_id, "since": since, "until": until})
    try:
        zone = extract_zone(data, zone_id)
        firewall_events = zone["firewallEventsAdaptive"] if zone else []
        return len(firewall_events), count_countries(firewall_events)
    except Exception:
        return 0, []


def fetch_ua(zone_id, since, until):
    data = fetch_graphql(normal_requests_query, {"zoneTag": zone_id, "since": since, "until": until})
    try:
        if data.get("errors"):
            # GraphQL 报错通常是配置问题（如 Zone ID 无效），继续运行只会产出全零数据，直接终止
            sys.exit(f"GraphQL错误（zone {zone_id}）: {data['errors']}")
        zone = extract_zone(data, zone_id)
        if not zone or not zone.get("httpRequestsAdaptive"):
            return [], [], []
        user_agent_events = zone["httpRequestsAdaptive"]
        # 浏览器图表保留前 10 项，Bot 表格使用单独的完整分类结果。
        top_user_agents = process_user_agent_stats(user_agent_events)
        top_bots = process_bot_stats(user_agent_events)
        top_countries = count_countries(user_agent_events)
        return top_user_agents, top_bots, top_countries
    except Exception as e:
        print(f"获取数据时出错: {e}")
        if 'data' in locals():
            print(f"UA数据结构: {data}")
        return [], [], []


def merge_named_stats(existing, incoming, name_key):
    """合并两份 [{name_key, requests}] 排行并按数量降序排序。"""
    counts = {}
    for entry in list(existing) + list(incoming):
        name = entry.get(name_key) or "Unknown"
        counts[name] = counts.get(name, 0) + int(entry.get("requests") or 0)
    return [
        {name_key: name, "requests": count}
        for name, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ]


def merge_browser_stats(existing, incoming):
    return merge_named_stats(existing, incoming, "browser")


def merge_bot_stats(existing, incoming):
    """合并 Bot 统计：同名 Bot 请求累加，元数据（operator/classification/signature）取首次出现的值。"""
    bots = {}
    for entry in list(existing) + list(incoming):
        name = entry.get("name") or "Unknown"
        if name not in bots:
            bots[name] = {
                "name": name,
                "operator": entry.get("operator", "—"),
                "classification": entry.get("classification", "自动化客户端"),
                "signature": entry.get("signature", name),
                "requests": 0,
            }
        bots[name]["requests"] += entry.get("requests") or 0
    return sorted(bots.values(), key=lambda x: x["requests"], reverse=True)


# 按小时逐点统计，每个小时把所有域名的查询结果聚合到同一时间点
now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)

results = []
total_hours = 24
print(f"开始获取过去 {total_hours} 小时的数据，共 {len(zones)} 个域名...")

for i in range(total_hours, 0, -1):
    # 打印进度条
    progress = total_hours - i + 1
    percent = (progress / total_hours) * 100
    bar_length = 30
    filled_length = int(bar_length * progress // total_hours)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f"\r进度: |{bar}| {percent:.1f}% ({progress}/{total_hours} 小时)", end="", flush=True)

    since_time = now - timedelta(hours=i)
    until_time = now - timedelta(hours=i-1)
    since = since_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    until = until_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    since_ts = int(since_time.timestamp())
    until_ts = int(until_time.timestamp())

    hour_result = {
        "since": since_ts,
        "until": until_ts,
        "total_requests": 0,
        "total_bytes": 0,
        "total_megabytes": 0,
        "waf_mitigated_requests": 0,
        "top_user_agents": [],
        "top_bots": [],
        "top_countries": [],
        "top_waf_countries": [],
        "zones": []
    }

    for zone_id, label in zones:
        total_requests, total_bytes = fetch_traffic(zone_id, since, until)
        waf_mitigated_requests, top_waf_countries = fetch_waf(zone_id, since, until)
        top_user_agents, top_bots, top_countries = fetch_ua(zone_id, since, until)

        hour_result["total_requests"] += total_requests
        hour_result["total_bytes"] += total_bytes
        hour_result["waf_mitigated_requests"] += waf_mitigated_requests
        hour_result["top_user_agents"] = merge_browser_stats(hour_result["top_user_agents"], top_user_agents)
        hour_result["top_bots"] = merge_bot_stats(hour_result["top_bots"], top_bots)
        hour_result["top_countries"] = merge_named_stats(hour_result["top_countries"], top_countries, "country")
        hour_result["top_waf_countries"] = merge_named_stats(hour_result["top_waf_countries"], top_waf_countries, "country")

        # 保留每个域名的小时明细，供前端按域名筛选
        hour_result["zones"].append({
            "zone_id": zone_id,
            "name": label,
            "since": since_ts,
            "until": until_ts,
            "total_requests": total_requests,
            "total_bytes": total_bytes,
            "waf_mitigated_requests": waf_mitigated_requests,
            "top_user_agents": top_user_agents,
            "top_bots": top_bots,
            "top_countries": top_countries,
            "top_waf_countries": top_waf_countries,
        })

    hour_result["total_megabytes"] = round(hour_result["total_bytes"] / (1024 ** 2), 2)
    results.append(hour_result)

print("\n数据获取完成！")

# 保存到JSON文件
with open("cloudflare_hourly_stats.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print("数据已保存到 cloudflare_hourly_stats.json")
