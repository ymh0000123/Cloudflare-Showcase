import requests
from datetime import datetime, timedelta, timezone
import os
import sys
import json

API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
ZONE_ID = os.getenv('ZONE_ID')

if not API_TOKEN or not ZONE_ID:
    sys.exit("请设置环境变量 CLOUDFLARE_API_TOKEN 和 ZONE_ID")

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

traffic_query = """
query GetZoneAnalytics($zoneTag: String!, $since: DateTime!, $until: DateTime!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
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

def fetch_graphql(query, variables):
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
        sys.exit(f"请求异常: {e}")

now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)

results = []
for i in range(24, 0, -1):
    since_time = now - timedelta(hours=i)
    until_time = now - timedelta(hours=i-1)
    since = since_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    until = until_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    since_ts = int(since_time.timestamp())
    until_ts = int(until_time.timestamp())

    variables = {
        "zoneTag": ZONE_ID,
        "since": since,
        "until": until
    }

    # 流量与请求数
    traffic_data = fetch_graphql(traffic_query, variables)
    try:
        http_data = traffic_data["data"]["viewer"]["zones"][0]["httpRequests1hGroups"]
        if http_data:
            total_requests = http_data[0]["sum"]["requests"]
            total_bytes = http_data[0]["sum"]["bytes"]
        else:
            total_requests = 0
            total_bytes = 0
    except Exception:
        total_requests = 0
        total_bytes = 0

    # WAF缓解数
    waf_data = fetch_graphql(waf_query, variables)
    try:
        firewall_events = waf_data["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
        waf_mitigated_requests = len(firewall_events)
    except Exception:
        waf_mitigated_requests = 0

    result = {
        "since": since_ts,
        "until": until_ts,
        "total_requests": total_requests,
        "total_bytes": total_bytes,
        "total_megabytes": round(total_bytes / (1024 ** 2), 2),
        "waf_mitigated_requests": waf_mitigated_requests
    }
    results.append(result)

# 保存到JSON文件
with open("cloudflare_hourly_stats.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print("数据已保存到 cloudflare_hourly_stats.json")
