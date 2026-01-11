import requests
from datetime import datetime, timedelta, timezone
import os
import sys
import json
from user_agent_parser import process_user_agent_stats

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

normal_requests_query = """
query GetNormalUserAgentStats($zoneTag: String!, $since: DateTime!, $until: DateTime!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      httpRequestsAdaptive(
        limit: 5000,
        filter: { 
          datetime_geq: $since, 
          datetime_lt: $until,
          edgeResponseStatus_in: [200, 201, 202, 204, 206, 301, 302, 304, 307, 308]
        }
      ) {
        userAgent
        datetime
        edgeResponseStatus
        clientRequestHTTPHost
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
        total_bytes = 0    # WAF缓解数
    waf_data = fetch_graphql(waf_query, variables)
    try:
        firewall_events = waf_data["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
        waf_mitigated_requests = len(firewall_events)
    except Exception:
        waf_mitigated_requests = 0    # User-Agent统计（仅获取正常响应的请求，排除WAF拦截）
    ua_data = fetch_graphql(normal_requests_query, variables)
    try:
        # 检查是否有错误
        if ua_data.get("errors"):
            print(f"GraphQL错误: {ua_data['errors']}")
            top_user_agents = []
            top_domains = []
        elif not ua_data.get("data") or not ua_data["data"]["viewer"]["zones"]:
            print("UA数据为空或zone不存在")
            top_user_agents = []
            top_domains = []
        else:
            user_agent_events = ua_data["data"]["viewer"]["zones"][0]["httpRequestsAdaptive"]
            # 使用新的处理函数
            top_user_agents = process_user_agent_stats(user_agent_events)
            # 统计域名排行
            domain_counts = {}
            for event in user_agent_events:
                host = event.get("clientRequest", {}).get("host", "Unknown")
                domain_counts[host] = domain_counts.get(host, 0) + 1
            top_domains = [
                {"domain": domain, "requests": count}
                for domain, count in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
    except Exception as e:
        print(f"获取UA数据时出错: {e}")
        # 打印调试信息
        if 'ua_data' in locals():
            print(f"UA数据结构: {ua_data}")
        top_user_agents = []
        top_domains = []

    result = {
        "since": since_ts,
        "until": until_ts,
        "total_requests": total_requests,
        "total_bytes": total_bytes,
        "total_megabytes": round(total_bytes / (1024 ** 2), 2),
        "waf_mitigated_requests": waf_mitigated_requests,
        "top_user_agents": top_user_agents,
        "top_domains": top_domains
    }
    results.append(result)

# 保存到JSON文件
with open("cloudflare_hourly_stats.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print("数据已保存到 cloudflare_hourly_stats.json")
