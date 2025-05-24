import requests
from datetime import datetime, timedelta, timezone
import os

# 替换为您的 API Token 和 Zone ID
API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
ZONE_ID = os.getenv('ZONE_ID')

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

# 设置查询变量
variables = {
    "zoneTag": ZONE_ID,
    "since": since,
    "until": until
}

# 发送请求
response = requests.post(
    url="https://api.cloudflare.com/client/v4/graphql",
    headers=headers,
    json={"query": query, "variables": variables}
)

# 处理响应
if response.status_code != 200:
    raise Exception(f"请求失败，状态码：{response.status_code}，响应内容：{response.text}")

data = response.json()

# 计算 WAF 缓解请求数量
firewall_events = data["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
waf_mitigated_requests = len(firewall_events)

print(f"过去 24 小时通过 WAF 缓解的请求数：{waf_mitigated_requests}")
