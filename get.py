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
      }
    }
  }
}
"""

def parse_user_agent(ua_string):
    """解析User-Agent字符串，返回浏览器类型"""
    if not ua_string or ua_string == "Unknown":
        return "Unknown"
    
    ua = ua_string.lower()
      # 机器人和爬虫
    if any(bot in ua for bot in ['bot', 'crawler', 'spider', 'scraper']):
        if 'googlebot' in ua:
            return "Googlebot"
        elif 'ahrefsbot' in ua:
            return "AhrefsBot"
        elif 'bingbot' in ua:
            return "BingBot"
        elif 'gptbot' in ua:
            return "GPTBot"
        elif 'bytespider' in ua:
            return "ByteSpider"
        elif 'prerender' in ua:
            return "Prerender Bot"
        elif 'headlesschrome' in ua:
            return "Headless Chrome"
        else:
            return "Other Bot"
    
    # 特殊客户端
    if 'go-http-client' in ua:
        return "Go HTTP Client"
    elif 'curl' in ua:
        return "cURL"
    elif 'nginx-ssl early hints' in ua:
        return "Nginx Early Hints"
    elif 'fasthttp' in ua:
        return "FastHTTP"
    elif 'ktor' in ua:
        return "Ktor Client"
    elif 'python' in ua and 'aiohttp' in ua:
        return "Python aiohttp"
    elif 'restsharp' in ua:
        return "RestSharp"
    elif 'imgproxy' in ua:
        return "ImgProxy"
    
    # 浏览器识别
    if 'edg/' in ua or 'edge/' in ua:
        return "Microsoft Edge"
    elif 'chrome/' in ua and 'safari/' in ua:
        if 'opr/' in ua or 'opera' in ua:
            return "Opera"
        elif 'vivaldi' in ua:
            return "Vivaldi"
        else:
            return "Chrome"
    elif 'firefox/' in ua:
        return "Firefox"
    elif 'safari/' in ua and 'chrome/' not in ua:
        return "Safari"
    elif 'msie' in ua or 'trident' in ua:
        return "Internet Explorer"
    
    # 移动设备浏览器
    if 'mobile' in ua:
        if 'chrome' in ua:
            return "Chrome Mobile"
        elif 'safari' in ua:
            return "Safari Mobile"
        elif 'firefox' in ua:
            return "Firefox Mobile"
        else:
            return "Mobile Browser"
    
    return "Uncharted"

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
        elif not ua_data.get("data") or not ua_data["data"]["viewer"]["zones"]:
            print("UA数据为空或zone不存在")
            top_user_agents = []
        else:
            user_agent_events = ua_data["data"]["viewer"]["zones"][0]["httpRequestsAdaptive"]
            # 统计每个浏览器类型的出现次数（这些都是正常响应的请求）
            browser_counts = {}
            for event in user_agent_events:
                ua = event.get("userAgent", "Unknown")
                if not ua or ua.strip() == "":
                    continue
                    
                browser = parse_user_agent(ua)
                browser_counts[browser] = browser_counts.get(browser, 0) + 1
            
            # 按出现次数排序并取前10个
            top_user_agents = [
                {
                    "browser": browser,
                    "requests": count
                }
                for browser, count in sorted(browser_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
    except Exception as e:
        print(f"获取UA数据时出错: {e}")
        # 打印调试信息
        if 'ua_data' in locals():
            print(f"UA数据结构: {ua_data}")
        top_user_agents = []

    result = {
        "since": since_ts,
        "until": until_ts,
        "total_requests": total_requests,
        "total_bytes": total_bytes,
        "total_megabytes": round(total_bytes / (1024 ** 2), 2),
        "waf_mitigated_requests": waf_mitigated_requests,
        "top_user_agents": top_user_agents
    }
    results.append(result)

# 保存到JSON文件
with open("cloudflare_hourly_stats.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print("数据已保存到 cloudflare_hourly_stats.json")
