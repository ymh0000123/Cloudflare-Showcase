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
        elif 'Applebot' in ua:
            return "Applebot"
        elif 'facebookexternalhit' in ua or 'facebookbot' in ua:
            return "Facebook Bot"
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


def process_user_agent_stats(user_agent_events):
    """处理User-Agent统计数据，返回前10个最常见的浏览器"""
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
    
    return top_user_agents