BOT_METADATA = {
    "Googlebot": ("Google", "搜索引擎爬虫", "Googlebot/"),
    "BingBot": ("Microsoft", "搜索引擎爬虫", "bingbot/"),
    "Applebot": ("Apple", "AI 搜索", "Applebot"),
    "BaiduSpider": ("Baidu", "搜索引擎爬虫", "Baiduspider"),
    "Yandex": ("Yandex", "搜索引擎爬虫", "YandexBot"),
    "GPTBot": ("OpenAI", "AI 爬虫", "GPTBot"),
    "ChatGPT-User": ("OpenAI", "AI 助手", "ChatGPT-User"),
    "ClaudeBot": ("Anthropic", "AI 爬虫", "ClaudeBot"),
    "Claude-SearchBot": ("Anthropic", "AI 搜索", "Claude-SearchBot"),
    "Claude-User": ("Anthropic", "AI 助手", "Claude-User"),
    "Amazonbot": ("Amazon", "AI 爬虫", "Amazonbot"),
    "Amazon Kendra": ("Amazon", "企业搜索", "Amazon-Kendra"),
    "Amazon AdBot": ("Amazon", "广告营销", "AmazonAdBot"),
    "Meta-ExternalAgent": ("Meta", "AI 爬虫", "meta-externalagent"),
    "Meta-ExternalFetcher": ("Meta", "AI 抓取", "meta-externalfetcher"),
    "Meta-WebIndexer": ("Meta", "AI 搜索", "meta-webindexer"),
    "ByteSpider": ("ByteDance", "AI 爬虫", "Bytespider"),
    "CCBot": ("Common Crawl", "网页归档", "CCBot"),
    "Anthropic AI": ("Anthropic", "AI 爬虫", "anthropic-ai"),
    "Cohere AI": ("Cohere", "AI 爬虫", "cohere-ai"),
    "Perplexity": ("Perplexity", "AI 搜索", "PerplexityBot"),
    "YouBot": ("You.com", "AI 搜索", "YouBot"),
    "AhrefsBot": ("Ahrefs", "SEO 工具", "AhrefsBot"),
    "Ahrefs Site Audit": ("Ahrefs", "SEO 工具", "AhrefsSiteAudit"),
    "SEMrush": ("Semrush", "SEO 工具", "SemrushBot"),
    "Majestic SEO": ("Majestic", "SEO 工具", "MJ12bot"),
    "Moz/(dotBot)": ("Moz", "SEO 工具", "dotbot"),
    "Google AdsBot": ("Google", "广告营销", "AdsBot-Google"),
    "Google AdSense": ("Google", "广告营销", "Mediapartners-Google"),
    "Google AdsBot Mobile": ("Google", "广告营销", "AdsBot-Google-Mobile"),
    "Bing Ads": ("Microsoft", "广告营销", "adidxbot"),
    "Amazon Contxbot": ("Amazon", "广告营销", "Amazon-Contxbot"),
    "Facebook Bot": ("Meta", "社交媒体", "facebookexternalhit"),
    "Twitter Bot": ("X", "社交媒体", "Twitterbot"),
    "LinkedIn Bot": ("LinkedIn", "社交媒体", "LinkedInBot"),
    "WhatsApp": ("Meta", "社交媒体", "WhatsApp"),
    "Telegram Bot": ("Telegram", "社交媒体", "TelegramBot"),
    "Slack Bot": ("Slack", "社交媒体", "Slackbot"),
    "Discord Bot": ("Discord", "社交媒体", "Discordbot"),
    "Prerender Bot": ("Prerender", "预渲染服务", "prerender"),
    "Headless Chrome": ("Unknown", "无头浏览器", "HeadlessChrome"),
    "UptimeRobot": ("UptimeRobot", "监控服务", "UptimeRobot"),
    "Pingdom": ("SolarWinds", "监控服务", "Pingdom"),
    "Nagios": ("Nagios", "监控服务", "Nagios"),
    "GoogleOther": ("Google", "自动化客户端", "GoogleOther"),
    "Google-Agent": ("Google", "自动化客户端", "Google-Agent"),
    "Bing Preview": ("Microsoft", "搜索预览", "BingPreview"),
    "Google Inspection Tool": ("Google", "站点检查", "Google-InspectionTool"),
    "Other Bot": ("Unknown", "其他自动化客户端", "bot / crawler / spider / scraper"),
}


BOT_SIGNATURES = (
    (("googlebot",), "Googlebot"),
    (("bingbot",), "BingBot"),
    (("applebot",), "Applebot"),
    (("baiduspider",), "BaiduSpider"),
    (("yandex",), "Yandex"),
    (("gptbot",), "GPTBot"),
    (("chatgpt-user",), "ChatGPT-User"),
    (("claude-searchbot",), "Claude-SearchBot"),
    (("claude-user",), "Claude-User"),
    (("claudebot",), "ClaudeBot"),
    (("amazon-kendra",), "Amazon Kendra"),
    (("amazonadbot",), "Amazon AdBot"),
    (("amazon-contxtbot",), "Amazon Contxbot"),
    (("amazonbot",), "Amazonbot"),
    (("meta-externalagent",), "Meta-ExternalAgent"),
    (("meta-externalfetcher",), "Meta-ExternalFetcher"),
    (("meta-webindexer",), "Meta-WebIndexer"),
    (("bytespider",), "ByteSpider"),
    (("ccbot",), "CCBot"),
    (("anthropic-ai",), "Anthropic AI"),
    (("cohere-ai",), "Cohere AI"),
    (("perplexity",), "Perplexity"),
    (("youbot",), "YouBot"),
    (("ahrefssiteaudit",), "Ahrefs Site Audit"),
    (("ahrefsbot",), "AhrefsBot"),
    (("semrush",), "SEMrush"),
    (("mj12bot",), "Majestic SEO"),
    (("dotbot",), "Moz/(dotBot)"),
    (("adsbot-google-mobile",), "Google AdsBot Mobile"),
    (("adsbot-google",), "Google AdsBot"),
    (("mediapartners-google",), "Google AdSense"),
    (("adidxbot",), "Bing Ads"),
    (("facebookexternalhit", "facebookbot"), "Facebook Bot"),
    (("twitterbot",), "Twitter Bot"),
    (("linkedinbot",), "LinkedIn Bot"),
    (("whatsapp",), "WhatsApp"),
    (("telegrambot",), "Telegram Bot"),
    (("slackbot",), "Slack Bot"),
    (("discordbot",), "Discord Bot"),
    (("prerender",), "Prerender Bot"),
    (("headlesschrome",), "Headless Chrome"),
    (("uptimerobot",), "UptimeRobot"),
    (("pingdom",), "Pingdom"),
    (("nagios",), "Nagios"),
    (("google-other", "googleother"), "GoogleOther"),
    (("google-agent",), "Google-Agent"),
    (("bingpreview",), "Bing Preview"),
    (("google-inspectiontool",), "Google Inspection Tool"),
)


def identify_bot(ua_string):
    """返回自动化客户端的规范名称，无法识别时返回 None。"""
    if not ua_string:
        return None

    ua = ua_string.lower()
    for signatures, name in BOT_SIGNATURES:
        if any(signature in ua for signature in signatures):
            return name

    if any(keyword in ua for keyword in ("bot", "crawler", "spider", "scraper")):
        return "Other Bot"
    return None


def parse_user_agent(ua_string):
    """解析User-Agent字符串，返回浏览器类型"""
    if not ua_string or ua_string == "Unknown":
        return "Unknown"
    
    ua = ua_string.lower()
    identified_bot = identify_bot(ua_string)
    if identified_bot:
        return identified_bot
    
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


def process_bot_stats(user_agent_events):
    """统计已识别的自动化客户端，并附带用于前端展示的稳定元数据。"""
    bot_counts = {}

    for event in user_agent_events:
        ua = event.get("userAgent", "Unknown")
        if not ua or ua.strip() == "":
            continue

        name = identify_bot(ua)
        if name:
            bot_counts[name] = bot_counts.get(name, 0) + 1

    return [
        {
            "name": name,
            "operator": BOT_METADATA[name][0],
            "classification": BOT_METADATA[name][1],
            "signature": BOT_METADATA[name][2],
            "requests": count,
        }
        for name, count in sorted(bot_counts.items(), key=lambda item: item[1], reverse=True)
    ]
