def parse_user_agent(ua_string):
    """解析User-Agent字符串，返回浏览器类型"""
    if not ua_string or ua_string == "Unknown":
        return "Unknown"
    
    ua = ua_string.lower()
    
    # 机器人和爬虫
    if any(bot in ua for bot in ['bot', 'crawler', 'spider', 'scraper']):
        # 搜索引擎爬虫
        if 'googlebot' in ua:
            return "Googlebot"
        elif 'bingbot' in ua:
            return "BingBot"
        elif 'applebot' in ua:
            return "Applebot"
        elif 'baiduspider' in ua:
            return "BaiduSpider"
        elif 'yandex' in ua:
            return "Yandex"
        # AI 爬虫
        elif 'gptbot' in ua:
            return "GPTBot"
        elif 'chatgpt-user' in ua:
            return "ChatGPT-User"
        elif 'claudebot' in ua:
            return "ClaudeBot"
        elif 'claude-searchbot' in ua:
            return "Claude-SearchBot"
        elif 'claude-user' in ua:
            return "Claude-User"
        elif 'amazonbot' in ua:
            return "Amazonbot"
        elif 'amazon-kendra' in ua:
            return "Amazon Kendra"
        elif 'amazonadbot' in ua:
            return "Amazon AdBot"
        elif 'meta-externalagent' in ua:
            return "Meta-ExternalAgent"
        elif 'meta-externalfetcher' in ua:
            return "Meta-ExternalFetcher"
        elif 'meta-webindexer' in ua:
            return "Meta-WebIndexer"
        elif 'bytespider' in ua:
            return "ByteSpider"
        elif 'ccbot' in ua:
            return "CCBot"
        elif 'anthropic-ai' in ua:
            return "Anthropic AI"
        elif 'cohere-ai' in ua:
            return "Cohere AI"
        elif 'perplexity' in ua:
            return "Perplexity"
        elif 'youbot' in ua:
            return "YouBot"
        # SEO 工具
        elif 'ahrefsbot' in ua:
            return "AhrefsBot"
        elif 'ahrefssiteaudit' in ua:
            return "Ahrefs Site Audit"
        elif 'semrush' in ua:
            return "SEMrush"
        elif 'mj12bot' in ua:
            return "Majestic SEO"
        elif 'dotbot' in ua:
            return "Moz/(dotBot)"
        # 广告和营销
        elif 'adsbot-google' in ua:
            return "Google AdsBot"
        elif 'mediapartners-google' in ua:
            return "Google AdSense"
        elif 'adsbot-google-mobile' in ua:
            return "Google AdsBot Mobile"
        elif 'adidxbot' in ua:
            return "Bing Ads"
        elif 'amazon-contxtbot' in ua:
            return "Amazon Contxbot"
        # 社交媒体
        elif 'facebookexternalhit' in ua or 'facebookbot' in ua:
            return "Facebook Bot"
        elif 'twitterbot' in ua:
            return "Twitter Bot"
        elif 'linkedinbot' in ua:
            return "LinkedIn Bot"
        elif 'whatsapp' in ua:
            return "WhatsApp"
        elif 'telegrambot' in ua:
            return "Telegram Bot"
        elif 'slackbot' in ua:
            return "Slack Bot"
        elif 'discordbot' in ua:
            return "Discord Bot"
        # 监控和分析
        elif 'prerender' in ua:
            return "Prerender Bot"
        elif 'headlesschrome' in ua:
            return "Headless Chrome"
        elif 'uptimerobot' in ua:
            return "UptimeRobot"
        elif 'pingdom' in ua:
            return "Pingdom"
        elif 'nagios' in ua:
            return "Nagios"
        # 其他
        elif 'google-other' in ua or 'googleother' in ua:
            return "GoogleOther"
        elif 'google-agent' in ua:
            return "Google-Agent"
        elif 'bingpreview' in ua:
            return "Bing Preview"
        elif 'google-inspectiontool' in ua:
            return "Google Inspection Tool"
        else:
            return "Other Bot"
    # AI 助手（非 bot 关键词）
    elif 'claude-user' in ua:
        return "Claude-User"
    elif 'meta-externalagent' in ua:
        return "Meta-ExternalAgent"
    elif 'chatgpt-user' in ua:
        return "ChatGPT-User"
    elif 'google-agent' in ua:
        return "Google-Agent"
    
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