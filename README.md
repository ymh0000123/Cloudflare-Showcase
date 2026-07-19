# Cloudflare Showcase

## 项目简介

Cloudflare Showcase是一个展示Cloudflare功能和特性的项目。可以在GitHub Actions的工作流上运行，用于展示经过Cloudflare的服务的流量与请求。

## 文件结构

- `.github/workflows/main.yaml`: GitHub Actions的工作流配置文件。
- `LICENSE`: 项目的许可证文件。
- `README.md`: 项目的说明文档。
- `cloudflare_hourly_stats.json`: 包含每小时统计数据的JSON文件。
- `get.py`: 用于获取数据的Python脚本。
- `index.html`: 项目的主HTML文件。
- `requirements.txt`: Python项目的依赖文件。
- `waf.py`: 用于获取WAF的Python脚本。

## 功能特性

### 流量监控
- 总请求数统计
- 总流量统计
- WAF拦截数和拦截率

### 数据可视化
- 请求量与WAF拦截趋势图
- 流量变化趋势图
- 浏览器使用排行（支持柱状图和饼图切换）
- 国家/地区分布地图

### Bot访问分析
- 主要爬虫识别（GoogleBot、Claude-User、GPTBot等）
- 爬虫运营商分布统计
- 爬虫类别分析（搜索引擎、AI爬虫、广告营销等）
- User-Agent详细信息

## 使用说明

[博客文章](https://feishu.xiao-feishu.top/article/Cloudflare-Showcase)

## 贡献

欢迎提交问题和请求，也欢迎贡献代码。请确保在提交之前阅读我们的贡献指南。

## 许可证

本项目基于MIT许可证进行分发。详情请参阅`LICENSE`文件。