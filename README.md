# CWE 本地浏览与下载工具

这是一个面向 CWE（Common Weakness Enumeration）的本地数据下载、校验与浏览项目。项目通过 MITRE 提供的 CWE REST API 获取数据，并将结果整理为便于离线检索、分析和网页浏览的本地文件结构。

## 项目状态

当前数据集已完成完整验证，包含以下内容：

- 969 个 Weakness 条目
- 422 个 Category 条目
- 59 个 View 条目
- 3,876 个关系文件（parents、children、descendants、ancestors）

验证脚本已确认合并数据与拆分数据数量一致，当前可直接用于离线浏览与分析。

## 功能特性

- 支持 CWE 数据的完整拉取与增量更新
- 支持多线程并发下载关系数据，提升同步速度
- 支持失败重试与 SSL 容错
- 将条目拆分为单独 JSON 文件，便于脚本分析
- 提供现代化且美观的 FastAPI Web 浏览界面，包含丰富字段
- 支持在页面中按官方视图（如 CWE-699、CWE-1194、CWE-1000）快速过滤
- 支持在页面中按 ID 或名称搜索 CWE 卡片，并查看与 MITRE 官方站点相近的丰富字段数据，包括 Demonstrative Examples、Potential Mitigations、Observed Examples 等

## 环境要求

- Python 3.10 或更高版本
- pip
- 网络可访问 MITRE CWE REST API

## 安装依赖

建议先创建虚拟环境，然后安装依赖：

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

如果你已经在现有环境中工作，也可以直接执行 `pip install -r requirements.txt`。

## 项目结构

```text
CWE/
├── LICENSE
├── README.md
├── requirements.txt
├── .gitignore
├── data/
│   ├── version.json
│   ├── weaknesses.json
│   ├── categories.json
│   ├── views.json
│   ├── weaknesses/
│   ├── categories/
│   ├── views/
│   └── relations/
├── download_cwe.py
├── verify_cwe.py
├── show.py
└── templates/
    ├── index.html
    └── detail.html
```

## 启动 Web 浏览界面

启动服务：

```bash
python show.py
```

然后打开浏览器访问：

```text
http://127.0.0.1:8000
```

页面支持：

- 以卡片形式且按编号递增排序浏览 CWE 条目
- 官方视图标签过滤
- 在搜索框中按 ID 或名称快速筛选
- 点击卡片进入详情页
- 详情页呈现现代化排版，包含条目描述、扩展描述、关系数据、平台、模式、缓解措施、演示代码示例等

## 数据验证

下载或同步完成后，先运行验证脚本确认数据完整性：

```bash
python verify_cwe.py
```

脚本会检查：

- `version.json` 是否可读
- 合并文件与拆分文件数量是否一致
- 关系文件是否按预期生成

## 重新下载 CWE 数据

### 完整强制下载

当你想重新拉取全部数据时，使用：

```bash
python download_cwe.py --out-dir data --force --threads 8 --max-retries 5
```

参数说明：

- `--out-dir data`：数据输出目录
- `--force`：忽略本地缓存，强制重新下载
- `--threads 8`：关系数据并发线程数，通常 4 到 18 比较合适
- `--max-retries 5`：单个请求最大重试次数

### 增量更新

如果只想在远端版本变化时才同步：

```bash
python download_cwe.py --out-dir data --incremental
```

增量模式会先检查 `version.json` 中的 `ContentVersion`，如果与远端一致则跳过下载。

## 代码使用示例

### 读取单个 weakness

```python
import json

with open("data/weaknesses/79.json", "r", encoding="utf-8") as f:
    weakness = json.load(f)

print(weakness["ID"])
print(weakness["Name"])
```

## 常见问题

### 1. Web 服务无法启动

通常是依赖未安装，重新执行：

```bash
pip install -r requirements.txt
```

### 2. 下载时遇到 SSL 或超时错误

可以增加重试次数并降低线程数：

```bash
python download_cwe.py --out-dir data --force --threads 4 --max-retries 10
```

### 3. 本地数据与远端不一致

先运行验证脚本确认缺失范围，再执行完整强制下载：

```bash
python verify_cwe.py
python download_cwe.py --out-dir data --force --threads 8 --max-retries 5
```

## 许可证

本项目采用 MIT License，详见 [LICENSE](LICENSE)。

## 参考

- CWE 官方站点：https://cwe.mitre.org/
- CWE REST API 仓库：https://github.com/CWE-CAPEC/REST-API-wg
