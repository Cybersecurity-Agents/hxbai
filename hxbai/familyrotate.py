from __future__ import annotations

import re

FAMILIES = (
    ("xxe", re.compile(r"<!ENTITY|DOCTYPE\s+\w", re.I),
     "SOAP/XML 端点(登录后)声明指向文件的实体,看回显位置",
     "换角度:实体指向 /etc/passwd 校验回显位 -> 换 file:// 协议变体;参数逐个试;带会话 cookie 重发"),
    ("race", re.compile(r"race\.py|threading\.Barrier|ThreadPoolExecutor|concurrent\.futures", re.I),
     "/opt/tools/race.py --reqs 两请求或 --file xN,同 cookie 并发",
     "换角度:轮数×(50->200)、双同步模式(barrier/单连接)、先抓包校准'哪个响应差异=窗口命中'再放大"),
    ("padding_oracle", re.compile(r"padbuster|padding.?oracle|Invalid padding", re.I),
     "对加密 token 末块逐字节枚举,先发探针区分 padding 合法/非法两类响应",
     "换角度:先校准判定分支(状态码/文案/长度三类特征取最稳)再跑全循环;换块序(先解 IV 相邻块)"),
    ("smuggling", re.compile(r"Transfer-Encoding\s*:|xchunked|smuggl|sendall", re.I),
     "raw socket 发 TE 杂质/双头/头名变形三连,看下一响应错位",
     "换角度:三变体逐一试;先发垃圾剩余字节确认 desync;版本组合决定生效项"),
    ("auth_creds", re.compile(r"(login|signin|auth|session)[^\n]{0,80}(password|passwd|pwd)|(user|pass)[a-z]*=", re.I),
     "题面/页面注释/README 里明示的凭据先逐条真试(它们就是真凭据)",
     "换角度:同凭据×全部端点×GET/POST×大小写变体;两步登录先拿 cookie 再交密码;错误回显分支要读全"),
    ("ssti", re.compile(r"\{\{|\$\{|<%=", 0),
     "每个输入参数(可见+隐藏+API+header)各打 {{7*7}}/${7*7}/<%=7*7%>,看 49 回显",
     "换角度:探针跟到下一步页面/导出件里找;sink 在渲染处不在提交处;回显被转义≠没执行"),
    ("sqli", re.compile(r"union\s+select|sqlmap|information_schema|/\*\*/", re.I),
     "报错回显开(display_errors)先试 extractvalue/updatexml 一条出全值;再看 flag 是否在库里表",
     "换角度:空格->/**/、AND->&&、substr->mid 同义表;二阶注入(返回值再拼接)用 UNION SELECT 1# 伪造"),
    ("ocr", re.compile(r"tesseract|easyocr|paddleocr", re.I),
     "(无栈环境慎入)tesseract --psm 8 单行模式",
     "本镜像无 opencv/rapidocr——OCR 是沉没高发族;半遮蔽+加密 token 的验证码转 CBC/oracle 路线"),
    ("pivot", re.compile(
        r"\bsocat\b|\bchisel\b|proxychains|ssh\s+\w+@|fsockopen|/proc/self/mountinfo"
        r"|(?:172\.|10\.|192\.168\.)\d+\.\d+\D{0,40}(?:6379|3306|2222)", re.I),
     "多目标/内网题:从据点自身 ip a/route 推真实内网段,定向探测(不扫/24)后按服务指纹认每台角色(IP会漂,角色/漏洞不变)",
     "换角度(通用横向杠杆,非固定顺序):①先'洗'每个立足点的横向凭据(源码/配置/.env/DB/history/id_rsa/备份归档弱口令),A机凭据打B机(凭据复用是横向主引擎);②传输层选型:HTTP走代理、二进制协议(SSH/原生DB)起TCP隧道,被过滤的外网端口用双网卡据点桥出;③缺客户端就地手写协议别硬装工具;④每台内网主机逐台重新recon套对应漏洞类卡片,题面点名产品CVE全404时真洞常在同网段自研应用;⑤指向不可达网段/平台监控端点是诱饵,识别即跳过"),
)

_SUNK_SHARE = 0.40
_SUNK_MIN = 15


def scan_commands(cmds) -> dict:
    out: dict = {}
    for c in cmds or []:
        s = str(c)
        for name, rx, _p, _d in FAMILIES:
            try:
                n = len(rx.findall(s))
            except Exception:
                n = 1 if rx.search(s) else 0
            if n:
                out[name] = out.get(name, 0) + n
    return out


def render_block(stats: dict) -> str:
    if not stats:
        return ""
    total = sum(stats.values()) or 1
    tried, untried, sunk = [], [], []
    for name, _rx, probe, deepen in FAMILIES:
        n = stats.get(name, 0)
        if n == 0:
            untried.append((name, probe))
        elif n >= _SUNK_MIN and n / total >= _SUNK_SHARE:
            sunk.append((name, n))
        else:
            tried.append((name, n, deepen))
    lines = ["【技术族点名(已达卡壳阈值)——按命令层真实计数,不是建议是纪律】"]
    if tried:
        lines.append("以下族已试但未打通——不许换路,换角度打满(连续 3 个变体无新信号才允许切族):")
        for name, n, deepen in tried:
            lines.append(f"- {name}(已试 {n} 次):{deepen}")
    if untried:
        lines.append("以下族命令层零执行——每族先打一发探针再谈结论:")
        for name, probe in untried:
            lines.append(f"- {name}:{probe}")
    if sunk:
        lines.append("以下族已沉没大量命令且零产出——禁用,勿再投入:")
        for name, n in sunk:
            lines.append(f"- {name}({n}/{total} = {n // (total // 100) if total >= 100 else int(100 * n / total)}% 命令)")
    return "\n".join(lines) + "\n"
