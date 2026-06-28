#!/usr/bin/env python3
"""
将 ProtonVPN WireGuard 配置文件转换为 Clash 代理格式
目录结构: US/wg-US-FREE-106.conf -> clash_proxies.yaml

用法:
    python wg2clash.py                        # 当前目录下查找
    python wg2clash.py --input ./proton_free_wg --output clash_proxies.yaml
"""

import argparse
import os
import re
import sys
from pathlib import Path

# 目标国家
TARGET_COUNTRIES = {"CA", "CH", "JP", "MX", "NL", "NO", "RO", "SG", "US"}

# 国家名称映射（用于 Clash 代理名称显示）
COUNTRY_NAMES = {
    "CA": "🇨🇦 加拿大",
    "CH": "🇨🇭 瑞士",
    "JP": "🇯🇵 日本",
    "MX": "🇲🇽 墨西哥",
    "NL": "🇳🇱 荷兰",
    "NO": "🇳🇴 挪威",
    "RO": "🇷🇴 罗马尼亚",
    "SG": "🇸🇬 新加坡",
    "US": "🇺🇸 美国",
}


def parse_wg_conf(filepath: Path) -> dict | None:
    """解析 WireGuard .conf 文件，返回关键字段"""
    text = filepath.read_text(encoding="utf-8")

    def get(pattern):
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip() if m else None

    private_key = get(r"PrivateKey\s*=\s*(.+)")
    address     = get(r"Address\s*=\s*(.+)")
    dns         = get(r"DNS\s*=\s*(.+)")
    public_key  = get(r"PublicKey\s*=\s*(.+)")
    endpoint    = get(r"Endpoint\s*=\s*(.+)")
    allowed_ips = get(r"AllowedIPs\s*=\s*(.+)")

    if not all([private_key, public_key, endpoint]):
        return None

    # 解析 endpoint host:port
    ep_match = re.match(r"(.+):(\d+)$", endpoint)
    if not ep_match:
        return None

    return {
        "private_key": private_key,
        "public_key":  public_key,
        "address":     address or "10.2.0.2/32",
        "dns":         dns or "10.2.0.1",
        "server":      ep_match.group(1),
        "port":        int(ep_match.group(2)),
        "allowed_ips": allowed_ips or "0.0.0.0/0",
    }


def conf_to_clash_proxy(name: str, wg: dict) -> list[str]:
    """生成 Clash WireGuard proxy 条目（YAML 行列表）"""
    # Clash 的 WireGuard 代理格式
    ip = wg["address"].split("/")[0]  # 去掉前缀长度
    dns_servers = [d.strip() for d in wg["dns"].split(",")]

    lines = [
        f'  - name: "{name}"',
        f'    type: wireguard',
        f'    server: {wg["server"]}',
        f'    port: {wg["port"]}',
        f'    ip: {ip}',
        f'    private-key: {wg["private_key"]}',
        f'    public-key: {wg["public_key"]}',
        f'    dns: [{", ".join(dns_servers)}]',
        f'    udp: true',
    ]
    return lines


def build_proxy_name(cc: str, stem: str) -> str:
    """构造 Clash 显示名称，如 '🇺🇸 美国 | US-FREE-106'"""
    label = COUNTRY_NAMES.get(cc, cc)
    # 从文件名提取服务器标识，去掉 wg- 前缀和 .conf 后缀
    tag = stem.upper().removeprefix("WG-")
    return f"{label} | {tag}"


def collect_configs(input_dir: Path) -> list[tuple[str, str, dict]]:
    """
    遍历 input_dir/<CC>/*.conf，返回 [(cc, proxy_name, wg_dict), ...]
    只处理 TARGET_COUNTRIES 中的国家
    """
    results = []
    for cc in sorted(TARGET_COUNTRIES):
        country_dir = input_dir / cc
        if not country_dir.is_dir():
            print(f"[!] 目录不存在，跳过: {country_dir}")
            continue

        confs = sorted(country_dir.glob("*.conf"))
        if not confs:
            print(f"[!] {cc}/ 下无 .conf 文件，跳过")
            continue

        for conf_path in confs:
            wg = parse_wg_conf(conf_path)
            if not wg:
                print(f"[!] 解析失败，跳过: {conf_path}")
                continue
            proxy_name = build_proxy_name(cc, conf_path.stem)
            results.append((cc, proxy_name, wg))

        print(f"[+] {cc}: {len(confs)} 个配置")

    return results


def write_clash_yaml(proxies: list[tuple[str, str, dict]], output: Path) -> None:
    """写出 Clash YAML 文件"""
    lines = []

    # ── proxies 块 ────────────────────────────────────────────────────────────
    lines.append("proxies:")
    for cc, name, wg in proxies:
        lines.extend(conf_to_clash_proxy(name, wg))
        lines.append("")  # 空行分隔

    # ── proxy-groups 块 ───────────────────────────────────────────────────────
    lines.append("proxy-groups:")

    # 每个国家一个组
    cc_groups: dict[str, list[str]] = {}
    for cc, name, _ in proxies:
        cc_groups.setdefault(cc, []).append(name)

    all_group_names = []
    for cc in sorted(cc_groups):
        group_name = COUNTRY_NAMES.get(cc, cc)
        all_group_names.append(group_name)
        lines.append(f'  - name: "{group_name}"')
        lines.append(f'    type: url-test')
        lines.append(f'    url: "http://www.gstatic.com/generate_204"')
        lines.append(f'    interval: 300')
        lines.append(f'    tolerance: 50')
        lines.append(f'    proxies:')
        for pname in cc_groups[cc]:
            lines.append(f'      - "{pname}"')
        lines.append("")

    # 全局自动选择组
    lines.append('  - name: "🌍 ProtonVPN Free"')
    lines.append('    type: url-test')
    lines.append('    url: "http://www.gstatic.com/generate_204"')
    lines.append('    interval: 300')
    lines.append('    proxies:')
    for gname in all_group_names:
        lines.append(f'      - "{gname}"')
    lines.append("")

    # 手动选择组
    lines.append('  - name: "🔀 手动选择"')
    lines.append('    type: select')
    lines.append('    proxies:')
    lines.append('      - "🌍 ProtonVPN Free"')
    for gname in all_group_names:
        lines.append(f'      - "{gname}"')
    for _, name, _ in proxies:
        lines.append(f'      - "{name}"')
    lines.append("")

    output.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="WireGuard .conf → Clash proxy YAML 转换工具"
    )
    parser.add_argument("--input",  "-i", default=".",
                        help="WireGuard 配置根目录，下面有 US/ NL/ 等子目录 (默认: 当前目录)")
    parser.add_argument("--output", "-o", default="clash_proxies.yaml",
                        help="输出的 Clash YAML 文件 (默认: clash_proxies.yaml)")
    args = parser.parse_args()

    input_dir = Path(args.input).resolve()
    output    = Path(args.output).resolve()

    if not input_dir.is_dir():
        print(f"[-] 输入目录不存在: {input_dir}")
        sys.exit(1)

    print(f"[*] 扫描目录: {input_dir}")
    print(f"[*] 目标国家: {', '.join(sorted(TARGET_COUNTRIES))}\n")

    proxies = collect_configs(input_dir)
    if not proxies:
        print("[-] 未找到任何有效配置文件")
        sys.exit(1)

    print(f"\n[*] 共 {len(proxies)} 个代理，写出到 {output} ...")
    write_clash_yaml(proxies, output)

    print(f"[✓] 完成！")
    print(f"\n将 {output.name} 中的内容合并到你的 Clash 主配置文件，")
    print(f"或在主配置中用 proxy-providers 引用此文件。")


if __name__ == "__main__":
    main()