#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import json
import base64
import os
import sys
import urllib.parse
from typing import Dict, List, Any, Optional


def load_yaml_config(file_path: str) -> Dict[str, Any]:
    """
    加载YAML配置文件
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            return config
    except Exception as e:
        print(f"加载YAML文件失败: {e}")
        sys.exit(1)


def convert_vmess(proxy: Dict[str, Any]) -> Optional[str]:
    """
    转换vmess节点为v2rayN格式
    """
    try:
        # 创建vmess链接所需的json对象
        vmess_obj = {
            "v": "2",
            "ps": proxy.get('name', 'vmess node'),
            "add": proxy.get('server', ''),
            "port": str(proxy.get('port', '')),
            "id": proxy.get('uuid', ''),
            "aid": str(proxy.get('alterId', 0)),
            "net": proxy.get('network', 'tcp'),
            "type": proxy.get('type', 'none'),
            "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('servername', ''),
            "path": proxy.get('ws-path', '') or proxy.get('path', ''),
            "tls": "tls" if proxy.get('tls', False) else "",
            "sni": proxy.get('servername', '') or proxy.get('sni', ''),
            "alpn": ','.join(proxy.get('alpn', [])) if isinstance(proxy.get('alpn', []), list) else proxy.get('alpn', '')
        }
        
        # 处理特殊情况
        if proxy.get('network') == 'ws':
            vmess_obj['host'] = proxy.get('ws-headers', {}).get('Host', '') or proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
            vmess_obj['path'] = proxy.get('ws-path', '') or proxy.get('ws-opts', {}).get('path', '')
        elif proxy.get('network') == 'h2':
            vmess_obj['host'] = proxy.get('h2-opts', {}).get('host', [''])[0] if isinstance(proxy.get('h2-opts', {}).get('host', []), list) else ''
            vmess_obj['path'] = proxy.get('h2-opts', {}).get('path', '')
        elif proxy.get('network') == 'http':
            vmess_obj['host'] = proxy.get('http-opts', {}).get('headers', {}).get('Host', [''])[0] if isinstance(proxy.get('http-opts', {}).get('headers', {}).get('Host', []), list) else ''
            vmess_obj['path'] = proxy.get('http-opts', {}).get('path', [''])[0] if isinstance(proxy.get('http-opts', {}).get('path', []), list) else ''
        elif proxy.get('network') == 'grpc':
            vmess_obj['path'] = proxy.get('grpc-opts', {}).get('grpc-service-name', '')
            
        # 编码为vmess链接
        vmess_json_str = json.dumps(vmess_obj)
        vmess_b64 = base64.b64encode(vmess_json_str.encode('utf-8')).decode('utf-8')
        return f"vmess://{vmess_b64}"
    except Exception as e:
        print(f"转换vmess节点 '{proxy.get('name', 'unknown')}' 失败: {e}")
        return None


def convert_ss(proxy: Dict[str, Any]) -> Optional[str]:
    """
    转换Shadowsocks节点为v2rayN格式
    """
    try:
        server = proxy.get('server', '')
        port = proxy.get('port', '')
        password = proxy.get('password', '')
        method = proxy.get('cipher', 'aes-128-gcm')
        name = proxy.get('name', 'ss node')
        
        # 创建ss链接
        user_info = f"{method}:{password}"
        user_info_b64 = base64.b64encode(user_info.encode('utf-8')).decode('utf-8')
        
        # 添加插件信息（如果有）
        plugin_str = ""
        if proxy.get('plugin'):
            plugin_opts = proxy.get('plugin-opts', {})
            if proxy['plugin'] == 'obfs':
                plugin = "obfs-local"
                plugin_opts_str = []
                if plugin_opts.get('mode'):
                    plugin_opts_str.append(f"obfs={plugin_opts['mode']}")
                if plugin_opts.get('host'):
                    plugin_opts_str.append(f"obfs-host={plugin_opts['host']}")
                plugin_str = f";plugin={plugin};{';'.join(plugin_opts_str)}"
            elif proxy['plugin'] == 'v2ray-plugin':
                plugin = "v2ray-plugin"
                plugin_opts_str = []
                if plugin_opts.get('mode'):
                    plugin_opts_str.append(f"mode={plugin_opts['mode']}")
                if plugin_opts.get('host'):
                    plugin_opts_str.append(f"host={plugin_opts['host']}")
                if plugin_opts.get('tls'):
                    plugin_opts_str.append("tls")
                plugin_str = f";plugin={plugin};{';'.join(plugin_opts_str)}"
        
        ss_url = f"ss://{user_info_b64}@{server}:{port}{plugin_str}"
        
        # 添加节点名称
        ss_url += f"#{urllib.parse.quote(name)}"
        
        return ss_url
    except Exception as e:
        print(f"转换ss节点 '{proxy.get('name', 'unknown')}' 失败: {e}")
        return None


def convert_trojan(proxy: Dict[str, Any]) -> Optional[str]:
    """
    转换trojan节点为v2rayN格式
    """
    try:
        server = proxy.get('server', '')
        port = proxy.get('port', '')
        password = proxy.get('password', '')
        name = proxy.get('name', 'trojan node')
        sni = proxy.get('sni', '') or proxy.get('servername', '')
        alpn = proxy.get('alpn', [])
        alpn_str = ""
        if alpn:
            if isinstance(alpn, list):
                alpn_str = f"&alpn={','.join(alpn)}"
            else:
                alpn_str = f"&alpn={alpn}"
        
        # 处理网络类型
        network = proxy.get('network', '')
        network_params = ""
        if network == 'ws':
            host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '') or proxy.get('ws-headers', {}).get('Host', '')
            path = proxy.get('ws-opts', {}).get('path', '') or proxy.get('ws-path', '')
            if host:
                network_params += f"&host={urllib.parse.quote(host)}"
            if path:
                network_params += f"&path={urllib.parse.quote(path)}"
            network_params = f"&type=ws{network_params}"
        elif network == 'grpc':
            service_name = proxy.get('grpc-opts', {}).get('grpc-service-name', '')
            if service_name:
                network_params = f"&type=grpc&serviceName={urllib.parse.quote(service_name)}"
        
        # 构建trojan URL
        trojan_url = f"trojan://{password}@{server}:{port}?sni={sni}{alpn_str}{network_params}"
        trojan_url += f"#{urllib.parse.quote(name)}"
        
        return trojan_url
    except Exception as e:
        print(f"转换trojan节点 '{proxy.get('name', 'unknown')}' 失败: {e}")
        return None


def convert_vless(proxy: Dict[str, Any]) -> Optional[str]:
    """
    转换vless节点为v2rayN格式
    """
    try:
        server = proxy.get('server', '')
        port = proxy.get('port', '')
        uuid = proxy.get('uuid', '')
        name = proxy.get('name', 'vless node')
        tls = "tls" if proxy.get('tls', False) else "none"
        sni = proxy.get('servername', '') or proxy.get('sni', '')
        
        # 处理流控制
        flow = proxy.get('flow', '')
        flow_param = f"&flow={flow}" if flow else ""
        
        # 处理网络类型
        network = proxy.get('network', 'tcp')
        network_params = ""
        
        if network == 'ws':
            host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '') or proxy.get('ws-headers', {}).get('Host', '')
            path = proxy.get('ws-opts', {}).get('path', '') or proxy.get('ws-path', '')
            if host:
                network_params += f"&host={urllib.parse.quote(host)}"
            if path:
                network_params += f"&path={urllib.parse.quote(path)}"
        elif network == 'grpc':
            service_name = proxy.get('grpc-opts', {}).get('grpc-service-name', '')
            if service_name:
                network_params += f"&serviceName={urllib.parse.quote(service_name)}"
        elif network == 'tcp':
            if proxy.get('tcp-opts', {}).get('header', {}).get('type') == 'http':
                host = proxy.get('tcp-opts', {}).get('header', {}).get('request', {}).get('headers', {}).get('Host', [''])
                path = proxy.get('tcp-opts', {}).get('header', {}).get('request', {}).get('path', [''])
                if isinstance(host, list) and host:
                    network_params += f"&host={urllib.parse.quote(host[0])}"
                if isinstance(path, list) and path:
                    network_params += f"&path={urllib.parse.quote(path[0])}"
        
        # 处理ALPN
        alpn = proxy.get('alpn', [])
        alpn_str = ""
        if alpn:
            if isinstance(alpn, list):
                alpn_str = f"&alpn={','.join(alpn)}"
            else:
                alpn_str = f"&alpn={alpn}"
        
        # 构建vless URL
        vless_url = f"vless://{uuid}@{server}:{port}?encryption=none&security={tls}&type={network}{network_params}{flow_param}{alpn_str}"
        if sni:
            vless_url += f"&sni={sni}"
        vless_url += f"#{urllib.parse.quote(name)}"
        
        return vless_url
    except Exception as e:
        print(f"转换vless节点 '{proxy.get('name', 'unknown')}' 失败: {e}")
        return None


def convert_hysteria2(proxy: Dict[str, Any]) -> Optional[str]:
    """
    转换hysteria2节点为v2rayN格式
    """
    try:
        server = proxy.get('server', '')
        port = proxy.get('port', '')
        password = proxy.get('password', '') or proxy.get('auth', '')
        name = proxy.get('name', 'hysteria2 node')
        sni = proxy.get('sni', '') or proxy.get('servername', '')
        
        # 处理obfs参数
        obfs = proxy.get('obfs', '')
        obfs_param = proxy.get('obfs-password', '') or proxy.get('obfs-param', '')
        obfs_str = ""
        if obfs:
            obfs_str = f"&obfs={obfs}"
            if obfs_param:
                obfs_str += f"&obfs-password={urllib.parse.quote(obfs_param)}"
        
        # 处理ALPN
        alpn = proxy.get('alpn', '')
        alpn_str = f"&alpn={alpn}" if alpn else ""
        
        # 处理其他参数
        insecure = "&insecure=1" if proxy.get('skip-cert-verify', False) else ""
        pinSHA256 = f"&pinSHA256={proxy.get('fingerprint', '')}" if proxy.get('fingerprint', '') else ""
        
        # 构建hysteria2 URL
        hy2_url = f"hysteria2://{password}@{server}:{port}?sni={sni}{obfs_str}{alpn_str}{insecure}{pinSHA256}"
        hy2_url += f"#{urllib.parse.quote(name)}"
        
        return hy2_url
    except Exception as e:
        print(f"转换hysteria2节点 '{proxy.get('name', 'unknown')}' 失败: {e}")
        return None


def convert_proxies(config: Dict[str, Any]) -> List[str]:
    """
    转换所有代理节点
    """
    v2ray_links = []
    
    # 获取代理列表
    proxies = config.get('proxies', [])
    if not proxies:
        print("未找到任何代理节点")
        return v2ray_links
    
    print(f"找到 {len(proxies)} 个代理节点")
    
    # 转换每个代理
    for proxy in proxies:
        proxy_type = proxy.get('type', '').lower()
        link = None
        
        if proxy_type == 'vmess':
            link = convert_vmess(proxy)
        elif proxy_type == 'ss' or proxy_type == 'shadowsocks':
            link = convert_ss(proxy)
        elif proxy_type == 'trojan':
            link = convert_trojan(proxy)
        elif proxy_type == 'vless':
            link = convert_vless(proxy)
        elif proxy_type == 'hysteria2' or proxy_type == 'hy2':
            link = convert_hysteria2(proxy)
        else:
            print(f"不支持的代理类型: {proxy_type}, 节点名称: {proxy.get('name', 'unknown')}")
            continue
        
        if link:
            v2ray_links.append(link)
    
    return v2ray_links


def main():
    """
    主函数
    """
    # 获取当前目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 查找当前目录下的所有yaml文件
    yaml_files = [f for f in os.listdir(current_dir) if f.endswith(('.yaml', '.yml'))]
    
    if not yaml_files:
        print("当前目录下没有找到yaml文件")
        sys.exit(1)
    
    # 处理所有yaml文件
    all_links = []
    for yaml_file in yaml_files:
        yaml_path = os.path.join(current_dir, yaml_file)
        print(f"处理文件: {yaml_file}")
        
        # 加载配置
        config = load_yaml_config(yaml_path)
        
        # 转换代理
        links = convert_proxies(config)
        all_links.extend(links)
    
    # 写入结果到v2ray.txt
    output_file = os.path.join(current_dir, "v2ray.txt")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_links))
    
    print(f"成功转换 {len(all_links)} 个节点到 {output_file}")


if __name__ == "__main__":
    main()