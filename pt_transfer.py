#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PT 下载器管理命令行工具
支持 Transmission 和 qBittorrent
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("请先安装 requests 库: pip install requests")
    sys.exit(1)


class Config:
    """配置文件管理"""

    def __init__(self, config_path: str = "downloaders.json"):
        self.config_path = Path(config_path)
        self.downloaders: List[Dict] = []
        self.load()

    def load(self):
        """加载配置文件"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.downloaders = data.get('downloaders', [])
            except Exception as e:
                print(f"加载配置文件失败: {e}")
                self.downloaders = []
        else:
            self.downloaders = []

    def save(self):
        """保存配置文件"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({'downloaders': self.downloaders}, f,
                          indent=2, ensure_ascii=False)
            print(f"✓ 配置已保存到 {self.config_path}")
        except Exception as e:
            print(f"✗ 保存配置文件失败: {e}")

    def add_downloader(self, downloader: Dict):
        """添加下载器"""
        self.downloaders.append(downloader)
        self.save()

    def get_downloaders(self) -> List[Dict]:
        """获取所有下载器"""
        return self.downloaders


class TransmissionClient:
    """Transmission 客户端"""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.url = f"http://{host}:{port}/transmission/rpc"
        self.auth = HTTPBasicAuth(username, password)
        self.session_id = None

    def _get_session_id(self):
        """获取 session ID"""
        if self.session_id:
            return

        response = requests.post(
            self.url,
            json={"method": "session-get"},
            auth=self.auth,
            timeout=10
        )

        if response.status_code == 409:
            self.session_id = response.headers.get('X-Transmission-Session-Id')

    def _request(self, method: str, arguments: Dict = None) -> Optional[Dict]:
        """发送请求"""
        try:
            self._get_session_id()
            headers = {'X-Transmission-Session-Id': self.session_id} if self.session_id else {}

            response = requests.post(
                self.url,
                json={"method": method, "arguments": arguments or {}},
                auth=self.auth,
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"请求错误: {e}")
            return None

    def test_connection(self) -> tuple[bool, str]:
        """测试连接"""
        try:
            self._get_session_id()
            headers = {'X-Transmission-Session-Id': self.session_id} if self.session_id else {}

            response = requests.post(
                self.url,
                json={"method": "session-get"},
                auth=self.auth,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('result') == 'success':
                    version = data.get('arguments', {}).get('version', 'Unknown')
                    return True, f"连接成功! 版本: {version}"

            return False, f"连接失败: HTTP {response.status_code}"
        except Exception as e:
            return False, f"连接错误: {str(e)}"

    def get_all_torrents(self) -> List[Dict]:
        """获取所有种子"""
        result = self._request("torrent-get", {
            "fields": ["id", "name", "hashString", "trackers"]
        })

        if result and result.get('result') == 'success':
            return result.get('arguments', {}).get('torrents', [])
        return []

    def remove_torrent(self, torrent_id: int, delete_data: bool = False):
        """删除种子"""
        result = self._request("torrent-remove", {
            "ids": [torrent_id],
            "delete-local-data": delete_data
        })
        return result and result.get('result') == 'success'


class QBittorrentClient:
    """qBittorrent 客户端"""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.url = f"http://{host}:{port}"
        self.username = username
        self.password = password
        self.cookies = None

    def _login(self):
        """登录"""
        if self.cookies:
            return True

        try:
            login_url = f"{self.url}/api/v2/auth/login"
            response = requests.post(
                login_url,
                data={'username': self.username, 'password': self.password},
                timeout=10
            )

            if response.status_code == 200 and response.text == 'Ok.':
                self.cookies = response.cookies
                return True
            return False
        except Exception as e:
            print(f"登录错误: {e}")
            return False

    def test_connection(self) -> tuple[bool, str]:
        """测试连接"""
        try:
            if not self._login():
                return False, "用户名或密码错误"

            version_url = f"{self.url}/api/v2/app/version"
            response = requests.get(version_url, cookies=self.cookies, timeout=10)

            if response.status_code == 200:
                version = response.text.strip()
                return True, f"连接成功! 版本: {version}"

            return False, f"连接失败: HTTP {response.status_code}"
        except Exception as e:
            return False, f"连接错误: {str(e)}"

    def get_all_torrents(self) -> List[Dict]:
        """获取所有种子"""
        if not self._login():
            return []

        try:
            url = f"{self.url}/api/v2/torrents/info"
            response = requests.get(url, cookies=self.cookies, timeout=30)

            if response.status_code == 200:
                torrents = response.json()
                # 获取每个种子的 tracker 信息
                for torrent in torrents:
                    tracker_url = f"{self.url}/api/v2/torrents/trackers"
                    params = {'hash': torrent['hash']}
                    tracker_response = requests.get(
                        tracker_url,
                        params=params,
                        cookies=self.cookies,
                        timeout=10
                    )
                    if tracker_response.status_code == 200:
                        trackers = tracker_response.json()
                        torrent['trackers'] = [{'announce': t['url']} for t in trackers if t['url']]
                    else:
                        torrent['trackers'] = []

                return torrents
            return []
        except Exception as e:
            print(f"获取种子列表错误: {e}")
            return []

    def remove_torrent(self, torrent_hash: str, delete_data: bool = False):
        """删除种子"""
        if not self._login():
            return False

        try:
            url = f"{self.url}/api/v2/torrents/delete"
            data = {
                'hashes': torrent_hash,
                'deleteFiles': 'true' if delete_data else 'false'
            }
            response = requests.post(url, data=data, cookies=self.cookies, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"删除种子错误: {e}")
            return False


def clear_screen():
    """清屏"""
    try:
        # Windows
        if os.name == 'nt':
            os.system('cls')
        else:
            # Unix/Linux/Mac
            # 检查是否有 TERM 环境变量
            if os.environ.get('TERM'):
                os.system('clear')
            else:
                # 如果没有 TERM 变量,使用 ANSI 转义序列
                print('\033[2J\033[H', end='')
    except Exception:
        # 如果清屏失败,就打印空行
        print('\n' * 50)


def print_header(title: str):
    """打印标题"""
    print("\n" + "=" * 50)
    print(f"  {title}")
    print("=" * 50 + "\n")


def extract_tracker_domain(tracker_url: str) -> str:
    """提取 tracker 域名"""
    try:
        parsed = urlparse(tracker_url)
        return parsed.netloc or tracker_url
    except:
        return tracker_url


def get_tracker_domains(client) -> Set[str]:
    """获取所有 tracker 域名"""
    torrents = client.get_all_torrents()
    domains = set()

    for torrent in torrents:
        trackers = torrent.get('trackers', [])
        for tracker in trackers:
            announce = tracker.get('announce', '')
            if announce:
                domain = extract_tracker_domain(announce)
                if domain:
                    domains.add(domain)

    return domains


def get_torrents_by_tracker(client, tracker_domain: str) -> List[Dict]:
    """根据 tracker 域名获取种子"""
    torrents = client.get_all_torrents()
    result = []

    for torrent in torrents:
        trackers = torrent.get('trackers', [])
        for tracker in trackers:
            announce = tracker.get('announce', '')
            if tracker_domain in announce:
                result.append(torrent)
                break

    return result


def show_downloaders(config: Config):
    """显示所有下载器"""
    clear_screen()
    print_header("PT 下载器管理")

    downloaders = config.get_downloaders()

    if not downloaders:
        print("暂无配置的下载器\n")
        return False

    print("已配置的下载器:\n")
    for idx, dl in enumerate(downloaders, 1):
        print(f"{idx}. [{dl['type'].upper()}] {dl['name']}")
        print(f"   地址: {dl['host']}:{dl['port']}")
        print(f"   用户: {dl['username']}\n")

    return True


def select_tracker(client, exclude_domain: str = None) -> Optional[str]:
    """选择 tracker"""
    print("\n正在获取 tracker 列表...")
    domains = get_tracker_domains(client)

    if exclude_domain:
        domains.discard(exclude_domain)

    if not domains:
        print("✗ 没有找到可用的 tracker")
        return None

    domains_list = sorted(list(domains))

    print("\n可用的 tracker 站点:\n")
    for idx, domain in enumerate(domains_list, 1):
        print(f"{idx}. {domain}")

    while True:
        choice = input("\n请选择 tracker (输入编号): ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(domains_list):
                return domains_list[idx]
            else:
                print("✗ 无效的选项,请重新输入")
        except ValueError:
            print("✗ 请输入数字")


def find_cross_seed_torrents(client):
    """查找可以转种的种子"""
    clear_screen()
    print_header("查找可以转种的种子")

    # 选择源站
    print("步骤 1/2: 选择源站点")
    source_tracker = select_tracker(client)
    if not source_tracker:
        return

    print(f"\n已选择源站点: {source_tracker}")

    # 选择目标站
    print("\n步骤 2/2: 选择目标站点")
    target_tracker = select_tracker(client, exclude_domain=source_tracker)
    if not target_tracker:
        return

    print(f"\n已选择目标站点: {target_tracker}")

    # 获取种子列表
    print("\n正在分析种子...")
    source_torrents = get_torrents_by_tracker(client, source_tracker)
    target_torrents = get_torrents_by_tracker(client, target_tracker)

    # 获取目标站已有的种子 hash
    target_hashes = set()
    for torrent in target_torrents:
        hash_str = torrent.get('hashString') or torrent.get('hash', '')
        if hash_str:
            target_hashes.add(hash_str.lower())

    # 找出可以转种的种子
    cross_seed_candidates = []
    for torrent in source_torrents:
        hash_str = torrent.get('hashString') or torrent.get('hash', '')
        if hash_str and hash_str.lower() not in target_hashes:
            cross_seed_candidates.append(torrent)

    # 显示结果
    print(f"\n{'=' * 50}")
    print(f"分析结果:")
    print(f"{'=' * 50}")
    print(f"源站点 ({source_tracker}) 种子数: {len(source_torrents)}")
    print(f"目标站点 ({target_tracker}) 种子数: {len(target_torrents)}")
    print(f"可转种数量: {len(cross_seed_candidates)}")

    if cross_seed_candidates:
        print(f"\n前 10 个可转种的种子:\n")
        for idx, torrent in enumerate(cross_seed_candidates[:10], 1):
            name = torrent.get('name', '未知')
            hash_str = torrent.get('hashString') or torrent.get('hash', '')
            print(f"{idx}. {name}")
            print(f"   Hash: {hash_str}\n")
    else:
        print("\n✓ 没有可转种的种子,所有种子都已存在于目标站点")


def find_diff_torrents(client):
    """查找两个站点差异的种子清单"""
    clear_screen()
    print_header("查找站点差异种子")

    # 选择源站
    print("步骤 1/2: 选择源站点")
    source_tracker = select_tracker(client)
    if not source_tracker:
        return

    print(f"\n已选择源站点: {source_tracker}")

    # 选择目标站
    print("\n步骤 2/2: 选择目标站点")
    target_tracker = select_tracker(client, exclude_domain=source_tracker)
    if not target_tracker:
        return

    print(f"\n已选择目标站点: {target_tracker}")

    # 获取种子列表
    print("\n正在分析种子...")
    source_torrents = get_torrents_by_tracker(client, source_tracker)
    target_torrents = get_torrents_by_tracker(client, target_tracker)

    # 获取源站的种子 hash
    source_hashes = set()
    for torrent in source_torrents:
        hash_str = torrent.get('hashString') or torrent.get('hash', '')
        if hash_str:
            source_hashes.add(hash_str.lower())

    # 找出目标站多出来的种子
    diff_torrents = []
    for torrent in target_torrents:
        hash_str = torrent.get('hashString') or torrent.get('hash', '')
        if hash_str and hash_str.lower() not in source_hashes:
            diff_torrents.append(torrent)

    # 显示结果
    print(f"\n{'=' * 50}")
    print(f"分析结果:")
    print(f"{'=' * 50}")
    print(f"源站点 ({source_tracker}) 种子数: {len(source_torrents)}")
    print(f"目标站点 ({target_tracker}) 种子数: {len(target_torrents)}")
    print(f"目标站多出种子数: {len(diff_torrents)}")

    if diff_torrents:
        print(f"\n目标站点多出的种子:\n")
        for idx, torrent in enumerate(diff_torrents, 1):
            name = torrent.get('name', '未知')
            print(f"{idx}. {name}")
    else:
        print("\n✓ 目标站点没有多余的种子")

    return diff_torrents, target_tracker


def clean_diff_torrents(client, dl_config: Dict):
    """清理两个站点差异的种子清单"""
    result = find_diff_torrents(client)

    if not result:
        return

    diff_torrents, target_tracker = result

    if not diff_torrents:
        return

    # 确认删除
    print(f"\n{'=' * 50}")
    print("⚠️  警告: 此操作将删除上述种子!")
    print(f"{'=' * 50}")

    delete_data = input("\n是否同时删除种子数据? (y/N): ").strip().lower() == 'y'
    confirm = input("确认删除? 输入 'yes' 确认: ").strip().lower()

    if confirm != 'yes':
        print("\n✗ 操作已取消")
        return

    # 执行删除
    print("\n开始删除种子...")
    success_count = 0
    fail_count = 0

    for torrent in diff_torrents:
        name = torrent.get('name', '未知')

        if dl_config['type'] == 'transmission':
            torrent_id = torrent.get('id')
            if client.remove_torrent(torrent_id, delete_data):
                print(f"✓ 已删除: {name}")
                success_count += 1
            else:
                print(f"✗ 删除失败: {name}")
                fail_count += 1
        else:  # qbittorrent
            torrent_hash = torrent.get('hash')
            if client.remove_torrent(torrent_hash, delete_data):
                print(f"✓ 已删除: {name}")
                success_count += 1
            else:
                print(f"✗ 删除失败: {name}")
                fail_count += 1

    print(f"\n{'=' * 50}")
    print(f"删除完成!")
    print(f"成功: {success_count} 个")
    print(f"失败: {fail_count} 个")
    print(f"{'=' * 50}")


def select_downloader_menu(config: Config, dl_config: Dict):
    """选择下载器后的菜单"""
    if dl_config['type'] == 'transmission':
        client = TransmissionClient(
            dl_config['host'],
            dl_config['port'],
            dl_config['username'],
            dl_config['password']
        )
    else:
        client = QBittorrentClient(
            dl_config['host'],
            dl_config['port'],
            dl_config['username'],
            dl_config['password']
        )

    # 测试连接
    success, message = client.test_connection()
    if not success:
        print(f"\n✗ 连接失败: {message}")
        input("\n按回车键继续...")
        return

    while True:
        clear_screen()
        print_header(f"管理下载器: {dl_config['name']}")

        print("功能菜单:\n")
        print("1. 查找可以转种的种子")
        print("2. 查找两个站点差异的种子清单")
        print("3. 清理两个站点差异的种子清单")
        print("0. 返回上级菜单")

        choice = input("\n请选择功能: ").strip()

        if choice == '1':
            find_cross_seed_torrents(client)
            input("\n按回车键继续...")
        elif choice == '2':
            find_diff_torrents(client)
            input("\n按回车键继续...")
        elif choice == '3':
            clean_diff_torrents(client, dl_config)
            input("\n按回车键继续...")
        elif choice == '0':
            break
        else:
            print("\n✗ 无效的选项")
            input("\n按回车键继续...")


def select_downloader(config: Config):
    """选择下载器"""
    downloaders = config.get_downloaders()

    if not downloaders:
        print("\n✗ 暂无配置的下载器")
        return

    print("\n请选择下载器:\n")
    for idx, dl in enumerate(downloaders, 1):
        print(f"{idx}. [{dl['type'].upper()}] {dl['name']}")

    while True:
        choice = input("\n请输入编号 (0 返回): ").strip()

        if choice == '0':
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(downloaders):
                select_downloader_menu(config, downloaders[idx])
                return
            else:
                print("✗ 无效的选项,请重新输入")
        except ValueError:
            print("✗ 请输入数字")


def add_downloader(config: Config):
    """添加下载器"""
    clear_screen()
    print_header("添加新下载器")

    # 步骤1: 输入下载器名称
    name = input("请输入下载器名称 (例如: 我的 Transmission): ").strip()
    if not name:
        print("✗ 名称不能为空")
        return

    # 步骤2: 选择下载器类型
    print("\n请选择下载器类型:")
    print("1. Transmission")
    print("2. qBittorrent")

    choice = input("\n请输入选项 (1-2): ").strip()

    if choice == '1':
        dl_type = 'transmission'
    elif choice == '2':
        dl_type = 'qbittorrent'
    else:
        print("✗ 无效的选项")
        return

    # 步骤3: 填写服务器地址
    host = input("\n请输入服务器地址 (例如: 192.168.1.100,不需要带http): ").strip()
    if not host:
        print("✗ 地址不能为空")
        return

    # 步骤4: 填写端口
    port_str = input("请输入端口 (Transmission 默认 9091, qBittorrent 默认 8080): ").strip()
    try:
        port = int(port_str)
        if port < 1 or port > 65535:
            raise ValueError()
    except ValueError:
        print("✗ 端口必须是 1-65535 之间的数字")
        return

    # 步骤5: 填写用户名
    username = input("请输入用户名: ").strip()
    if not username:
        print("✗ 用户名不能为空")
        return

    # 步骤6: 填写密码
    password = input("请输入密码: ").strip()
    if not password:
        print("✗ 密码不能为空")
        return

    # 步骤7: 测试连接
    print("\n正在测试连接...")

    if dl_type == 'transmission':
        client = TransmissionClient(host, port, username, password)
    else:
        client = QBittorrentClient(host, port, username, password)

    success, message = client.test_connection()

    print(f"\n{message}")

    if success:
        # 保存配置
        downloader = {
            'name': name,
            'type': dl_type,
            'host': host,
            'port': port,
            'username': username,
            'password': password
        }
        config.add_downloader(downloader)
        print("\n✓ 下载器添加成功!")
    else:
        print("\n✗ 连接失败,配置未保存")


def main():
    """主函数"""
    config = Config()

    while True:
        has_downloaders = show_downloaders(config)

        print("\n可用操作:")
        print("1. 添加新下载器")
        if has_downloaders:
            print("2. 选择下载器")
        print("0. 退出程序")

        choice = input("\n请选择操作: ").strip()

        if choice == '1':
            add_downloader(config)
            input("\n按回车键继续...")
        elif choice == '2' and has_downloaders:
            select_downloader(config)
        elif choice == '0':
            print("\n再见!")
            break
        else:
            print("\n✗ 无效的选项")
            input("\n按回车键继续...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序已中断,再见!")
        sys.exit(0)