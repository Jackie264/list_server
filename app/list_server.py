#!/usr/bin/env python3
# app/list_server.py

import http.server
import socketserver
import os
import urllib.parse
import html
import sys
import json
import mimetypes
import datetime
import time
import shutil
import socket
from socketserver import ThreadingMixIn

LISTEN_PORT = 8001
FILE_SERVER_ROOT = os.environ.get('FILE_SERVER_ROOT', '/feeds_data')
ABS_FILE_SERVER_ROOT = os.path.abspath(FILE_SERVER_ROOT)
STATIC_ASSETS_DIR = "/style"
CSS_URL = "/style/main.css"

# ==================== symlink 安全边界配置 ====================
# 我们仍然允许 FILE_SERVER_ROOT 下存在软链接（包括指向根目录之外的软链接），
# 但要求软链接“解析后的真实路径”必须落在一个受信任的根目录集合内，
# 否则拒绝访问。这样既保留了软链接的可用性，又避免了任意路径穿越
# （例如 /feeds_data/evil -> /etc 这种情况）。
#
# 默认只信任 FILE_SERVER_ROOT 自身（解析后的真实路径）。
# 如果你确实需要软链接指向根目录之外的其他目录，
# 通过环境变量 FILE_SERVER_ALLOWED_SYMLINK_TARGETS 追加，
# 多个路径用系统的 os.pathsep（Linux 下是 ":"）分隔。
REAL_FILE_SERVER_ROOT = os.path.realpath(ABS_FILE_SERVER_ROOT)

_extra_roots_env = os.environ.get("FILE_SERVER_ALLOWED_SYMLINK_TARGETS", "")
ALLOWED_REAL_ROOTS = [REAL_FILE_SERVER_ROOT]
if _extra_roots_env.strip():
    for _p in _extra_roots_env.split(os.pathsep):
        _p = _p.strip()
        if not _p:
            continue
        _real_extra = os.path.realpath(os.path.abspath(_p))
        if _real_extra not in ALLOWED_REAL_ROOTS:
            ALLOWED_REAL_ROOTS.append(_real_extra)
# ==================== 结束 symlink 安全边界配置 ====================

# 从环境变量读取 JSON 配置
DOMAIN_FOOTER_INFO_ENV = os.environ.get("DOMAIN_FOOTER_INFO_JSON", "")

if DOMAIN_FOOTER_INFO_ENV.strip():
    try:
        DOMAIN_FOOTER_INFO = json.loads(DOMAIN_FOOTER_INFO_ENV)
        if not isinstance(DOMAIN_FOOTER_INFO, dict):
            raise ValueError("DOMAIN_FOOTER_INFO_JSON must be a JSON object")
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Failed to parse DOMAIN_FOOTER_INFO_JSON: {e}", file=sys.stderr)
        DOMAIN_FOOTER_INFO = {}
else:
    # 默认值（可选）
    DOMAIN_FOOTER_INFO = {}


def human_readable_size(size_bytes):
    if size_bytes is None:
        return "-"
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = 0
    while i < len(size_name) - 1 and size_bytes >= 1024:
        size_bytes /= 1024
        i += 1
    format_string = "{:.0f} {}" if i == 0 else "{:.1f} {}"
    return format_string.format(size_bytes, size_name[i])


def format_mtime(timestamp):
    if timestamp is None:
        return "-"
    try:
        return datetime.datetime.fromtimestamp(timestamp).strftime("%a %b %d %H:%M:%S %Y")
    except (ValueError, TypeError):
        return "-"


def resolve_safe_path(requested_url_path_normalized):
    """
    将（已经过 normpath 处理的）URL 路径解析为服务器上的真实物理路径，
    并确保解析软链接之后的真实路径仍然落在 ALLOWED_REAL_ROOTS 中的
    某一个受信任根目录之下。

    返回解析后的真实物理路径；如果校验失败，返回 None。
    """
    try:
        candidate = os.path.normpath(
            os.path.join(ABS_FILE_SERVER_ROOT, requested_url_path_normalized.lstrip('/'))
        )
        real_candidate = os.path.realpath(candidate)
    except Exception:
        return None

    # 使用 commonpath 做目录包含关系校验，避免字符串前缀比较误判
    try:
        if os.path.commonpath([ABS_FILE_SERVER_ROOT, candidate]) != ABS_FILE_SERVER_ROOT:
            return None
    except ValueError:
        return None

    # 解析软链接后的真实路径必须位于允许的真实根目录集合内
    for allowed_root in ALLOWED_REAL_ROOTS:
        try:
            if os.path.commonpath([allowed_root, real_candidate]) == allowed_root:
                return real_candidate
        except ValueError:
            continue

    return None


class CustomListingAndFileHandler(http.server.BaseHTTPRequestHandler):
    # ==================== 新增方法来服务静态文件 ====================
    def _serve_static_file(self, requested_url_path):
        """
        根据 URL 路径，从 STATIC_ASSETS_DIR 目录服务静态文件。
        执行安全检查，防止目录遍历攻击。
        """
        try:
            # 提取 /style/ 后的子路径，例如 "main.css" 或 "icons/favicon.ico"
            # 假设所有静态文件请求都以 /style/ 开头
            if requested_url_path.startswith('/style/'):
                # 获取 /style/ 后的部分路径
                sub_path = requested_url_path[len('/style/'):]
            else:
                # 理论上此分支不应该被触发，因为 do_GET 会先判断
                self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Unexpected static path request.")
                return

            # 对子路径进行 URL 解码和规范化，防止编码问题和路径异常
            decoded_sub_path = urllib.parse.unquote(sub_path, errors='surrogateescape')
            normalized_sub_path = os.path.normpath(decoded_sub_path)
            # 额外检查：拒绝任何绝对路径
            if os.path.isabs(normalized_sub_path):
                self.send_error(http.HTTPStatus.BAD_REQUEST, "Absolute paths are not allowed.")
                return

            # 构建和规范化目标物理路径
            candidate_path = os.path.normpath(os.path.join(STATIC_ASSETS_DIR, normalized_sub_path))

            # --- 第一层安全检查：对拼接/规范化后的字符串路径做 startswith 校验 ---
            # 写法对照 CodeQL 官方 py/path-injection 文档的推荐模式
            # （https://codeql.github.com/codeql-query-help/python/py-path-injection/），
            # 加 os.sep 后缀避免 "/style_evil" 这种前缀碰瓷绕过 "/style"。
            static_root_with_sep = STATIC_ASSETS_DIR + os.sep
            if not (candidate_path == STATIC_ASSETS_DIR or candidate_path.startswith(static_root_with_sep)):
                self.send_error(http.HTTPStatus.FORBIDDEN, "Access to requested path outside static assets directory is forbidden.")
                return
            # --- 结束第一层安全检查 ---

            # 获取 STATIC_ASSETS_DIR 和候选文件的真实路径（解析 symlink）
            abs_static_realroot = os.path.realpath(os.path.abspath(STATIC_ASSETS_DIR))
            abs_file_realpath = os.path.realpath(os.path.abspath(candidate_path))

            # --- 第二层安全检查：解析软链接后的真实路径仍必须落在静态根目录内 ---
            static_realroot_with_sep = abs_static_realroot + os.sep
            if not (abs_file_realpath == abs_static_realroot or abs_file_realpath.startswith(static_realroot_with_sep)):
                self.send_error(http.HTTPStatus.FORBIDDEN, "Access to requested path outside static assets directory is forbidden.")
                return
            # --- 结束安全检查 ---

            # 检查文件是否存在且是普通文件
            if not os.path.isfile(abs_file_realpath):
                self.send_error(http.HTTPStatus.NOT_FOUND, "Static file not found.")
                return
            # 加强：禁止符号链接
            if os.path.islink(abs_file_realpath):
                self.send_error(http.HTTPStatus.FORBIDDEN, "Symlinks are not allowed for static assets.")
                return
            # 安全检查已于上方完成，无需重复校验

            # 猜测文件的 MIME 类型
            mimetype, _ = mimetypes.guess_type(abs_file_realpath)
            if mimetype is None:
                mimetype = 'application/octet-stream'  # 如果无法猜测，使用通用二进制流
            # 就地清除 CR/LF/冒号，防止 HTTP Response Splitting；
            # 直接写在 send_header 调用旁边，而不是经过独立的工具函数。
            safe_mimetype = mimetype.replace('\r', '').replace('\n', '').replace(':', '')
            self.send_response(http.HTTPStatus.OK)
            self.send_header("Content-type", safe_mimetype)
            self.send_header("Content-Length", str(os.path.getsize(abs_file_realpath)))
            # 强烈建议为静态文件添加缓存头，提高客户端加载速度
            self.send_header('Cache-Control', 'public, max-age=31536000')  # 缓存一年
            self.end_headers()

            # 以二进制模式读取文件并写入响应体
            with open(abs_file_realpath, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)  # 高效地复制文件内容到响应流
            return

        except FileNotFoundError:
            self.send_error(http.HTTPStatus.NOT_FOUND, "Static file not found.")
        except PermissionError:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied to read static file.")
        except Exception as e:
            # 捕获其他未知错误
            print(f"Error serving static file {requested_url_path}: {e}", file=sys.stderr)
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error serving static file.")

    # ==================== 结束新增方法 ====================

    def do_GET(self):
        # ==================== 优先处理 /style/ 静态文件请求 ====================
        if self.path.startswith('/style/'):
            self._serve_static_file(self.path)
            return  # 处理完静态文件后直接返回，不执行后续逻辑
        # ==================== 结束 ====================

        parsed_url = urllib.parse.urlparse(self.path)
        url_path = parsed_url.path
        try:
            decoded_url_path = urllib.parse.unquote(url_path, errors='surrogateescape')
            decoded_url_path = os.path.normpath(decoded_url_path)
        except Exception:
            self.send_error(http.HTTPStatus.BAD_REQUEST, "Bad path.")
            return

        # ==================== 路径安全校验（支持软链接） ====================
        # 使用 resolve_safe_path 统一校验：解析软链接之后的真实路径，
        # 必须落在 ALLOWED_REAL_ROOTS 允许的根目录集合内。
        # 后续所有文件系统操作（isdir/isfile/listdir/open）都基于这个
        # 已校验过的真实路径进行，而不是未经 realpath 解析的拼接路径，
        # 避免 "校验一个路径、实际访问另一个路径" 的漏洞。
        real_physical_path = resolve_safe_path(decoded_url_path)
        if real_physical_path is None:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Access denied.")
            return
        # ==================== 结束路径安全校验 ====================

        try:
            if os.path.isdir(real_physical_path):
                self.serve_directory_listing(real_physical_path, decoded_url_path)
            elif os.path.isfile(real_physical_path):
                self.serve_file(real_physical_path)
            elif os.path.exists(real_physical_path):
                self.send_error(http.HTTPStatus.NOT_FOUND, "Resource type not supported.")
            else:
                self.send_error(http.HTTPStatus.NOT_FOUND, "Resource not found.")
        except PermissionError:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied.")
        except Exception as e:
            print(f"Unexpected error processing path {real_physical_path}: {e}", file=sys.stderr)
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")

    def serve_directory_listing(self, physical_path, display_url_path):
        try:
            items = os.listdir(physical_path)
            filtered_items = [
                name for name in items
                if not name.startswith('.')
            ]
            filtered_items.sort(key=str.lower)
        except OSError as e:
            print(f"Error listing directory {physical_path}: {e}", file=sys.stderr)
            self.send_error(
                http.HTTPStatus.INTERNAL_SERVER_ERROR,
                "Could not list directory: Permission denied or directory not found."
            )
            return

        r = []
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append('<meta charset="utf-8">')
        r.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        r.append(f'<title>Index of {html.escape(display_url_path)}</title>')
        r.append(f'<link rel="stylesheet" href="{html.escape(CSS_URL)}">')

        r.append('<link rel="icon" href="/style/favicon.ico" type="image/x-icon">')
        r.append('<link rel="icon" type="image/png" sizes="16x16" href="/style/favicon-16x16.png">')
        r.append('<link rel="icon" type="image/png" sizes="32x32" href="/style/favicon-32x32.png">')
        r.append('<link rel="apple-touch-icon" sizes="180x180" href="/style/apple-touch-icon.png">')
        r.append('<link rel="manifest" href="/style/site.webmanifest">')
        r.append('<meta name="theme-color" content="#ffffff">')

        r.append('</head><body>')

        r.append('<div class="container">')

        header_components = ['<h1>']
        header_components.append('<span class="listing-logo-container">')
        header_components.append(f'<img src="{html.escape("/style/apple-touch-icon.png")}" class="listing-logo-image">')
        header_components.append('</span>')
        header_components.append('Index of')
        header_components.append('&nbsp;')
        header_components.append('<a href="/">Home</a>')

        if display_url_path != '/':
            segments = display_url_path.strip('/').split('/')
            current_url_accumulator = '/'
            for i, segment in enumerate(segments):
                header_components.append(' / ')
                escaped_segment = html.escape(segment)
                quoted_segment_for_url = urllib.parse.quote(segment, errors='surrogateescape')
                current_url_accumulator = urllib.parse.urljoin(current_url_accumulator, quoted_segment_for_url + '/')
                if i < len(segments) - 1:
                    header_components.append(f'<a href="{current_url_accumulator}">{escaped_segment}</a>')
                else:
                    header_components.append(f'{escaped_segment}')

        header_components.append('</h1>')
        r.append(''.join(header_components))

        r.append('<hr>')

        r.append('<table id="fileTable">')
        r.append('<thead>')
        r.append('<tr>')
        r.append('<th data-sort-by="name">File Name</th>')
        r.append('<th data-sort-by="size">File Size</th>')
        r.append('<th data-sort-by="date">Date</th>')
        r.append('</tr>')
        r.append('</thead>')
        r.append('<tbody>')

        if display_url_path != '/':
            parent_url_path = os.path.normpath(os.path.join(display_url_path, os.pardir))
            parent_url_path = parent_url_path if parent_url_path.endswith('/') else parent_url_path + '/'
            quoted_parent_url_path = urllib.parse.quote(parent_url_path, errors='surrogateescape')
            r.append(f'<tr class="parent-dir" data-name="../" data-size="-2" data-date="-2">')
            r.append(f'<td><a href="{quoted_parent_url_path}">../</a></td>')
            r.append('<td>-</td>')
            r.append('<td>-</td>')
            r.append('</tr>')

        for name in filtered_items:
            # name 来自 os.listdir(physical_path)，即已校验目录下的真实文件系统条目，
            # 而不是用户请求中的原始字符串；这里再就地做一次 startswith 校验，
            # 作为并发场景（TOCTOU）下的兜底防护。
            item_physical_path = os.path.join(physical_path, name)
            item_real_path = os.path.realpath(item_physical_path)
            item_is_within_trusted_root = any(
                item_real_path == allowed_root or item_real_path.startswith(allowed_root + os.sep)
                for allowed_root in ALLOWED_REAL_ROOTS
            )
            if not item_is_within_trusted_root:
                # 理论上不会发生（目录本身已校验过），出现说明并发场景下
                # 文件系统发生了变化（TOCTOU），直接跳过这一项更安全。
                continue

            base_url_for_join = display_url_path if display_url_path.endswith('/') else display_url_path + '/'
            quoted_item_name = urllib.parse.quote(name, errors='surrogateescape')
            item_url_path = urllib.parse.urljoin(base_url_for_join, quoted_item_name)

            displayname = html.escape(name)
            is_dir = os.path.isdir(item_real_path)
            if is_dir:
                displayname += "/"
                if not item_url_path.endswith('/'):
                    item_url_path += '/'

            stats = None
            try:
                stats = os.stat(item_real_path)
            except OSError:
                pass

            sort_name = name
            sort_size = stats.st_size if stats and not is_dir else -1
            sort_date = stats.st_mtime if stats else -1

            size_display = "-"
            date_display = "-"

            if stats:
                if not is_dir:
                    size_display = human_readable_size(stats.st_size)
                date_display = format_mtime(stats.st_mtime)

            escaped_sort_name = html.escape(str(sort_name), quote=True)
            escaped_sort_size = html.escape(str(sort_size), quote=True)
            escaped_sort_date = html.escape(str(sort_date), quote=True)

            r.append(f'<tr data-name="{escaped_sort_name}" data-size="{escaped_sort_size}" data-date="{escaped_sort_date}">')
            r.append(f'<td><a href="{item_url_path}">{displayname}</a></td>')
            r.append(f'<td>{size_display}</td>')
            r.append(f'<td>{date_display}</td>')
            r.append('</tr>')

        r.append('</tbody>')
        r.append('</table>')

        display_domain = "Unknown Host"
        host_header = self.headers.get('Host')
        domain_info = None

        if host_header:
            hostname = host_header.split(':')[0]
            parts = hostname.split('.')
            if len(parts) > 1:
                main_domain = '.'.join(parts[-2:])
            else:
                main_domain = hostname
            display_domain = main_domain

            domain_info = DOMAIN_FOOTER_INFO.get(display_domain)

        r.append('<p class="footer-info">')
        r.append('  <span class="footer-left">')

        if domain_info and (domain_info.get("icp_text", "") or domain_info.get("mps_text", "")):
            icp_text_val = domain_info.get("icp_text", "")
            icp_url_val = domain_info.get("icp_url", "#")
            mps_text_val = domain_info.get("mps_text", "")
            mps_url_val = domain_info.get("mps_url", "#")

            if icp_text_val:
                r.append(f'    <a href="{html.escape(icp_url_val)}" target="_blank">{html.escape(icp_text_val)}</a>')

            if icp_text_val and mps_text_val:
                r.append('    &nbsp;&nbsp;')

            if mps_text_val:
                r.append(f'    <img src="https://beian.mps.gov.cn/img/logo01.dd7ff50e.png" alt="公安网备图标" class="beian-icon">')
                r.append(f'    <a href="{html.escape(mps_url_val)}" rel="noreferrer" target="_blank">{html.escape(mps_text_val)}</a>')

        r.append('  </span>')
        r.append('  <span class="footer-right">')
        r.append('    Page is auto-generated with <a href="https://www.python.org/" target="_blank">Python</a>')
        r.append('  </span>')
        r.append('</p>')

        current_year = datetime.datetime.now().year
        r.append(f'<p class="footer">Copyright &copy; {current_year} {html.escape(display_domain)} All Rights Reserved.</p>')
        r.append('<script src="/style/sort.js"></script>')

        r.append('</div>')
        r.append('</body></html>')

        encoded_html = '\n'.join(r).encode('utf-8')

        self.send_response(http.HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_html)))
        self.end_headers()
        self.wfile.write(encoded_html)

    def serve_file(self, physical_path):
        try:
            mimetype, _ = mimetypes.guess_type(physical_path)
            if mimetype is None:
                mimetype = 'application/octet-stream'
            # 就地清除 CR/LF/冒号，防止 HTTP Response Splitting；
            # 直接写在 send_header 调用旁边，而不是经过独立的工具函数。
            safe_mimetype = mimetype.replace('\r', '').replace('\n', '').replace(':', '')

            file_size = os.path.getsize(physical_path)

            self.send_response(http.HTTPStatus.OK)
            self.send_header("Content-type", safe_mimetype)
            self.send_header("Content-Length", str(file_size))
            self.end_headers()

            with open(physical_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)

        except FileNotFoundError:
            self.send_error(http.HTTPStatus.NOT_FOUND, "File not found or inaccessible.")
        except PermissionError:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied to read file.")
        except Exception as e:
            print(f"Error serving file {physical_path}: {e}", file=sys.stderr)
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")


class ThreadedTCPServer(ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    print("Feeds directory lister script is starting...")
    sys.stdout.flush()
    print(f"Running with Python version: {sys.version}")
    sys.stdout.flush()

    if not os.path.isdir(FILE_SERVER_ROOT):
        print(f"Error: Feeds root directory not found or not accessible: {FILE_SERVER_ROOT}", file=sys.stderr)
        sys.stdout.flush()
        sys.exit(1)

    # ==================== 检查 STATIC_ASSETS_DIR ====================
    # 确保静态文件目录也存在，否则静态文件无法被服务
    if not os.path.isdir(STATIC_ASSETS_DIR):
        print(f"Warning: Static assets directory not found or not accessible: {STATIC_ASSETS_DIR}", file=sys.stderr)
        # 可以选择退出或继续，这里我们选择警告并继续，因为可能有些部署不需要静态文件
        sys.stdout.flush()
    # ==================== 结束 ====================

    print(f"Attempting to start server on port {LISTEN_PORT}")
    sys.stdout.flush()
    print(f"Serving content from file root: {FILE_SERVER_ROOT}")
    sys.stdout.flush()
    print(f"Allowed real roots (symlink targets included): {ALLOWED_REAL_ROOTS}")
    sys.stdout.flush()

    server_address = ('', LISTEN_PORT)

    try:
        with ThreadedTCPServer(server_address, CustomListingAndFileHandler, bind_and_activate=False) as httpd:
            httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print("Setting SO_REUSEADDR option and attempting to bind socket...")
            sys.stdout.flush()

            httpd.server_bind()
            httpd.server_activate()

            print(f"Server successfully bound and activated on http://localhost:{LISTEN_PORT}")
            sys.stdout.flush()
            print("Starting server loop. Press Ctrl+C to stop.")
            sys.stdout.flush()

            httpd.serve_forever()
    except PermissionError:
        print(f"Error: Permission denied to bind on port {LISTEN_PORT}. Try running with sudo or a higher port.", file=sys.stderr)
        sys.stdout.flush()
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.stdout.flush()
        sys.exit(1)
