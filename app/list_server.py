#!/usr/bin/env python3
# app/list_server.py

import http.server
import socketserver
import os
import stat
import urllib.parse
import html
import sys
import json
import mimetypes
import datetime
import shutil
import socket
from socketserver import ThreadingMixIn

LISTEN_PORT = 8001
FILE_SERVER_ROOT = os.environ.get('FILE_SERVER_ROOT', '/feeds_data')
ABS_FILE_SERVER_ROOT = os.path.abspath(FILE_SERVER_ROOT)
STATIC_ASSETS_DIR = "/style"
CSS_URL = "/style/main.css"

# ==================== 隐藏/拒绝访问规则 ====================
# 1. 以 "." 开头的文件/目录（.env、.git、.htpasswd ……）：列表隐藏 + 直接访问也拒绝
# 2. 以指定后缀结尾的文件（默认 .pem）：列表隐藏 + 直接访问也拒绝
#    可通过环境变量 FILE_SERVER_HIDDEN_SUFFIXES 自定义，逗号分隔，
#    例如 ".pem,.key,.crt"；设置为空字符串则不隐藏任何后缀。
_hidden_suffixes_env = os.environ.get("FILE_SERVER_HIDDEN_SUFFIXES", ".pem")
HIDDEN_SUFFIXES = tuple(
    s.strip().lower() for s in _hidden_suffixes_env.split(",") if s.strip()
)


def is_hidden_name(name):
    """单个文件名/目录名是否应当被隐藏（并拒绝访问）。大小写不敏感。"""
    if not name:
        return False
    if name.startswith('.'):
        return True
    return bool(HIDDEN_SUFFIXES) and name.lower().endswith(HIDDEN_SUFFIXES)
# ==================== 结束 隐藏规则 ====================

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

# 目录列表页的内容安全策略：页面本身没有内联脚本/样式，全部来自同源 /style/
# （备案图标来自 beian.mps.gov.cn）
LISTING_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' https://beian.mps.gov.cn data:; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

CONNECTION_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout)


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
    except (ValueError, TypeError, OverflowError, OSError):
        return "-"


def is_within_allowed_roots(real_path):
    for allowed_root in ALLOWED_REAL_ROOTS:
        if real_path == allowed_root or real_path.startswith(allowed_root.rstrip(os.sep) + os.sep):
            return True
    return False


def resolve_safe_path(requested_url_path_normalized):
    """
    将（已经过 normpath 处理的）URL 路径解析为服务器上的真实物理路径，
    并确保：
      1. 解析软链接之后的真实路径仍然落在 ALLOWED_REAL_ROOTS 中的某一个受信任根目录之下；
      2. 请求路径的任何一级、以及解析后的最终文件名，都不是被隐藏的名字
         （dotfile、.pem 等）。

    返回解析后的真实物理路径；如果校验失败，返回 None。
    """
    if not isinstance(requested_url_path_normalized, str):
        return None
    if '\x00' in requested_url_path_normalized:
        return None

    try:
        # 强制按“绝对 URL 路径”语义归一化，再转为相对路径，避免绝对路径覆盖 join 基路径
        safe_rel = os.path.normpath('/' + requested_url_path_normalized).lstrip('/')
        candidate = os.path.abspath(os.path.join(ABS_FILE_SERVER_ROOT, safe_rel))
    except Exception:
        return None

    # 请求路径中任何一级是隐藏名（.xxx / *.pem）都直接拒绝
    for part in safe_rel.split('/'):
        if is_hidden_name(part):
            return None

    # candidate 必须位于 FILE_SERVER_ROOT 之下
    try:
        if os.path.commonpath([ABS_FILE_SERVER_ROOT, candidate]) != ABS_FILE_SERVER_ROOT:
            return None
    except ValueError:
        return None

    try:
        real_candidate = os.path.realpath(candidate)
    except Exception:
        return None

    # 解析软链接后的真实路径必须位于允许的真实根目录集合内。
    #
    # 写法说明（为了让 CodeQL py/path-injection 能识别为净化）：
    #   - 对 realpath 之后的同一个变量做单独的 startswith 判断；
    #   - 只在判断为真的分支里 return 该变量，不使用 any()/辅助函数/or 组合条件；
    #   - 路径恰好等于根目录本身时，返回根目录常量，而不是用户派生的值。
    for allowed_root in ALLOWED_REAL_ROOTS:
        if real_candidate == allowed_root:
            return allowed_root
        if real_candidate.startswith(allowed_root.rstrip(os.sep) + os.sep):
            # 软链接指向 xxx.pem / .xxx 的情况：按最终真实文件名再检查一次
            if is_hidden_name(os.path.basename(real_candidate)):
                return None
            return real_candidate

    return None


class CustomListingAndFileHandler(http.server.BaseHTTPRequestHandler):
    # 不暴露 "BaseHTTP/0.6 Python/3.x" 版本信息
    server_version = "ListServer"
    sys_version = ""
    # 单个 socket 操作的超时，缓解 slowloris 类慢速连接占用线程
    timeout = 60

    # ==================== 公共响应头 ====================
    def _send_common_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    # ==================== 服务静态文件 ====================
    def _serve_static_file(self, requested_url_path):
        """
        根据 URL 路径（不含 query string），从 STATIC_ASSETS_DIR 目录服务静态文件。
        执行安全检查，防止目录遍历攻击。
        """
        try:
            if requested_url_path.startswith('/style/'):
                sub_path = requested_url_path[len('/style/'):]
            else:
                self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Unexpected static path request.")
                return

            # 对子路径进行 URL 解码和规范化，防止编码问题和路径异常
            decoded_sub_path = urllib.parse.unquote(sub_path, errors='surrogateescape')
            if '\x00' in decoded_sub_path:
                self.send_error(http.HTTPStatus.BAD_REQUEST, "Bad path.")
                return
            normalized_sub_path = os.path.normpath(decoded_sub_path)
            # 额外检查：拒绝任何绝对路径
            if os.path.isabs(normalized_sub_path):
                self.send_error(http.HTTPStatus.BAD_REQUEST, "Absolute paths are not allowed.")
                return

            # 构建和规范化目标物理路径
            candidate_path = os.path.normpath(os.path.join(STATIC_ASSETS_DIR, normalized_sub_path))

            # --- 第一层安全检查：字符串前缀校验（加 os.sep 避免 "/style_evil" 碰瓷） ---
            static_root_with_sep = STATIC_ASSETS_DIR + os.sep
            # 注意：这里刻意只用单个 startswith，不要写成 "a == root or a.startswith(...)"。
            # CodeQL 的 py/path-injection 只认“归一化后 + 单独的 startswith 守卫”，
            # 带 or 的复合条件无法被识别为净化，会产生误报。
            # 也不需要允许 candidate_path == STATIC_ASSETS_DIR：目录本身不是可服务的文件。
            if not candidate_path.startswith(static_root_with_sep):
                self.send_error(http.HTTPStatus.FORBIDDEN, "Access to requested path outside static assets directory is forbidden.")
                return

            # --- 第二层安全检查：解析软链接后的真实路径仍必须落在静态根目录内 ---
            abs_static_realroot = os.path.realpath(os.path.abspath(STATIC_ASSETS_DIR))
            abs_file_realpath = os.path.realpath(os.path.abspath(candidate_path))
            static_realroot_with_sep = abs_static_realroot + os.sep
            # 同上：单独的 startswith 守卫，且检查的就是下面 open() 实际使用的变量。
            if not abs_file_realpath.startswith(static_realroot_with_sep):
                self.send_error(http.HTTPStatus.FORBIDDEN, "Access to requested path outside static assets directory is forbidden.")
                return

            mimetype, _ = mimetypes.guess_type(abs_file_realpath)
            if mimetype is None:
                mimetype = 'application/octet-stream'
            # 就地清除 CR/LF/冒号，防止 HTTP Response Splitting
            safe_mimetype = mimetype.replace('\r', '').replace('\n', '').replace(':', '')

            # 先打开、再 fstat：确认是普通文件，并避免“检查后文件被替换”的竞争
            with open(abs_file_realpath, 'rb') as f:
                fs = os.fstat(f.fileno())
                if not stat.S_ISREG(fs.st_mode):
                    self.send_error(http.HTTPStatus.NOT_FOUND, "Static file not found.")
                    return

                self.send_response(http.HTTPStatus.OK)
                self.send_header("Content-type", safe_mimetype)
                self.send_header("Content-Length", str(fs.st_size))
                self.send_header('Cache-Control', 'public, max-age=31536000')
                self._send_common_security_headers()
                self.end_headers()
                shutil.copyfileobj(f, self.wfile)
            return

        except CONNECTION_ERRORS:
            return  # 客户端中途断开，无需处理
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            self.send_error(http.HTTPStatus.NOT_FOUND, "Static file not found.")
        except PermissionError:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied to read static file.")
        except Exception as e:
            print(f"Error serving static file {requested_url_path}: {e}", file=sys.stderr)
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error serving static file.")

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        url_path = parsed_url.path

        # ==================== 优先处理 /style/ 静态文件请求 ====================
        # 注意：必须用去掉 query string 的 url_path 判断，否则 /style/main.css?v=1 会 404
        if url_path.startswith('/style/'):
            self._serve_static_file(url_path)
            return

        try:
            decoded_url_path = urllib.parse.unquote(url_path, errors='surrogateescape')
            if '\x00' in decoded_url_path:
                raise ValueError("NUL byte in path")
            # 统一成以单个 "/" 开头（normpath 会保留开头的 "//"，这里先去掉）
            decoded_url_path = os.path.normpath('/' + decoded_url_path.lstrip('/'))
        except Exception:
            self.send_error(http.HTTPStatus.BAD_REQUEST, "Bad path.")
            return

        # ==================== 路径安全校验（支持软链接 + 隐藏规则） ====================
        # 后续所有文件系统操作都基于这个已校验过的真实路径进行，
        # 避免 "校验一个路径、实际访问另一个路径" 的漏洞。
        real_physical_path = resolve_safe_path(decoded_url_path)
        if real_physical_path is None:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Access denied.")
            return

        try:
            if os.path.isdir(real_physical_path):
                self.serve_directory_listing(real_physical_path, decoded_url_path)
            elif os.path.isfile(real_physical_path):
                self.serve_file(real_physical_path)
            elif os.path.exists(real_physical_path):
                self.send_error(http.HTTPStatus.NOT_FOUND, "Resource type not supported.")
            else:
                self.send_error(http.HTTPStatus.NOT_FOUND, "Resource not found.")
        except CONNECTION_ERRORS:
            return
        except PermissionError:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied.")
        except Exception as e:
            print(f"Unexpected error processing path {real_physical_path}: {e}", file=sys.stderr)
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")

    def serve_directory_listing(self, physical_path, display_url_path):
        try:
            items = os.listdir(physical_path)
            # 隐藏 dotfile 以及 .pem 等被屏蔽的文件/目录
            filtered_items = [name for name in items if not is_hidden_name(name)]
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
                # 不再使用 urljoin（它对特殊字符的处理容易出意外），直接拼接已 quote 的片段
                current_url_accumulator += quoted_segment_for_url + '/'
                if i < len(segments) - 1:
                    header_components.append(
                        f'<a href="{html.escape(current_url_accumulator, quote=True)}">{escaped_segment}</a>'
                    )
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
            r.append('<tr class="parent-dir" data-name="../" data-size="-2" data-date="-2">')
            r.append(f'<td><a href="{html.escape(quoted_parent_url_path, quote=True)}">../</a></td>')
            r.append('<td>-</td>')
            r.append('<td>-</td>')
            r.append('</tr>')

        # 先把当前目录的 URL 前缀整体 quote 一次。
        # （原来的写法把未 quote 的 display_url_path 交给 urljoin，目录名里若含有
        #  双引号等字符，会被原样带进 href 属性，造成属性注入 / XSS。）
        base_url_quoted = urllib.parse.quote(
            display_url_path.rstrip('/') + '/', errors='surrogateescape'
        )

        for name in filtered_items:
            item_physical_path = os.path.join(physical_path, name)
            item_real_path = os.path.realpath(item_physical_path)

            # 兜底防护（TOCTOU / 软链接）：真实路径必须在受信任根目录内，
            # 且软链接指向的最终文件名也不能是被隐藏的名字（例如 link -> key.pem）。
            if not is_within_allowed_roots(item_real_path):
                continue
            if is_hidden_name(os.path.basename(item_real_path)):
                continue

            quoted_item_name = urllib.parse.quote(name, errors='surrogateescape')
            item_url_path = base_url_quoted + quoted_item_name

            displayname = html.escape(name)
            is_dir = os.path.isdir(item_real_path)
            if is_dir:
                displayname += "/"
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
            r.append(f'<td><a href="{html.escape(item_url_path, quote=True)}">{displayname}</a></td>')
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
            if not isinstance(domain_info, dict):
                domain_info = None

        r.append('<p class="footer-info">')
        r.append('  <span class="footer-left">')

        if domain_info and (domain_info.get("icp_text", "") or domain_info.get("mps_text", "")):
            icp_text_val = domain_info.get("icp_text", "")
            icp_url_val = domain_info.get("icp_url", "#")
            mps_text_val = domain_info.get("mps_text", "")
            mps_url_val = domain_info.get("mps_url", "#")

            if icp_text_val:
                r.append(f'    <a href="{html.escape(icp_url_val)}" rel="noopener noreferrer" target="_blank">{html.escape(icp_text_val)}</a>')

            if icp_text_val and mps_text_val:
                r.append('    &nbsp;&nbsp;')

            if mps_text_val:
                r.append('    <img src="https://beian.mps.gov.cn/img/logo01.dd7ff50e.png" alt="公安网备图标" class="beian-icon">')
                r.append(f'    <a href="{html.escape(mps_url_val)}" rel="noopener noreferrer" target="_blank">{html.escape(mps_text_val)}</a>')

        r.append('  </span>')
        r.append('  <span class="footer-right">')
        r.append('    Page is auto-generated with <a href="https://www.python.org/" rel="noopener noreferrer" target="_blank">Python</a>')
        r.append('  </span>')
        r.append('</p>')

        current_year = datetime.datetime.now().year
        r.append(f'<p class="footer">Copyright &copy; {current_year} {html.escape(display_domain)} All Rights Reserved.</p>')
        r.append('<script src="/style/sort.js"></script>')

        r.append('</div>')
        r.append('</body></html>')

        # errors='replace'：文件名/路径里如果有非 UTF-8 字节（surrogateescape 产生的代理字符），
        # 原来的 .encode('utf-8') 会抛 UnicodeEncodeError，导致整个目录 500。
        encoded_html = '\n'.join(r).encode('utf-8', errors='replace')

        self.send_response(http.HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_html)))
        self._send_common_security_headers()
        self.send_header("Content-Security-Policy", LISTING_CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(encoded_html)

    def serve_file(self, physical_path):
        headers_sent = False
        try:
            mimetype, _ = mimetypes.guess_type(physical_path)
            if mimetype is None:
                mimetype = 'application/octet-stream'
            # 就地清除 CR/LF/冒号，防止 HTTP Response Splitting
            safe_mimetype = mimetype.replace('\r', '').replace('\n', '').replace(':', '')

            # 先打开、再 fstat，避免检查与使用之间文件被替换
            with open(physical_path, 'rb') as f:
                fs = os.fstat(f.fileno())
                if not stat.S_ISREG(fs.st_mode):
                    self.send_error(http.HTTPStatus.NOT_FOUND, "Resource type not supported.")
                    return

                self.send_response(http.HTTPStatus.OK)
                headers_sent = True
                self.send_header("Content-type", safe_mimetype)
                self.send_header("Content-Length", str(fs.st_size))
                self._send_common_security_headers()
                # 用户目录里的 .html / .svg / .xml 等文件与列表页同源，
                # 直接打开会执行其中的脚本（存储型 XSS）。
                # CSP sandbox 会让这些文档以“唯一源 + 禁止脚本”的方式渲染，
                # 对 RSS/XML、图片、下载等正常用途没有影响。
                self.send_header("Content-Security-Policy", "sandbox")
                self.end_headers()
                shutil.copyfileobj(f, self.wfile)

        except CONNECTION_ERRORS:
            return  # 客户端中途断开
        except FileNotFoundError:
            if not headers_sent:
                self.send_error(http.HTTPStatus.NOT_FOUND, "File not found or inaccessible.")
        except PermissionError:
            if not headers_sent:
                self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied to read file.")
        except Exception as e:
            print(f"Error serving file {physical_path}: {e}", file=sys.stderr)
            # 响应头已发出后再 send_error 会把错误页拼进文件内容，所以只在未发送时才发
            if not headers_sent:
                self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")


class ThreadedTCPServer(ThreadingMixIn, socketserver.TCPServer):
    # 线程随主进程退出，避免关闭时被慢连接卡住
    daemon_threads = True


if __name__ == "__main__":
    print("Feeds directory lister script is starting...")
    sys.stdout.flush()
    print(f"Running with Python version: {sys.version}")
    sys.stdout.flush()

    if not os.path.isdir(FILE_SERVER_ROOT):
        print(f"Error: Feeds root directory not found or not accessible: {FILE_SERVER_ROOT}", file=sys.stderr)
        sys.stdout.flush()
        sys.exit(1)

    # 确保静态文件目录也存在，否则静态文件无法被服务
    if not os.path.isdir(STATIC_ASSETS_DIR):
        print(f"Warning: Static assets directory not found or not accessible: {STATIC_ASSETS_DIR}", file=sys.stderr)
        sys.stdout.flush()

    print(f"Attempting to start server on port {LISTEN_PORT}")
    sys.stdout.flush()
    print(f"Serving content from file root: {FILE_SERVER_ROOT}")
    sys.stdout.flush()
    print(f"Allowed real roots (symlink targets included): {ALLOWED_REAL_ROOTS}")
    sys.stdout.flush()
    print(f"Hidden suffixes (also blocked on direct access): {list(HIDDEN_SUFFIXES)}; dotfiles are always hidden")
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
