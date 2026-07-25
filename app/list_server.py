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


def sanitize_header_value(value):
    if value is None:
        return value
    return value.replace('\r', '').replace('\n', '').replace(':', '')


def resolve_safe_path(requested_url_path_normalized):
    try:
        candidate = os.path.normpath(
            os.path.join(ABS_FILE_SERVER_ROOT, requested_url_path_normalized.lstrip('/'))
        )
    except Exception:
        return None

    try:
        if os.path.commonpath([ABS_FILE_SERVER_ROOT, candidate]) != ABS_FILE_SERVER_ROOT:
            return None
    except ValueError:
        return None

    real_candidate = os.path.realpath(candidate)
    for allowed_root in ALLOWED_REAL_ROOTS:
        try:
            if os.path.commonpath([allowed_root, real_candidate]) == allowed_root:
                return real_candidate
        except ValueError:
            continue

    return None


class CustomListingAndFileHandler(http.server.BaseHTTPRequestHandler):
    def _serve_static_file(self, requested_url_path):
        try:
            if requested_url_path.startswith('/style/'):
                sub_path = requested_url_path[len('/style/'):]
            else:
                self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Unexpected static path request.")
                return

            decoded_sub_path = urllib.parse.unquote(sub_path, errors='surrogateescape')
            normalized_sub_path = os.path.normpath(decoded_sub_path)
            if os.path.isabs(normalized_sub_path):
                self.send_error(http.HTTPStatus.BAD_REQUEST, "Absolute paths are not allowed.")
                return

            candidate_path = os.path.join(STATIC_ASSETS_DIR, normalized_sub_path)
            abs_static_realroot = os.path.realpath(os.path.abspath(STATIC_ASSETS_DIR))
            abs_file_realpath = os.path.realpath(os.path.abspath(candidate_path))

            # Only allow access if the resolved file path is strictly under the static assets root.
            if os.path.commonpath([abs_static_realroot, abs_file_realpath]) != abs_static_realroot:
                self.send_error(http.HTTPStatus.FORBIDDEN, "Access to requested path outside static assets directory is forbidden.")
                return

            if not os.path.isfile(abs_file_realpath):
                self.send_error(http.HTTPStatus.NOT_FOUND, "Static file not found.")
                return
            if os.path.islink(abs_file_realpath):
                self.send_error(http.HTTPStatus.FORBIDDEN, "Symlinks are not allowed for static assets.")
                return

            mimetype, _ = mimetypes.guess_type(abs_file_realpath)
            if mimetype is None:
                mimetype = 'application/octet-stream'
            # Sanitize mimetype to remove CR, LF, colon to prevent HTTP response splitting
            safe_mimetype = sanitize_header_value(mimetype)
            self.send_response(http.HTTPStatus.OK)
            self.send_header("Content-type", safe_mimetype)
            self.send_header("Content-Length", str(os.path.getsize(abs_file_realpath)))
            self.send_header('Cache-Control', 'public, max-age=31536000')
            self.end_headers()

            with open(abs_file_realpath, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
            return

        except FileNotFoundError:
            self.send_error(http.HTTPStatus.NOT_FOUND, "Static file not found.")
        except PermissionError:
            self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied to read static file.")
        except Exception as e:
            print(f"Error serving static file {requested_url_path}: {e}", file=sys.stderr)
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error serving static file.")


    def do_GET(self):
        if self.path.startswith('/style/'):
            self._serve_static_file(self.path)
            return

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
            item_physical_path = os.path.join(physical_path, name)

            base_url_for_join = display_url_path if display_url_path.endswith('/') else display_url_path + '/'
            quoted_item_name = urllib.parse.quote(name, errors='surrogateescape')
            item_url_path = urllib.parse.urljoin(base_url_for_join, quoted_item_name)

            displayname = html.escape(name)
            is_dir = os.path.isdir(item_physical_path)
            if is_dir:
                displayname += "/"
                if not item_url_path.endswith('/'):
                    item_url_path += '/'

            stats = None
            try:
                stats = os.stat(item_physical_path)
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
            safe_mimetype = sanitize_header_value(mimetype)

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

    if not os.path.isdir(STATIC_ASSETS_DIR):
        print(f"Warning: Static assets directory not found or not accessible: {STATIC_ASSETS_DIR}", file=sys.stderr)
        sys.stdout.flush()

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
