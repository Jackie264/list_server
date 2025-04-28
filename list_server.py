#!/usr/bin/env python3

import http.server
import socketserver
import os
import urllib.parse
import html
import sys
import mimetypes
import datetime
import time
from socketserver import ThreadingMixIn
import shutil

LISTEN_PORT = 8001
FILE_SERVER_ROOT = "/home/ubuntu/Downloads/firmware"
CSS_URL = "/style/main.css"

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

class CustomListingAndFileHandler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		parsed_url = urllib.parse.urlparse(self.path)
		url_path = parsed_url.path
		try:
			decoded_url_path = urllib.parse.unquote(url_path, errors='surrogateescape')
			decoded_url_path = os.path.normpath(decoded_url_path)
		except Exception:
			self.send_error(http.HTTPStatus.BAD_REQUEST, "Bad path.")
			return

		try:
			abs_root = os.path.abspath(FILE_SERVER_ROOT)
			physical_path = os.path.normpath(os.path.join(abs_root, decoded_url_path.lstrip('/')))
		except Exception:
			self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Error processing path.")
			return

		if not os.path.commonpath([abs_root, physical_path]) == abs_root:
			self.send_error(http.HTTPStatus.FORBIDDEN, "Access denied.")
			return

		try:
			if os.path.isdir(physical_path):
				self.serve_directory_listing(physical_path, decoded_url_path)
			elif os.path.isfile(physical_path):
				self.serve_file(physical_path)
			elif os.path.exists(physical_path):
				self.send_error(http.HTTPStatus.NOT_FOUND, "Resource type not supported.")
			else:
				self.send_error(http.HTTPStatus.NOT_FOUND, "Resource not found.")
		except PermissionError:
			self.send_error(http.HTTPStatus.FORBIDDEN, "Permission denied.")
		except Exception as e:
			print(f"Unexpected error processing path {physical_path}: {e}", file=sys.stderr)
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
		r.append('<html><head>')
		r.append('<meta charset="utf-8">')
		r.append(f'<title>Index of {html.escape(display_url_path)}</title>')
		r.append(f'<link rel="stylesheet" href="{html.escape(CSS_URL)}">')
		r.append('</head><body>')
		r.append('<div class="container">')

		header_components = ['<h1>Index of ']
		header_components.append('<a href="/">Home</a>')

		if display_url_path != '/':
			segments = display_url_path.strip('/').split('/')
			current_url_accumulator = '/'
			for i, segment in enumerate(segments):
				separator = ' ' if i == 0 else ' / '
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
		if host_header:
			hostname = host_header.split(':')[0]
			parts = hostname.split('.')
			if len(parts) > 2:
				main_domain = '.'.join(parts[-2:])
			else:
				main_domain = hostname
			display_domain = main_domain

		r.append('<p class="footer-info">Page content is automatically generated with <a href="https://www.python.org/">Python</a>.</p>')

		current_year = datetime.datetime.now().year
		r.append(f'<p class="footer">Copyright &copy; {current_year} {html.escape(display_domain)}</p>')
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

			file_size = os.path.getsize(physical_path)

			self.send_response(http.HTTPStatus.OK)
			self.send_header("Content-type", mimetype)
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
			self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, "Error reading file.")

class ThreadedTCPServer(ThreadingMixIn, socketserver.TCPServer):
	pass

if __name__ == "__main__":
	if not os.path.isdir(FILE_SERVER_ROOT):
		print(f"Error: Feeds root directory not found or not accessible: {FILE_SERVER_ROOT}", file=sys.stderr)
		sys.exit(1)

	server_address = ('', LISTEN_PORT)
	try:
		with ThreadedTCPServer(server_address, CustomListingAndFileHandler) as httpd:
			print(f"Starting custom listing and file server on port {LISTEN_PORT}")
			print(f"Serving content from: {FILE_SERVER_ROOT}")
			httpd.serve_forever()
	except PermissionError:
		print(f"Error: Permission denied to bind on port {LISTEN_PORT}. Try running with sudo or a higher port.", file=sys.stderr)
		sys.exit(1)
	except Exception as e:
		print(f"An error occurred: {e}", file=sys.stderr)
		sys.exit(1)
