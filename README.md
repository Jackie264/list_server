# List Server

A lightweight Python-based file server that provides elegant directory listings with a responsive web interface. Perfect for serving and browsing files through a web browser with sorting capabilities and mobile-friendly design.

## Features

- **Clean Web Interface**: Modern, responsive design with sortable file listings
- **Security First**: Built-in protection against directory traversal attacks
- **Static Asset Support**: Serves CSS, JavaScript, and favicon files
- **Docker Ready**: Containerized deployment with health checks
- **Multi-domain Support**: Custom footer information for different domains
- **File Type Detection**: Automatic MIME type detection for proper file serving
- **Threaded Server**: Multi-threaded request handling for better performance

## Quick Start

### Using Docker (Recommended)

1. Pull and run the pre-built image:
```bash
docker run -d \
  --name feeds-lister \
  -p 8001:8001 \
  -v /path/to/your/data:/feeds_data \
  jackie264/feeds-lister:latest
```

2. Or use the provided [docker-compose.yml](docker-compose.yml):
```bash
# Edit the volume path in docker-compose.yml first
docker-compose up -d
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/Jackie264/list_server.git
cd list_server
```

2. Run the server:
```bash
python3 app/list_server.py
```

3. Access the web interface at `http://localhost:8001`

## Configuration

### Environment Variables

- `FILE_SERVER_ROOT`: Directory to serve files from (default: `/feeds_data`)
- `TZ`: Timezone for the container (default: `Asia/Shanghai`)

### Server Settings

The server configuration can be modified in [`app/list_server.py`](app/list_server.py):

- `LISTEN_PORT`: Server port (default: `8001`)
- `STATIC_ASSETS_DIR`: Static files directory (default: `/style`)
- `DOMAIN_FOOTER_INFO`: Custom footer information for specific domains

## File Structure

```
list_server/
├── app/
│   └── list_server.py          # Main server application
├── style/                      # Static assets
│   ├── main.css               # Stylesheet
│   ├── sort.js                # Table sorting functionality
│   ├── favicon.ico            # Favicon files
│   ├── favicon-16x16.png
│   ├── favicon-32x32.png
│   ├── apple-touch-icon.png
│   ├── android-chrome-*.png
│   └── site.webmanifest
├── .github/
│   └── workflows/
│       └── docker-build-push.yml  # CI/CD pipeline
├── Dockerfile                 # Container build instructions
├── docker-compose.yml         # Docker Compose configuration
└── LICENSE                    # MIT License
```

## Development

### Building the Docker Image

```bash
docker build -t list-server .
```

### Running in Development Mode

```bash
# Set custom file root
export FILE_SERVER_ROOT="/path/to/your/files"
python3 app/list_server.py
```

## Security Features

- **Path Validation**: Prevents directory traversal attacks using `os.path.commonpath()`
- **Input Sanitization**: Proper URL decoding and HTML escaping
- **File Type Restrictions**: Only serves regular files and directories
- **Permission Handling**: Graceful handling of permission errors

## Browser Support

The web interface is designed to work on:
- Modern desktop browsers (Chrome, Firefox, Safari, Edge)
- Mobile browsers with responsive design
- Supports sorting and touch interactions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Python's built-in `http.server` module
- Responsive design with modern CSS
- Automated builds via GitHub Actions