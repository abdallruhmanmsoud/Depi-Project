# Forensics Dashboard

A modular, web-based dashboard for **digital forensics**, **malware analysis**, and **incident response** on Linux. Built with Flask and Flask-SocketIO for real-time log streaming.

---

## Features

| Feature | Description |
|---|---|
| **Modular tool system** | Each analysis tool is a self-contained Python module in `tools/`. |
| **Live output streaming** | WebSocket-powered real-time command output in the browser. |
| **File upload & validation** | Upload files via the web UI; magic-byte and extension validation. |
| **Prerequisite checking** | Dashboard shows whether each tool's system dependencies are installed. |
| **Auto-reporting** | Analysis results are automatically saved as timestamped text reports. |
| **Extensible** | Add new tools by dropping a single Python file into `tools/`. |

---

## Quick Start

```bash
# 1. Clone / copy the project
cd forensics-dashboard

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Run the dashboard
python app.py
```

Open **http://localhost:5000** in your browser.

---

## Project Structure

```
forensics-dashboard/
├── app.py                  # Flask application entry point
├── config.py               # Central configuration
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── tools/                  # Analysis tool modules (plugins)
│   ├── base.py             # BaseTool abstract class
│   ├── strings_tool.py     # Strings extraction module
│   ├── yara_tool.py        # YARA scanning module
│   └── volatility_tool.py  # Volatility 3 module
├── utils/                  # Core utilities
│   ├── loader.py           # Dynamic plugin discovery
│   ├── validator.py        # Upload file validation
│   └── reporter.py         # Report generation
├── templates/              # Jinja2 HTML templates
│   ├── base.html
│   ├── index.html
│   ├── tool.html
│   └── session.html
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── uploads/                # Uploaded files (auto-created)
├── reports/                # Saved reports (auto-created)
└── yara_rules/             # YARA rule files (.yar / .yara)
    └── sample.yar
```

---

## Admin Guide: Adding a New Tool

### 1. Create a new Python file in `tools/`

```python
# tools/my_tool.py

from tools.base import BaseTool, StepResult
from typing import Callable

class MyTool(BaseTool):
    tool_id = "mytool"                          # unique slug
    name = "My Custom Tool"                     # display name
    description = "What this tool does."        # shown on dashboard
    accepted_extensions = [".bin", ".exe"]       # empty list = any file
    system_prerequisites = ["mytool-binary"]     # commands that must exist on PATH

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit:
            emit("[Step 1/2] Doing something ...")
        step = self._exec(f"mytool-binary --analyze '{filepath}'", emit)
        results.append(step)

        if emit:
            emit("[Step 2/2] Post-processing ...")
        step = self._exec(f"grep 'pattern' '{filepath}'", emit)
        results.append(step)

        if emit:
            emit("Analysis complete.")
        return results
```

### 2. Restart the dashboard

```bash
python app.py
```

The new tool will be automatically discovered and shown on the dashboard. No changes to `app.py` or any other file are needed.

### 3. Key points

- **`tool_id`** must be unique across all tools.
- **`accepted_extensions`** controls which files the tool accepts. Use an empty list `[]` to accept any file.
- **`system_prerequisites`** lists command-line programs the tool needs. The dashboard checks these on startup and shows their status.
- Use **`self._exec(command, emit)`** to run shell commands. It handles streaming output to the browser and capturing results.
- The **`emit`** callback streams lines to the browser in real time via WebSocket. Always check `if emit:` before calling it.

---

## Configuration

Edit `config.py` to customize:

| Setting | Default | Description |
|---|---|---|
| `UPLOAD_FOLDER` | `./uploads` | Where uploaded files are stored |
| `REPORT_FOLDER` | `./reports` | Where reports are saved |
| `TOOLS_FOLDER` | `./tools` | Directory scanned for tool plugins |
| `MAX_CONTENT_LENGTH` | 512 MB | Maximum upload file size |
| `SECRET_KEY` | `change-me-in-production` | Flask session secret |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## YARA Rules

Place `.yar` or `.yara` rule files in the `yara_rules/` directory. The YARA tool module will scan uploaded files against all rules found there.

A sample rule (`sample.yar`) is included to detect common suspicious strings and PE executables.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard home page |
| `GET` | `/tool/<tool_id>` | Tool-specific upload & analysis page |
| `POST` | `/upload/<tool_id>` | Upload a file (multipart form, field: `file`) |
| `GET` | `/session/<session_id>` | View session logs |
| `GET` | `/report/<session_id>` | Download session report |
| `GET` | `/api/tools` | JSON: list all tools and prerequisite status |
| `GET` | `/api/sessions` | JSON: list all analysis sessions |

---

## WebSocket Events

| Event | Direction | Payload | Description |
|---|---|---|---|
| `run_analysis` | Client → Server | `{session_id}` | Start analysis |
| `log` | Server → Client | `{line, done}` | Live log line |
| `save_report` | Client → Server | `{session_id}` | Trigger report save |
| `report_saved` | Server → Client | `{path, name}` | Report saved confirmation |

---

## System Requirements

- **Python 3.10+**
- **Linux** (tested on Ubuntu/Debian)
- Optional system tools (depending on which modules you use):
  - `strings` (part of GNU binutils)
  - `file` (file type identification)
  - `yara` (YARA pattern matching)
  - `vol` (Volatility 3 memory forensics framework)

---

## License

This project is provided as-is for educational and professional forensics use.
