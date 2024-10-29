# Apache Log Report Generator

This Python script generates a detailed, multi-format report from Apache HTTP server log files. Designed to provide insights into server activity, it processes access and error logs from a specified directory and produces an HTML and PDF report with key statistics, charts, and monthly breakdowns. 

## Features

- **Flexible Directory Selection**: Choose the directory of log files, with `/var/log/httpd/` as the default.
- **Comprehensive Access Log Parsing**: Extracts IP addresses, URLs, methods, status codes, and user agents from access logs.
- **Error Log Analysis**: Identifies error levels and frequencies to understand server issues.
- **Detailed Summary Statistics**: Calculates total requests, unique visitors, top URLs, and user agents.
- **Chart Generation**:
  - Request frequency over time
  - HTTP status distribution
  - Top requested URLs
  - Frequent IP addresses
  - Error levels and messages
- **Monthly Reports**: Generates individual HTML and PDF reports for each month with detailed logs and charts.
- **HTML and PDF Output**: Creates a visually appealing HTML report with linked monthly summaries and a complete PDF report.

## Requirements

- Python 3.x
- `matplotlib` for chart generation
- `weasyprint` for PDF generation
- Apache log files located in the default directory or custom path

## Usage

1. Clone this repository.
2. Install the required packages:
   ```bash
   pip install matplotlib weasyprint
