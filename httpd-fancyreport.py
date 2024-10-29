import os
import re
import gzip
import glob
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from collections import Counter
from weasyprint import HTML

# Function to prompt for the log directory
def prompt_for_log_directory():
    dir_path = input("Ingrese la ruta al directorio que contiene los archivos de registro de Apache (por defecto: /var/log/httpd/): ")
    if not dir_path:
        dir_path = '/var/log/httpd/'
    if not os.path.exists(dir_path):
        print("Directorio no encontrado. Por favor, verifique la ruta e intente de nuevo.")
        exit(1)
    return dir_path

# Create a folder with current timestamp
def create_output_folder():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder_name = f"reporte_apache_logs-{timestamp}"
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

# Function to parse access logs
def parse_access_logs(dir_path):
    access_logs = glob.glob(os.path.join(dir_path, 'access_log*'))
    if not access_logs:
        print("No se encontraron archivos access_log en el directorio especificado.")
        exit(1)
    access_logs.sort()
    access_data = []
    for file_path in access_logs:
        print(f"Procesando {file_path}...")
        data = parse_single_access_log(file_path)
        print(f"Encontradas {len(data)} entradas en {file_path}")
        access_data.extend(data)
    return access_data

# Function to parse a single access log file
def parse_single_access_log(file_path):
    data = []
    # Handle compressed files
    if file_path.endswith('.gz'):
        f = gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')
    else:
        f = open(file_path, 'r', encoding='utf-8', errors='ignore')
    try:
        for line in f:
            parsed_line = parse_access_log_line(line)
            if parsed_line:
                data.append(parsed_line)
    finally:
        f.close()
    return data

# Function to parse a single line of access log
def parse_access_log_line(line):
    # Combined Log Format regex matching your sample
    regex = r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (.*?) (\S+)" (\d{3}) (\S+) "(.*?)" "(.*?)"$'
    match = re.match(regex, line)
    if match:
        ip, ident, authuser, date_str, method, request, protocol, status, bytes_sent, referer, user_agent = match.groups()
        # Handle timezone offset
        try:
            timestamp = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            # If timezone offset is not included
            try:
                timestamp = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S')
            except ValueError:
                return None
        status = int(status)
        bytes_sent = int(bytes_sent) if bytes_sent != '-' else 0
        return {
            'ip': ip,
            'ident': ident,
            'authuser': authuser,
            'timestamp': timestamp,
            'method': method,
            'request': request,
            'protocol': protocol,
            'status': status,
            'bytes_sent': bytes_sent,
            'referer': referer if referer else '-',
            'user_agent': user_agent if user_agent else '-',
            'month': timestamp.strftime('%Y-%m')
        }
    else:
        return None

# Function to parse error logs
def parse_error_logs(dir_path):
    error_logs = glob.glob(os.path.join(dir_path, 'error_log*'))
    if not error_logs:
        print("No se encontraron archivos error_log en el directorio especificado.")
        exit(1)
    error_logs.sort()
    error_data = []
    for file_path in error_logs:
        print(f"Procesando {file_path}...")
        data = parse_single_error_log(file_path)
        print(f"Encontradas {len(data)} entradas en {file_path}")
        error_data.extend(data)
    return error_data

# Function to parse a single error log file
def parse_single_error_log(file_path):
    data = []
    # Handle compressed files
    if file_path.endswith('.gz'):
        f = gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')
    else:
        f = open(file_path, 'r', encoding='utf-8', errors='ignore')
    try:
        for line in f:
            parsed_line = parse_error_log_line(line)
            if parsed_line:
                data.append(parsed_line)
    finally:
        f.close()
    return data

# Function to parse a single line of error log
def parse_error_log_line(line):
    # Error Log Format matching your sample
    regex = r'^\[(.*?)\] \[(\w+)\] (.*)$'
    match = re.match(regex, line)
    if match:
        date_str, level, message = match.groups()
        try:
            timestamp = datetime.strptime(date_str, '%a %b %d %H:%M:%S %Y')
        except ValueError:
            return None
        return {
            'timestamp': timestamp,
            'level': level,
            'message': message.strip(),
            'month': timestamp.strftime('%Y-%m')
        }
    else:
        return None

# Generate summary statistics for access logs
def generate_access_summary(access_data):
    summary = {}
    total_requests = len(access_data)
    summary['total_requests'] = total_requests

    # Unique visitors
    unique_ips = set(entry['ip'] for entry in access_data)
    summary['unique_visitors'] = len(unique_ips)

    # Top requested URLs
    url_counter = Counter(entry['request'] for entry in access_data)
    summary['top_urls'] = url_counter.most_common(10)

    # Status code distribution
    status_counter = Counter(entry['status'] for entry in access_data)
    summary['status_distribution'] = status_counter

    # Top user agents
    user_agent_counter = Counter(entry['user_agent'] for entry in access_data)
    summary['top_user_agents'] = user_agent_counter.most_common(5)

    # Top IP addresses
    ip_counter = Counter(entry['ip'] for entry in access_data)
    summary['top_ips'] = ip_counter.most_common(5)

    return summary

# Generate summary statistics for error logs
def generate_error_summary(error_data):
    summary = {}
    total_errors = len(error_data)
    summary['total_errors'] = total_errors

    # Error levels
    level_counter = Counter(entry['level'] for entry in error_data)
    summary['level_distribution'] = level_counter

    # Top error messages
    message_counter = Counter(entry['message'] for entry in error_data)
    summary['top_error_messages'] = message_counter.most_common(5)

    return summary

# Generate charts for access logs
def generate_access_charts(access_data, output_folder):
    chart_paths = {}

    # Requests over time
    timestamps = [entry['timestamp'] for entry in access_data]
    if not timestamps:
        return chart_paths
    timestamps.sort()
    first_date = timestamps[0].date()
    last_date = timestamps[-1].date()
    date_range = (last_date - first_date).days + 1
    date_counts = Counter(ts.date() for ts in timestamps)
    dates = [first_date + timedelta(days=i) for i in range(date_range)]
    counts = [date_counts.get(date, 0) for date in dates]

    plt.figure(figsize=(14, 6))
    plt.plot(dates, counts, marker='o', linestyle='-', color='blue')
    plt.xlabel('Fecha')
    plt.ylabel('Número de Peticiones')
    plt.title('Peticiones HTTP en el Tiempo')
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    timeline_chart_path = os.path.join(output_folder, 'access_timeline.png')
    plt.savefig(timeline_chart_path)
    plt.close()
    chart_paths['Peticiones HTTP en el Tiempo'] = timeline_chart_path

    # Status code distribution pie chart
    status_counter = Counter(entry['status'] for entry in access_data)
    labels = [str(status) for status in status_counter.keys()]
    sizes = status_counter.values()
    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title('Distribución de Códigos de Estado HTTP')
    plt.axis('equal')
    status_pie_chart_path = os.path.join(output_folder, 'status_pie_chart.png')
    plt.savefig(status_pie_chart_path)
    plt.close()
    chart_paths['Distribución de Códigos de Estado HTTP'] = status_pie_chart_path

    # Top requested URLs bar chart
    url_counter = Counter(entry['request'] for entry in access_data)
    top_urls = url_counter.most_common(10)
    if top_urls:
        urls = [url for url, count in top_urls]
        counts = [count for url, count in top_urls]
        plt.figure(figsize=(12, 6))
        plt.barh(urls[::-1], counts[::-1], color='green')
        plt.xlabel('Frecuencia')
        plt.ylabel('URL Solicitada')
        plt.title('Top 10 URLs Más Solicitadas')
        plt.tight_layout()
        urls_chart_path = os.path.join(output_folder, 'top_urls_chart.png')
        plt.savefig(urls_chart_path)
        plt.close()
        chart_paths['Top 10 URLs Más Solicitadas'] = urls_chart_path

    # Top IP addresses bar chart
    ip_counter = Counter(entry['ip'] for entry in access_data)
    top_ips = ip_counter.most_common(10)
    if top_ips:
        ips = [ip for ip, count in top_ips]
        counts = [count for ip, count in top_ips]
        plt.figure(figsize=(12, 6))
        plt.barh(ips[::-1], counts[::-1], color='orange')
        plt.xlabel('Frecuencia')
        plt.ylabel('Dirección IP')
        plt.title('Top 10 Direcciones IP')
        plt.tight_layout()
        ips_chart_path = os.path.join(output_folder, 'top_ips_chart.png')
        plt.savefig(ips_chart_path)
        plt.close()
        chart_paths['Top 10 Direcciones IP'] = ips_chart_path

    return chart_paths

# Generate charts for error logs
def generate_error_charts(error_data, output_folder):
    chart_paths = {}

    # Error levels bar chart
    level_counter = Counter(entry['level'] for entry in error_data)
    if level_counter:
        levels = list(level_counter.keys())
        counts = list(level_counter.values())
        plt.figure(figsize=(8, 6))
        plt.bar(levels, counts, color='red')
        plt.xlabel('Nivel de Error')
        plt.ylabel('Cantidad')
        plt.title('Distribución de Niveles de Error')
        plt.tight_layout()
        levels_chart_path = os.path.join(output_folder, 'error_levels_chart.png')
        plt.savefig(levels_chart_path)
        plt.close()
        chart_paths['Distribución de Niveles de Error'] = levels_chart_path

    return chart_paths

# Generate the index HTML report
def generate_index_html(access_summary, error_summary, chart_paths, output_folder, months):
    # Common CSS styles for both web and PDF versions
    common_css = """
    body { font-family: Arial, sans-serif; margin: 20px; }
    .chart { margin-bottom: 50px; }
    .summary { margin-bottom: 50px; }
    .summary h2 { margin-top: 0; }
    ul { list-style-type: none; padding: 0; }
    li { margin: 5px 0; }
    a { text-decoration: none; color: #1a0dab; }
    a:hover { text-decoration: underline; }
    img { max-width: 100%; height: auto; }
    """

    # Additional CSS for PDF version
    pdf_css = """
    @page {
        size: A4;
        margin: 20mm;
    }
    h1, h2, h3, h4, h5, h6 {
        page-break-after: avoid;
    }
    table, pre, img {
        page-break-inside: avoid;
    }
    """

    # HTML content for the index page
    html_content = f"""
    <html>
    <head>
        <title>Reporte de Logs de Apache</title>
        <style>
            {common_css}
        </style>
    </head>
    <body>
        <h1>Reporte de Logs de Apache</h1>

        <div class="summary">
            <h2>Estadísticas de Acceso</h2>
            <p><strong>Total de Peticiones:</strong> {access_summary['total_requests']}</p>
            <p><strong>Visitantes Únicos:</strong> {access_summary['unique_visitors']}</p>
            <p><strong>URLs Más Solicitadas:</strong></p>
            <ul>
    """

    for url, count in access_summary['top_urls']:
        html_content += f"<li>{url}: {count} peticiones</li>\n"

    html_content += f"""
            </ul>
            <p><strong>Direcciones IP Más Frecuentes:</strong></p>
            <ul>
    """

    for ip, count in access_summary['top_ips']:
        html_content += f"<li>{ip}: {count} peticiones</li>\n"

    html_content += f"""
            </ul>
            <p><strong>Agentes de Usuario Más Comunes:</strong></p>
            <ul>
    """

    for agent, count in access_summary['top_user_agents']:
        html_content += f"<li>{agent}: {count} veces</li>\n"

    html_content += f"""
            </ul>
        </div>

        <div class="summary">
            <h2>Estadísticas de Errores</h2>
            <p><strong>Total de Errores:</strong> {error_summary['total_errors']}</p>
            <p><strong>Niveles de Error:</strong></p>
            <ul>
    """

    for level, count in error_summary['level_distribution'].items():
        html_content += f"<li>{level}: {count} errores</li>\n"

    html_content += f"""
            </ul>
            <p><strong>Mensajes de Error Más Comunes:</strong></p>
            <ul>
    """

    for message, count in error_summary['top_error_messages']:
        html_content += f"<li>{message}: {count} veces</li>\n"

    html_content += """
            </ul>
        </div>
    """

    # Add charts to the index page
    for chart_title, chart_filename in chart_paths.items():
        html_content += f"""
        <div class="chart">
            <h2>{chart_title}</h2>
            <img src="{os.path.basename(chart_filename)}" alt="{chart_title}">
        </div>
        """

    html_content += """
        <h2>Reportes Mensuales</h2>
        <ul>
    """

    for month in months:
        html_content += f'<li><a href="reporte_{month}.html">Reporte de {month}</a></li>\n'

    html_content += """
        </ul>
    </body>
    </html>
    """

    # Save the web version of the HTML file
    html_path = os.path.join(output_folder, 'index.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"Reporte HTML principal generado en {html_path}")

    # Prepare HTML for PDF conversion (add PDF-specific CSS)
    html_content_for_pdf = f"""
    <html>
    <head>
        <title>Reporte de Logs de Apache</title>
        <style>
            {common_css}
            {pdf_css}
        </style>
    </head>
    <body>
    """ + html_content.split('<body>')[1]

    # Save the PDF version of the HTML file
    html_pdf_path = os.path.join(output_folder, 'index_pdf.html')
    with open(html_pdf_path, 'w', encoding='utf-8') as f:
        f.write(html_content_for_pdf)

    return html_pdf_path  # Ensure html_pdf_path is defined before returning

# Generate monthly reports
def generate_monthly_reports(access_data, error_data, output_folder):
    months = sorted(set(entry['month'] for entry in access_data + error_data))
    for month in months:
        # Filter data for the month
        access_entries = [entry for entry in access_data if entry['month'] == month]
        error_entries = [entry for entry in error_data if entry['month'] == month]

        # Generate charts for the month
        chart_paths = generate_monthly_charts(access_entries, error_entries, output_folder, month)

        # Common CSS styles
        common_css = """
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 50px; table-layout: fixed; word-wrap: break-word; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; }
        th { background-color: #f2f2f2; }
        img { max-width: 100%; height: auto; }
        .chart { margin-bottom: 50px; }
        .summary { margin-bottom: 50px; }
        .summary h2 { margin-top: 0; }
        """

        # Additional CSS for PDF version
        pdf_css = """
        @page {
            size: A4;
            margin: 20mm;
        }
        h1, h2, h3, h4, h5, h6 {
            page-break-after: avoid;
        }
        table, pre, img {
            page-break-inside: avoid;
        }
        """

        html_content = f"""
        <html>
        <head>
            <title>Reporte de {month}</title>
            <style>
                {common_css}
            </style>
        </head>
        <body>
            <h1>Reporte de {month}</h1>
        """

        # Include charts
        for chart_title, chart_filename in chart_paths.items():
            html_content += f"""
            <div class="chart">
                <h2>{chart_title}</h2>
                <img src="{os.path.basename(chart_filename)}" alt="{chart_title}">
            </div>
            """

        # Access log details
        html_content += """
            <h2>Detalles de Acceso</h2>
            <table>
                <thead>
                    <tr>
                        <th>Fecha y Hora</th>
                        <th>IP</th>
                        <th>Método</th>
                        <th>Recurso</th>
                        <th>Código de Estado</th>
                        <th>Agente de Usuario</th>
                    </tr>
                </thead>
                <tbody>
        """

        for entry in access_entries:
            html_content += f"""
                <tr>
                    <td>{entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{entry['ip']}</td>
                    <td>{entry['method']}</td>
                    <td>{entry['request']}</td>
                    <td>{entry['status']}</td>
                    <td>{entry['user_agent']}</td>
                </tr>
            """

        html_content += """
                </tbody>
            </table>
        """

        # Error log details
        html_content += """
            <h2>Detalles de Errores</h2>
            <table>
                <thead>
                    <tr>
                        <th>Fecha y Hora</th>
                        <th>Nivel</th>
                        <th>Mensaje</th>
                    </tr>
                </thead>
                <tbody>
        """

        for entry in error_entries:
            html_content += f"""
                <tr>
                    <td>{entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{entry['level']}</td>
                    <td>{entry['message']}</td>
                </tr>
            """

        html_content += """
                </tbody>
            </table>
            <p><a href="index.html">Volver al índice</a></p>
        </body>
        </html>
        """

        # Save the web version of the monthly report
        html_path = os.path.join(output_folder, f'reporte_{month}.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        # Prepare HTML for PDF conversion
        html_content_for_pdf = f"""
        <html>
        <head>
            <title>Reporte de {month}</title>
            <style>
                {common_css}
                {pdf_css}
            </style>
        </head>
        """ + html_content.split('<body>')[1]

        # Save the PDF version of the monthly report
        html_pdf_path = os.path.join(output_folder, f'reporte_{month}_pdf.html')
        with open(html_pdf_path, 'w', encoding='utf-8') as f:
            f.write(html_content_for_pdf)

        # Generate PDF for the monthly report
        pdf_path = os.path.join(output_folder, f'reporte_{month}.pdf')
        HTML(html_pdf_path, base_url=output_folder).write_pdf(pdf_path)
        print(f"Reporte mensual PDF generado en {pdf_path}")

    return months  # Ensure months is defined before returning

# Generate monthly charts
def generate_monthly_charts(access_entries, error_entries, output_folder, month):
    chart_paths = {}

    # Top requested URLs in the month
    url_counter = Counter(entry['request'] for entry in access_entries)
    top_urls = url_counter.most_common(10)
    if top_urls:
        urls = [url for url, count in top_urls]
        counts = [count for url, count in top_urls]
        plt.figure(figsize=(12, 6))
        plt.barh(urls[::-1], counts[::-1], color='green')
        plt.xlabel('Frecuencia')
        plt.ylabel('URL Solicitada')
        plt.title(f'Top 10 URLs Más Solicitadas en {month}')
        plt.tight_layout()
        urls_chart_path = os.path.join(output_folder, f'top_urls_{month}.png')
        plt.savefig(urls_chart_path)
        plt.close()
        chart_paths[f'Top URLs en {month}'] = urls_chart_path

    # Error levels in the month
    level_counter = Counter(entry['level'] for entry in error_entries)
    if level_counter:
        levels = list(level_counter.keys())
        counts = list(level_counter.values())
        plt.figure(figsize=(8, 6))
        plt.bar(levels, counts, color='red')
        plt.xlabel('Nivel de Error')
        plt.ylabel('Cantidad')
        plt.title(f'Distribución de Niveles de Error en {month}')
        plt.tight_layout()
        levels_chart_path = os.path.join(output_folder, f'error_levels_{month}.png')
        plt.savefig(levels_chart_path)
        plt.close()
        chart_paths[f'Niveles de Error en {month}'] = levels_chart_path

    return chart_paths

# Generate PDF using WeasyPrint
def generate_pdf(html_pdf_path, output_folder):
    pdf_path = os.path.join(output_folder, 'reporte_completo.pdf')
    HTML(html_pdf_path, base_url=output_folder).write_pdf(pdf_path)
    print(f"Reporte PDF generado en {pdf_path}")

# Main function
def main():
    log_dir = prompt_for_log_directory()
    output_folder = create_output_folder()

    # Parse access logs
    access_data = parse_access_logs(log_dir)
    if not access_data:
        print("No se encontraron registros de acceso.")
        return

    # Parse error logs
    error_data = parse_error_logs(log_dir)
    if not error_data:
        print("No se encontraron registros de errores.")
        return

    # Generate summaries
    access_summary = generate_access_summary(access_data)
    error_summary = generate_error_summary(error_data)

    # Generate charts
    access_chart_paths = generate_access_charts(access_data, output_folder)
    error_chart_paths = generate_error_charts(error_data, output_folder)
    chart_paths = {**access_chart_paths, **error_chart_paths}

    # Generate monthly reports
    months = generate_monthly_reports(access_data, error_data, output_folder)

    # Generate index HTML
    html_pdf_path = generate_index_html(access_summary, error_summary, chart_paths, output_folder, months)

    # Generate PDF
    generate_pdf(html_pdf_path, output_folder)

if __name__ == '__main__':
    main()
