# SyslogStudio User Guide

## Overview

SyslogStudio is a lightweight, cross-platform desktop application for receiving and analyzing syslog messages in real time. It supports UDP, TCP, and TLS protocols (RFC 5424 and RFC 3164) and provides a visual interface for viewing, filtering, and exporting log data.

Key capabilities:

- Receive syslog messages over UDP, TCP, and TLS simultaneously
- Parse both RFC 5424 and RFC 3164 (BSD) syslog formats automatically
- Filter logs by severity, facility, hostname, application name, source IP, text search (with regex), and date range
- Export logs as CSV or plain text
- Monitor real-time statistics: message rates, severity distribution, top sources, buffer usage
- Generate and manage TLS certificates directly from the UI (PKI assistant)

## Getting Started

### Download and Install

**Pre-built binaries:** Download the latest release for your platform from the GitHub Releases page. The application is a single executable file:

- **Windows:** `SyslogStudio.exe`
- **macOS:** `SyslogStudio.app`

No installation is required. Place the executable wherever you like and run it.

**Build from source:** If you prefer to build from source, you need Go 1.23+, Node.js 18+, and the Wails CLI v2:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
cd frontend && npm install && cd ..
wails build
```

The binary is produced in `build/bin/`.

### First Launch

1. Run the application. A native window opens with the **Logs** view active.
2. By default, the UDP protocol is enabled on port 514.
3. Click **Start** to begin listening for syslog messages.
4. Point your syslog sources (routers, servers, applications) to the IP address of the machine running SyslogStudio on the configured port.

> **Note:** On Linux and macOS, listening on ports below 1024 (such as the standard syslog port 514) requires root/administrator privileges. You can either run the application with elevated privileges or change the port to a value above 1024 (e.g., 1514).

## Server Configuration

The **Server Controls** panel at the top of the application lets you configure which protocols to enable, their ports, and the buffer size.

### Enabling Protocols

Toggle each protocol independently:

| Protocol | Default Port | Description |
|----------|-------------|-------------|
| **UDP**  | 514         | Standard syslog transport. Connectionless, fast, no delivery guarantee. |
| **TCP**  | 514         | Connection-oriented syslog transport. Reliable delivery. |
| **TLS**  | 6514        | Encrypted syslog over TLS (RFC 5425). Requires a certificate. |

You can enable any combination of protocols. At least one must be enabled to start the server.

### Port Selection

Each protocol has its own port field. Enter a port number between 1 and 65535. Note the following:

- TCP and TLS cannot share the same port (both use TCP sockets internally).
- UDP can use the same port number as TCP or TLS since it operates on a different transport layer.
- Ports below 1024 may require elevated privileges on Linux/macOS.

### Buffer Size

The **Max Buffer** field controls how many messages are kept in memory. The default is 10,000. When the buffer is full, the oldest messages are discarded to make room for new ones (ring buffer).

Increase the buffer if you need to retain more history; decrease it to reduce memory usage.

### Starting and Stopping

- Click **Start** to begin listening. Active listeners appear as badges (e.g., `UDP:514`, `TCP:514`).
- Click **Stop** to shut down all listeners. Buffered messages are preserved until you clear them.

Your server configuration is automatically saved and restored the next time you launch the application.

## Viewing Logs

### The Log Viewer

The main panel displays incoming syslog messages in a table with the following columns:

- **Timestamp** -- when the message was generated (from the syslog header)
- **Severity** -- color-coded severity level (Emergency, Alert, Critical, Error, Warning, Notice, Info, Debug)
- **Facility** -- the syslog facility (kern, user, mail, daemon, auth, etc.)
- **Hostname** -- the hostname of the sending device
- **App Name** -- the application or process that generated the message
- **Message** -- the log message content
- **Source IP** -- the IP address the message was received from
- **Protocol** -- UDP, TCP, or TLS

### Selecting a Message

Click any row in the log viewer to open the **Log Detail** panel. This panel shows the full details of the selected message, including:

- All parsed fields (timestamp, severity, facility, hostname, app name, process ID, message ID)
- Structured data (if present in RFC 5424 messages)
- The raw, unparsed syslog message
- Source IP and protocol

Click the same row again or click elsewhere to deselect.

### Auto-Scroll

By default, the log viewer automatically scrolls to show the newest messages as they arrive. You can toggle auto-scroll on or off. When auto-scroll is off, you can freely scroll through the log history without being interrupted by new arrivals.

### Clearing Logs

Use the **Clear** function to empty the log buffer. This removes all messages from both the display and memory.

## Filtering

The **Filter Bar** provides several ways to narrow down the displayed messages. All filters are applied together (logical AND).

### Severity Filter

Select one or more severity levels to display only messages at those levels. The severity levels are:

| Level | Numeric | Typical Use |
|-------|---------|-------------|
| Emergency | 0 | System is unusable |
| Alert | 1 | Immediate action required |
| Critical | 2 | Critical conditions |
| Error | 3 | Error conditions |
| Warning | 4 | Warning conditions |
| Notice | 5 | Normal but significant |
| Info | 6 | Informational |
| Debug | 7 | Debug-level messages |

When no severities are selected, all severity levels are shown.

### Facility Filter

Select one or more facilities to filter by the source subsystem. Common facilities include kern, user, mail, daemon, auth, syslog, cron, and local0 through local7. When no facilities are selected, all are shown.

### Hostname Filter

Enter a hostname string. Messages whose hostname contains the entered text (case-insensitive) will be displayed.

### App Name Filter

Enter an application name string. Messages whose app name contains the entered text (case-insensitive) will be displayed.

### Source IP Filter

Enter an IP address or partial IP string. Messages whose source IP contains the entered text (case-insensitive) will be displayed.

### Text Search

Enter a search term to filter messages by their content. The search checks both the parsed message and the raw message text.

#### Regex Mode

Toggle the **Regex** option to interpret the search field as a regular expression. This allows advanced patterns such as:

- `error|warning` -- matches messages containing "error" or "warning"
- `^Failed` -- matches messages starting with "Failed"
- `\d{3}\.\d{3}\.\d{3}\.\d{3}` -- matches IP address patterns

If the regex is invalid, it is silently ignored and no filtering is applied for that field.

### Date Range

Set a **From** and/or **To** date to restrict messages to a specific time window. You can enter a date (YYYY-MM-DD) or a full datetime. When only a date is provided for the "To" field, the entire day is included.

## Exporting Logs

You can export the currently filtered set of logs in two formats:

### CSV Export

1. Apply any desired filters.
2. Click the **Export CSV** button.
3. Choose a file location in the save dialog (default filename: `syslog_export.csv`).
4. The CSV file includes a UTF-8 BOM for compatibility with Excel and contains the columns: Timestamp, Severity, Facility, Hostname, AppName, ProcID, Message, SourceIP, Protocol.

### TXT Export

1. Apply any desired filters.
2. Click the **Export TXT** button.
3. Choose a file location in the save dialog (default filename: `syslog_export.txt`).
4. Each line is formatted as: `YYYY-MM-DD HH:MM:SS [Severity] Facility Hostname AppName: Message`

Both export functions respect the current filters, so only the messages visible in the viewer are exported.

## Dashboard

Switch to the **Dashboard** view using the sidebar navigation. The dashboard displays real-time statistics about the syslog server:

- **Total Messages** -- the total number of messages received since the server was last started.
- **Messages per Second** -- the current throughput, calculated using a sliding window.
- **Severity Distribution** -- a breakdown of messages by severity level, showing how many messages have been received at each level.
- **Top Sources** -- the hostnames that have sent the most messages, ranked by count.
- **Buffer Usage** -- shows how many messages are currently stored versus the maximum buffer size, so you can see how close you are to the ring buffer limit.

Statistics are updated every second while the server is running.

## Theme

SyslogStudio supports both **light** and **dark** themes. Toggle between them using the theme button in the sidebar. Your preference is saved to the browser's local storage and persists across sessions.

## Language

The application supports English and French. The language is automatically detected based on your system locale:

- If your system locale starts with `fr`, the interface is displayed in French.
- Otherwise, the interface defaults to English.

There is no manual language selector; the app follows your operating system language setting.
