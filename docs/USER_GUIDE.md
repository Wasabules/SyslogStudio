# SyslogStudio User Guide

## Overview

SyslogStudio is a lightweight, cross-platform desktop application for receiving and analyzing syslog messages in real time. It supports UDP, TCP, and TLS protocols (RFC 5424 and RFC 3164) and provides a visual interface for viewing, filtering, and exporting log data.

Key capabilities:

- Receive syslog messages over UDP, TCP, and TLS simultaneously
- Parse both RFC 5424 and RFC 3164 (BSD) syslog formats automatically, and read the messages
  that bend them: rsyslog's forwarding format, JSON, key=value (FortiGate), Cisco IOS and ASA,
  messages with no priority
- Filter logs by severity, facility, hostname, application name, source IP, text search (with regex), and date range
- Export logs as CSV or plain text
- Monitor real-time statistics: message rates, severity distribution, top sources, buffer usage
- Generate and manage TLS certificates directly from the UI (PKI assistant)

## Getting Started

### Download and Install

**Pre-built binaries:** Download the latest release for your platform from the GitHub Releases page. The application is a single executable file:

- **Windows:** `SyslogStudio.exe`, or the installer
- **macOS:** `SyslogStudio.app`

No installation is required. Place the executable wherever you like and run it.

The Windows installer offers two kinds of installation:

- **Just for me** -- in your profile, with no administrator rights. SyslogStudio receives during
  your session, with its window open or in the background.
- **For all users** -- in Program Files, with administrator rights. The same, and SyslogStudio
  can also run as a Windows service that receives from boot, with nobody signed in (see
  [Running in the Background](#running-in-the-background)). A portable copy or a per-user
  installation cannot.

Run over an existing installation, the installer preselects it and updates it where it is.
Choosing **For all users** over a **Just for me** copy replaces it with one in Program Files;
your settings and logs are kept.

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

### Messages that bend the standard

Many devices send something close to RFC 5424 or RFC 3164, but not quite. SyslogStudio reads
the header as the RFCs define it when it is one. When it is not, it reads the rest of the
message the way a file import reads a line:

| What arrives | Example | What is read |
|---|---|---|
| rsyslog's forwarding format: an RFC 3339 timestamp and no version | `<30>2026-10-27T09:14:02+01:00 nas-01 smbd[812]: …` | timestamp, host, application, process |
| No host before the tag | `<134>Oct 27 09:14:02 dhcp: lease …` | application (`dhcp`), no invented host |
| JSON | `<14>{"level":"error","msg":"disk full","host":"app-3"}` | level, timestamp, host, application, message |
| key=value (FortiGate and others) | `<189>date=… time=… devname="FGT60F" level="warning" msg="…"` | timestamp (date and time together), host, level, message |
| Cisco IOS, IOS-XE, NX-OS, ASA | `<187>123: *Oct 27 09:14:02.123: %LINK-3-UPDOWN: …` | timestamp, host when sent, the mnemonic as the application |
| No priority at all | `2026-10-27 09:14:02 ERROR motion detection failed` | timestamp, and a level word at the very front |

The severity in the priority is the sender's own and stays, unless the message declares its own
level in a field (JSON `level`, key=value `level=`). A level word inside the text never overrides
it. With no priority, a level word at the very front of the message is taken; one in the middle
of a sentence is not.

The raw message is always kept as it arrived, shown in the detail panel.

### Source rules: reading a device differently

Some devices bend the standard further than reading it automatically can follow: no hostname,
a format of their own, the same priority on every message, a clock in another time zone,
Windows-1252 instead of UTF-8. A **source rule** says how the messages of such a device are
read. It applies as they arrive, before the live view, the history, the alert rules and the
routing see them, so an alert on errors fires on the error the device meant.

The quickest way to write one is from a message: **right-click** it, then **Read this device's
messages differently…**. The rule is opened on that device's address; if a rule already names
the address, that rule opens instead. Rules are listed, ordered, turned off and removed in
**Settings > Sources**.

A rule has three parts.

**Which messages**
- **Addresses**: an IP, a CIDR (`10.0.7.0/24`) or a pattern, comma-separated.
- **Hostnames** and **Applications**: patterns such as `fw-*`, matched against the message as
  read without the rule.
- **Raw text contains**: a regular expression, case-insensitive. Behind a relay every device
  arrives from the same address, and this is what tells them apart.

Every condition given has to match. Rules are tried in the order listed, and the first that
matches applies.

**How they are read** — the same formats as a file import: JSON, key=value, a regular
expression with named groups (`time`, `level`, `host`, `app`, `msg`), and the others.
- When the header is not standard, the format reads what follows the priority.
- When the header is standard, the format reads the message text. A container logging JSON
  through a syslog driver keeps its host and application, and gains its level and message.
- **Automatic detection** keeps the reading as received. The time zone then applies to the
  timestamps that carry none, RFC 3164 ones included.

**Corrections**

| Setting | What it does |
|---|---|
| Hostname | As sent, the address the message came from, or a name you give |
| Application | Replaces the one sent |
| Severity | *Automatic*: the priority, unless the message declares a level in a field. *Always the priority*. *From the message text*: a level word anywhere in the text wins |
| Encoding | UTF-8, Windows-1252, ISO-8859-1 or ISO-8859-15, for a device that garbles accents |
| Use the arrival time | For a device whose clock cannot be trusted |

While a rule is written, every change is tried on the device's latest messages. The preview shows
each one as read with the rule, with what it was without the rule struck through. A rule applies
to the messages that arrive once it is saved; messages already received keep their reading. In
the live view, the detail panel names the rule that read a message.

Rules belong to the engine the window drives: while it drives the system service, they are the
service's. Installing the service copies the window's rules to it.

### Auto-Scroll

By default, the log viewer automatically scrolls to show the newest messages as they arrive. You can toggle auto-scroll on or off. When auto-scroll is off, you can freely scroll through the log history without being interrupted by new arrivals.

### Clearing Logs

Use the **Clear** function to empty the log buffer. This removes all messages from both the display and memory.

## Filtering

The **Filter Bar** provides several ways to narrow down the displayed messages. All filters are applied together (logical AND).

Every filter, sort and grouping below means the same thing in the live view, in the history and in
an export: the same messages, in the same order.

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

### Hostname, App Name and Source IP Filters

Enter part of a hostname, an application name or an IP address. Messages whose field contains the
entered text are displayed:

- Case does not matter, and neither does an accent on a Latin letter: `cafe` finds `CAFÉ-01`.
- Everything else counts as typed, spaces included. `web_01` finds `web_01` and not `web-01`, and
  `50%` is a percent sign, not a wildcard.

### Search

The search box looks in each message's text and in its raw line. The button beside it switches
between three modes. Each mode finds the same messages in the live view, in the history and in an
export.

#### Text mode (`Aa`)

The words as typed, in that order, the last one possibly unfinished:

- `connection ref` finds "Connection refused".
- Case, accents and the punctuation between words do not matter: `192.168.1` finds 192.168.1.10.
- A word is found from its beginning: `onnection` finds nothing. Use Regex mode for that.
- A search with no letter or digit in it, such as `->`, is looked for exactly as typed.

#### FTS mode (`FTS`)

Words combined with operators:

- `error timeout` or `error AND timeout`: both words, anywhere in the message.
- `error OR timeout`: either word.
- `error NOT timeout`: the first word without the second. NOT excludes from what comes before it,
  so it cannot start a search.
- `(error OR refused) NOT disk`: parentheses group operators.
- `"connection refused"`: these words, in this order.
- `time*`: any word starting with "time".
- `NEAR(error timeout, 5)`: both words, at most 5 words apart. Without a distance, 10.

Operators work in any case. To search for the word "or" itself, quote it: `"or"`.

#### Regex mode (`.*`)

A regular expression in Go's syntax, without regard to case. For example:

- `error|warning` -- matches messages containing "error" or "warning"
- `^Failed` -- matches messages starting with "Failed"
- `\d{3}\.\d{3}\.\d{3}\.\d{3}` -- matches IP address patterns

#### How words are compared

Words are split the way the history's full-text index (SQLite FTS5) splits them:

- letters and digits make words, and anything else separates them;
- case does not matter;
- an accent on a Latin letter does not matter either: `délai` finds "delai".

A search that cannot be read is not applied, and a note under the box says why. That covers an
unclosed quote, an operator with nothing after it and an invalid regular expression.

### Date Range

Set a **From** and/or **To** time to restrict messages to a time window:

- **From** is included, and **To** includes its whole minute: from 22:30 to 22:33 keeps 22:33:59.
- Times are read in the zone the list is displayed in (Settings > Timezone), and the boxes follow
  when that zone changes.
- The window stands for the same instants in every view, whatever zone the service or the machine
  is in.

### Sorting and Grouping

Click a column header to sort by it, and again to reverse.

- Text sorts without regard to case.
- Numbers sort as numbers, process and message ids included: numeric ids first, then the others.
- Messages that tie keep the order they arrived in.

**Group by** gathers messages by severity, hostname, application or source IP:

- the biggest groups come first, then by name;
- a group holds exactly the messages whose field is its name: `web` does not take in `web-01`;
- messages without a value are grouped under *unknown*.

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

## Keeping the History

**Settings > Storage** sets how long messages stay in the history and what happens to the disk
space they took. The defaults need no attention: old messages go every few minutes, and their
space goes back to the disk as they do.

### How long

- **Keep messages for**: 1, 7, 30, 90, 180 or 365 days, unlimited, or any number of days with
  *Custom…*.
- **Max messages** and **Max database size** cap the history whatever its age. They protect the
  disk, so they apply at all times, even with a scheduled cleanup.
- **Keep whole** moves the age limit back to the start of its day, its week (from Monday) or its
  month. With 90 days and whole months, the oldest month in the history is always complete, which
  is what a monthly report needs.

### When

**Clean up** sets when messages past their age go:

- **Continuously** (the default): every five minutes, a little at a time.
- **Every day**, **every week** or **every month**, at a time of day on the machine's clock. A run
  missed while SyslogStudio was off happens at the next start.

Between two scheduled runs the history keeps older messages, up to one more day, week or month:
the forecast below counts them.

### Disk space

SQLite keeps the space of deleted messages for new ones; **Disk space** sets when the file itself
shrinks:

- **Give it back as it goes** (the default): a little at a time after each cleanup.
- **Compact after each scheduled cleanup**: the whole database is rewritten after each run.
- **Only with the Compact button**: the file keeps its largest size until you press *Compact*.

Messages keep arriving through all of this:

- Cleanups work in small steps that the writes of new messages pass between.
- A full compaction holds those writes for its duration, between a few seconds and half a minute
  on a million messages depending on the disk, and the arriving messages wait in memory meanwhile.
- Memory holds up to 200,000 waiting messages, about a hundred seconds at 2,000 a second. Only a
  full compaction of a very large database at a high rate could outlast that; giving space back
  as it goes, the default, never rewrites the whole database.

A database created by an earlier version is switched to giving space back once, in the
background, the first time it is opened: one compaction, under the same rule.

### Where the database is heading

Under the settings, the forecast says what they mean at the rate messages actually arrive:

- messages and megabytes a day;
- the size the retention or a limit holds the database at, and in how many days it gets there;
- or, when nothing limits it, how fast it grows;
- free space on the disk, and when it would run out at this rate;
- the last cleanup — when, how many messages, how much space went back — and the next one.

## Encryption

**Settings > Storage > Encryption** encrypts the database at rest, with AES-256-GCM. The password
opens a random key, and that key encrypts the database, the certificate authority, the
destinations' credentials and the sealed inbox key. The password itself is never stored.

- **Change the password** asks for the current one. The data is not encrypted again: only the
  lock on the key changes.
- A database encrypted by a version before 1.8 opens with its password as before. Its first
  change of password, or the creation of a recovery key, replaces its key, which encrypts
  everything again once.
- Once this version has written a database, versions before 1.8 can no longer open it.

### The recovery key

A recovery key is a file that opens the database and its backups without the password. If the
password is forgotten, it gets everything back.

- **Create a recovery key…** saves it to a file you choose (`.key`). Keep it away from the
  computer: a USB stick, a safe, a password manager. Whoever has the file can open the database.
- On the unlock screen, **Forgot the password? Use the recovery key** asks for the file, then for a
  new password. *Later* keeps the current one.
- **Replace…** and **Remove** stop the old file from opening the database and the backups made
  from then on. Backups made before still open with it.

The recovery key works with encryption off too: backups are then encrypted, and open with the key.

## Backups

**Settings > Backups** copies the database to one or more **destinations**. Each backup is made
once, encrypted on this computer, then sent to every destination: a server only ever stores what it
cannot read.

### Destinations

**Add a destination…** offers four kinds:

| Kind | What it is |
|---|---|
| **Folder** | Another disk, a USB drive, or a network share or NFS export mounted on this machine. |
| **SFTP** | A server reached over SSH, signing in with a password or an SSH key (and its passphrase). |
| **FTPS** | An FTP server over TLS: explicit (AUTH TLS, usually port 21) or implicit (usually port 990). |
| **FTP** | An FTP server in the clear. |

- **Test the connection** writes a small file, lists the folder and deletes the file. Saving a
  server tests it first.
- The first connection to a server shows its **fingerprint**: the SSH key's, or, for FTPS, the
  certificate's when the system does not trust it (a NAS's own certificate). Compare it with the one
  the server's administrator gives you, or the one the NAS shows, and **Trust and save** only if
  they match. From then on, a server presenting anything else is refused: if it was reinstalled or
  its certificate renewed, edit the destination and trust the new identity.
- **FTP** sends the password in the clear: anyone on the network between this computer and the
  server can read it, sign in with it, and delete or replace what is there. The backups themselves
  stay encrypted. The destination is only saved once you acknowledge this; prefer SFTP or FTPS,
  which most NAS offer.
- Passwords and keys are kept like the routing destinations' credentials: never shown again,
  encrypted with the database when it is, and only ever sent to the server they were given for —
  moving a destination to another server or account means typing its password again.
- **Keep**: how many backups each destination keeps; the oldest go beyond that. SyslogStudio only
  deletes the files it made (`syslogstudio-….ssbackup` or `.db`).
- A destination can be turned off without being deleted. Deleting one leaves the backups already
  there where they are.

### When

- **Back up automatically**: every day, every week or every month, at a time of day. A backup
  missed while SyslogStudio was off is made at the next start, once the database is unlocked.
- A destination that fails — a disk unplugged, a server unreachable — is tried again an hour later,
  without holding up the others.
- A destination added is served from the next scheduled backup on. **Back up now** makes one at
  once, for every destination.

Messages keep arriving during a backup: the copy is the database as it was when the backup
started. Each backup is read back before it is sent, and checked once it has arrived: read back in
full in a folder, its size on a server.

What opens a backup:

| Database | Recovery key | The backup opens with |
|---|---|---|
| Encrypted | No | The password the database had when the backup was made |
| Encrypted | Yes | That password, or the recovery key |
| Not encrypted | Yes | The recovery key |
| Not encrypted | No | Nothing: the backup is a plain SQLite file |

### Opening a backup

**Open** in the list, or **Open a backup file…** for a backup from elsewhere, asks for its
password or recovery key, then shows the backup in the **History**. A backup on a server is read
as it arrives, by the window itself. A banner says so; the live
view and the database are untouched. **Close the backup** returns the History to the database.

### Importing a backup

**Import** adds the messages of a backup to the history, without replacing anything. It is in
three places:

- **Import** next to a backup in the list;
- **Import a file…**, for a backup from elsewhere or a database file (`.db`): one kept aside, or
  another installation's;
- **Import into the history**, in the banner of a backup open in the History.

Only the messages the history lacks are added. Each message keeps its own identifier, so
importing the same backup twice adds nothing the second time, and nothing already in the history
is changed or removed. A toast says how many were added and how many were there already.

The history is the database the window shows: your own, or the service's while the window drives
one that stores in the clear. The retention applies to what is imported: messages older than it go
at the next cleanup, so lengthen it first to keep them.

### Restoring

**Restore…** replaces the database with a backup:

1. The backup is opened first: a wrong password changes nothing.
2. The database as it is is copied on this computer, as
   `syslogstudio-…-before-restore.ssbackup` in a `backups` folder of the data directory, listed
   under **Before a restore**. Restoring that copy undoes the restore; these copies are never
   deleted automatically.
3. The database is replaced. Messages that arrive meanwhile wait in memory and go to the restored
   database.

The retention applies to the restored database: messages older than it are deleted at the next
cleanup. To read old messages, open the backup instead of restoring it.

With the system service, backups are made by the service, under its own account: a folder has
to be one that account can write to — a server destination avoids the question. Installing the
service hands it the destinations, credentials included. With the sealed inbox, the backups are
those of your own database, and stay with the window. A service switched to the sealed inbox later
hands its destinations to the window, when the window has none of its own.

## Running in the Background

SyslogStudio can keep receiving with its window closed, in two ways, both set up in
**Settings > Background**.

### In your session

- **Start SyslogStudio when I sign in** -- the application starts hidden in the system tray when
  you sign in, under your account and with your settings, and stops when you sign out. No
  administrator rights are needed.
- **Start receiving when SyslogStudio opens** -- the listeners start as last saved, without
  pressing Start. If the database is encrypted, the window appears at sign-in to ask for the
  password and returns to the tray afterwards.

### As a system service (Windows, Linux)

For a machine that must receive with nobody signed in. **Install the service** asks for
administrator rights once, creates the `SyslogStudio` service (automatic start at boot, account
`NT SERVICE\SyslogStudio`, restart on failure), copies your listeners, alert rules, routes,
destinations with their credentials and your TLS certificate to `%ProgramData%\SyslogStudio`,
and adds an inbound firewall rule on domain and private networks. This window stops its own
listeners, since the service takes over the ports, and your account is allowed to drive the
service.

**Bring the messages stored here to the service** is offered, ticked, when your database is not
encrypted. Once the service runs, the window copies your history into the service's database, in
the background:

- A banner shows how far the copy has got, and the History fills up meanwhile.
- If the copy stops — the window closed, the service stopped — it carries on the next time the
  window drives the service. Nothing is copied twice.
- Your own database keeps its copy.

While the service runs, **this window drives it**. A banner says so. Everything you see and
change is the service's:

- the listeners and their ports (ports below 1024 included), saved by the service and used
  again at its next start;
- the live view, the history and the statistics: what the service receives and stores;
- alert rules, routes and destinations, certificates, the simulator;
- imports: the window reads the file, which the service's account could not, and sends the
  messages to the service.

**Start** and **Stop** in the toolbar start and stop the service's listeners. The service itself
keeps running, and so do its alert rules and routes. A listener whose port another program holds
does not start, and the error names that program.

What happens when the service next starts, at boot for instance, is set by **Start receiving when
the service starts**. This option sits in Settings > Background and is shown while the window
drives the service:

- **On** (the default): the service listens as last saved, whatever was pressed before.
- **Off**: the service still starts with the computer, but receives nothing until you press
  Start.

The *Start receiving when SyslogStudio opens* option above only concerns your own receiver, so it
has no effect while the window drives the service.

When the service stops, the window shows your own receiver again, with a banner saying why, and
switches back as soon as the service runs. The banner offers what to do:

- **Start the service**, when it is stopped;
- **Allow my account**, when the service runs but your account may not drive it — another user
  of the machine, or a service installed by an earlier version. It asks for administrator
  rights once and restarts the service.

The window and the service connect over a local named pipe that only administrators and the
allowed accounts may open, and the window checks that what answers is the service itself.

#### On Linux

On a Linux system that runs systemd, the same button installs a systemd unit instead:

- The unit runs SyslogStudio as a `syslogstudio` system account. That account may listen on
  ports below 1024 and can do little else: the system is read-only to it, and home directories
  are out of its reach.
- The service keeps its configuration and data in `/var/lib/syslogstudio`, readable by root
  only. Its status and the socket windows connect to are in `/run/syslogstudio`.
- Administrator rights come from polkit (`pkexec`). Without polkit, run the commands with
  `sudo`.
- SyslogStudio must be installed from its package, or copied under `/usr/local` as root. A copy
  unpacked in a home directory cannot be installed as a service.
- No firewall rule is added. If a firewall filters what comes in, open the ports in it.
- The window connects over a Unix socket. The service checks who connects against the allowed
  accounts, and an account allowed later gets in without a restart.
- Credentials and private keys are protected by the directory's permissions: Linux has no
  DPAPI.
- Removing the package removes the service and keeps its data. Upgrading the package restarts
  the service on the new version.

#### With an encrypted database

When your database is encrypted, installing the service asks what it should do with the messages
it receives.

**Keep it encrypted** is the default. The service then works like this:

- It keeps no database. It seals each batch of messages with a public key: HPKE, hybrid
  post-quantum ML-KEM-768 + X25519.
- It cannot read back what it stored, and neither can anyone who copies its files.
- The private key stays with your database, encrypted by its password.
- Once you unlock the database in this window, the window collects the sealed batches and stores
  their messages in your encrypted history. The service then deletes them.

What to expect in this mode:

- The live view, the alerts and the routing work as before: the service sees the messages as
  they arrive.
- Until you unlock, your history does not show what the service received.
- Up to 1 GB waits on the service. At four-fifths full, the Background tab and the Windows event
  log warn you. Past that, new messages are dropped and counted.
- If the service stored in the clear before, it moves that database into the sealed inbox and
  deletes it. Its old messages reach your encrypted history too.

**Store unencrypted** keeps the earlier behaviour. The service has its own database, readable by
administrators only, and the window shows that database. You confirm that it is not encrypted.

Requirements and limits:

- SyslogStudio must be installed **for all users** (Program Files). A per-user or portable copy
  cannot be installed as a service.
- Without the sealed inbox, the service's database is not encrypted: nobody is there to type a
  password at boot. Its directory is readable by administrators only.
- The service's credentials and private key are sealed with DPAPI.
- With the sealed inbox, at-rest encryption applies to your own database, as usual, and your
  history stays in it.
- Storing unencrypted, the messages your own receiver stored stay in your own database unless
  they were brought to the service at install. The window shows them again when it is not driving
  the service.

To encrypt later, while the window drives a service that stores in the clear, open
**Settings > Storage > Encryption**. It asks for a new password, or for your own database's when
that one is encrypted already. One administrator prompt then does the rest:

1. Your own database is encrypted, and holds the history from then on.
2. The service switches to the sealed inbox and restarts.
3. The database the service had moves into its inbox. From there, it reaches your encrypted
   history while the window is open and unlocked.
4. The service's backup destinations come with it, when your own database has none.

#### Removing the service

**Uninstall…** first brings the service's messages back into your own database. This option is
ticked by default:

- It asks for your database's password when your database is encrypted.
- The service stops receiving during the copy, so nothing is lost on the way.
- Messages your database already holds are not copied twice.
- If the copy fails, nothing is removed.

With the sealed inbox, what still waits sealed on the service is collected first. **Also delete
its data** then removes the service's directory. To bring the service's messages back, the window
must be driving the service: start it first, or allow your account.

While the service is stopped, **Update its configuration** copies the window's own settings to
the service and restarts it; while the window drives the service there is nothing to copy, and
the button is not shown. **Start**, **Stop** and **Uninstall** each ask for administrator
rights.

### Troubleshooting the service

- `SyslogStudio.exe service status` prints:
  - the state and the listeners, and whether they start with the service;
  - the sealed inbox;
  - the number of messages received and the connected windows;
  - the allowed accounts and the last error. Pipe it through
  `more` when running it from `cmd`.
- On Windows, start-up errors are written to the **Application** event log, source
  `SyslogStudio`, and the service's own log is `%ProgramData%\SyslogStudio\logs\service.log`.
- On Linux, everything the service says is in the journal: `journalctl -u syslogstudio`.
- A port already in use at boot does not stop the service: it reports the error, retries every
  30 seconds, and a window can change the ports meanwhile.

### Headless

`SyslogStudio --headless [--data-dir DIR]` runs the receiver with no window, in the
foreground, until interrupted -- for systemd, launchd or a terminal. Without `--data-dir` it uses
the application's own configuration directory. It refuses an encrypted configuration, and a
directory another SyslogStudio already has open.

## Theme

SyslogStudio supports both **light** and **dark** themes. Toggle between them using the theme button in the sidebar. Your preference is saved to the browser's local storage and persists across sessions.

## Language

The application supports English and French. The language is automatically detected based on your system locale:

- If your system locale starts with `fr`, the interface is displayed in French.
- Otherwise, the interface defaults to English.

There is no manual language selector; the app follows your operating system language setting.
