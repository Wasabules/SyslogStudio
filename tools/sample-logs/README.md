# Sample logs

Small files for exercising **Import** by hand — one per shape the importer
claims to read, plus two awkward ones. Open the log view, press **Import**,
choose a file, and compare what the preview says with the table below.

Every address is from the documentation ranges (RFC 5737) and every domain from
RFC 2606, so nothing here points at a real host.

| File | Read as | What the preview should say |
|---|---|---|
| `plain-app.txt` | Automatic detection | 9 messages, 9 timestamps and 9 levels recognised, **6 lines joined**, 0 unrecognised |
| `json-lines.txt` | JSON | 8 messages, 8 timestamps, 8 levels — and *Automatic detection* finds **nothing** |
| `access.txt` | Access log | 7 messages, 3 Info, 2 Warning, 2 Error — the status code is the severity |
| `logfmt.txt` | logfmt | 7 messages, 7 timestamps, 7 levels; the pairs that are not fields stay in the message |
| `logcat.txt` | Custom pattern (below) | 9 messages, 9 levels, no timestamps — the format has none |
| `syslog-capture.txt` | Syslog (or automatic) | 8 messages, all 8 **with a syslog priority**: nothing is guessed |
| `messy.txt` | Automatic detection | 7 messages, 4 unrecognised — tick *Skip lines that do not match* and it drops to 3 |
| `apache-error.txt` | Automatic detection | 5 messages, detected as **Apache error log**, severity out of `[core:error]`, pid out of `[pid 1234]` |
| `klog.txt` | Automatic detection | 6 messages, detected as **Kubernetes klog**, severity from the leading letter, source file as the application |
| `logcat.txt` | Automatic detection | 9 messages, detected as **Android logcat**, tag as the application |
| `nginx-error.txt` | Automatic detection | 5 messages, slash-dated, severity out of `[error]` |
| `rsyslog-traditional.txt` | Automatic detection | 6 messages, detected as **syslog without a priority** — host and tag in their own columns (#50) |
| `auto-formats.txt` | Automatic detection | 24 messages, 20 timestamps, 15 levels, 6 with a host or app, 1 unrecognised — one line per format the recogniser knows |
| `archive-2019.txt` | Automatic detection | 6 messages filed under the **current year**; put 2019 in the Year box and they move |

## What the importer says a file is

Every file is named as well as read: the dialog reports what the sample turned
out to be — *Apache access log*, *Kubernetes klog*, *syslog without a
priority* — and switches the format selector to it when that shape has a mode
of its own. A file with no single dominant shape is called *mixed*, because
announcing one would be a confident answer to a question that has none.

`internal/importer/samples_test.go` checks every file in this directory: how
many messages it yields, what it is detected as, and the fields of its first
message. A file with no expectation fails that test, so adding a sample here
means making a claim about it.

## The pattern for `logcat.txt`

```
^(?P<level>[VDIWEF])/(?P<app>[^(]+)\(\s*\d+\): (?P<msg>.*)$
```

Since the brief logcat form is now recognised on its own, this pattern is no
longer needed for that file — it stays as the worked example of a custom
pattern, and of reading a single-letter level from a field that was declared to
be one. In free text a lone `E` is a letter, not a severity.

## What each file is for

- **`plain-app.txt`** — what detection is right about, with a Java stack trace
  in the middle of it. With *Join continuation lines* on it is 9 messages; turn
  it off and the same file becomes 15, with the error buried under its own
  trace.
- **`json-lines.txt`** — the format most applications write today and the one
  detection reads nothing from. Mixed on purpose: string levels with RFC 3339
  timestamps, and numeric levels (30, 40, 50, 60) with epoch milliseconds,
  seconds and microseconds, which are told apart by their magnitude.
- **`access.txt`** — the timestamp is not at the front of the line, which is why
  detection cannot see it, and there is no severity field at all. The status
  code is the severity: 5xx an error, 4xx a warning.
- **`logfmt.txt`** — quoted values with spaces and colons in them, to check that
  a message is not cut at the first space.
- **`logcat.txt`** — a shape nothing guesses, for trying a pattern of your own.
- **`syslog-capture.txt`** — a real capture, RFC 5424 and RFC 3164 in the same
  file, where every line carries its own severity and nothing is inferred.
- **`messy.txt`** — a banner, blank lines, a line that says nothing, and three
  different shapes. For watching the *not recognised* count and what *Skip
  lines that do not match* does to it.
- **`archive-2019.txt`** — BSD timestamps, which carry no year. For the Year
  box.
- **`auto-formats.txt`** — one line per shape automatic detection handles, in a
  single file, because it decides line by line: RFC 5424 and RFC 3164 with a
  priority and without, rsyslog's two stock templates, systemd, Go's standard
  logger, nginx and Apache error logs, an access line, Kubernetes klog, Android
  logcat, a Squid epoch, logback, Python logging, Serilog, MySQL, zap, Docker,
  Ruby, .NET, two JSON dialects, logfmt — and one line with no shape at all,
  which must stay unrecognised.

Import never fires alert rules and never relays to a notification destination,
so none of this can reach anything outside the application. Ticking *Also save
to the database* does write it to the history, which is worth knowing before
importing `messy.txt` eight times in a row.
