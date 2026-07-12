package syslog

import (
	"bufio"
	"bytes"
	"strconv"
)

// maxOctetCount bounds the declared length of an octet-counted frame so a
// malformed or hostile MSG-LEN cannot force an unbounded buffer. It matches
// the scanner's buffer capacity.
const maxOctetCount = tcpScanBufSize

// syslogFrameSplit is a bufio.SplitFunc implementing both syslog TCP
// framings from RFC 6587:
//
//   - Octet counting (RFC 6587 §3.4.1, mandated by RFC 5425 for TLS):
//     "MSG-LEN SP SYSLOG-MSG", where MSG-LEN is the decimal byte count of
//     SYSLOG-MSG. This is the correct framing for many devices sending
//     syslog over TLS and cannot be recovered by line splitting alone.
//
//   - Non-transparent framing (RFC 6587 §3.4.2): messages delimited by a
//     trailing LF. This is the legacy behavior and remains the fallback.
//
// A frame is treated as octet-counted only when it begins with a run of
// ASCII digits followed by a single space and the digits parse as a
// non-negative length within bounds; otherwise it falls back to LF
// delimiting. Leading CR/LF between frames is skipped.
func syslogFrameSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip any leading CR/LF left between frames.
	start := 0
	for start < len(data) && (data[start] == '\n' || data[start] == '\r') {
		start++
	}
	if start > 0 {
		data = data[start:]
	}

	if len(data) == 0 {
		if atEOF {
			return start, nil, nil
		}
		return start, nil, nil
	}

	// Attempt octet-counting: leading digits followed by a space.
	if data[0] >= '0' && data[0] <= '9' {
		sp := bytes.IndexByte(data, ' ')
		// Only treat as octet-counted if the prefix up to the space is
		// all digits. A digit-led message with no space (or with a
		// non-digit before the space) falls through to LF framing.
		if sp > 0 {
			allDigits := true
			for _, c := range data[:sp] {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				n, convErr := strconv.Atoi(string(data[:sp]))
				if convErr == nil && n >= 0 {
					if n > maxOctetCount {
						// Declared length exceeds our buffer; drop the
						// prefix so we don't stall forever. Advance past
						// the length+space and let subsequent bytes be
						// framed by LF as a best effort.
						return start + sp + 1, nil, nil
					}
					frameEnd := sp + 1 + n
					if len(data) >= frameEnd {
						return start + frameEnd, data[sp+1 : frameEnd], nil
					}
					// Need more data for the full frame.
					if atEOF {
						// Incomplete final frame: emit what we have.
						return start + len(data), data[sp+1:], nil
					}
					return start, nil, nil
				}
			}
		}
		// If we have a digit run but no space yet and more data may come,
		// wait — unless at EOF, where we fall through to LF handling.
		if sp < 0 && !atEOF {
			return start, nil, nil
		}
	}

	// Non-transparent framing: split on LF.
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return start + i + 1, dropCR(data[:i]), nil
	}

	if atEOF {
		return start + len(data), dropCR(data), nil
	}
	return start, nil, nil
}

// dropCR removes a trailing carriage return from a line.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[:len(data)-1]
	}
	return data
}

// ensure bufio is referenced (SplitFunc signature documentation).
var _ bufio.SplitFunc = syslogFrameSplit
