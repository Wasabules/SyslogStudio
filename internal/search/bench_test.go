package search

import (
	"fmt"
	"strings"
	"testing"
)

// The receiver's buffer and an export match up to 10 000 messages per call.
func benchMessages() [][2]string {
	templates := []string{
		"Failed password for root from 10.0.%d.%d port %d ssh2",
		"upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.10.%d.%d port %d",
		"Port GigabitEthernet1/0/%d error-disabled: link-flap detected (%d transitions in %d s)",
		"Échec de connexion : délai dépassé pour 192.168.%d.%d port %d",
	}
	msgs := make([][2]string, 10000)
	for i := range msgs {
		m := fmt.Sprintf(templates[i%len(templates)], i%250, i*7%250, 1000+i)
		msgs[i] = [2]string{m, "<14>1 2026-10-23T10:00:00Z host app - - - " + m}
	}
	return msgs
}

func BenchmarkMatch(b *testing.B) {
	msgs := benchMessages()
	for _, q := range []struct{ mode, query string }{
		{ModeText, "connection timed"},
		{ModeFTS, "error OR timeout"},
		{ModeRegex, "timed?\\s+out"},
	} {
		b.Run(q.mode, func(b *testing.B) {
			for b.Loop() {
				p := Compile(q.query, q.mode)
				for _, m := range msgs {
					p.Match(m[0], m[1])
				}
			}
		})
	}
	// What the buffer's search did before: a lowercase substring, per message.
	b.Run("old-substring", func(b *testing.B) {
		for b.Loop() {
			s := strings.ToLower("connection timed")
			for _, m := range msgs {
				_ = strings.Contains(strings.ToLower(m[0]), s) || strings.Contains(strings.ToLower(m[1]), s)
			}
		}
	})
}
