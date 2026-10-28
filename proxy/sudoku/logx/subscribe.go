/*
Copyright (C) 2026 by saba <contact me via issue>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
*/
package logx

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one log line as subscribers see it: "[Component] message", without color.
type Entry struct {
	Time  time.Time
	Level Level
	Text  string
}

// subscriberBuffer is how many lines a slow subscriber may fall behind before it misses some.
const subscriberBuffer = 256

var (
	subsMu     sync.Mutex
	subs       = map[chan Entry]struct{}{}
	subscribed atomic.Bool // len(subs) > 0, so logging stays free of extra work without subscribers
)

// Subscribe streams every line logged from now on until cancel is called. A subscriber that
// falls behind misses lines rather than slowing logging down.
func Subscribe() (entries <-chan Entry, cancel func()) {
	ch := make(chan Entry, subscriberBuffer)
	subsMu.Lock()
	subs[ch] = struct{}{}
	subscribed.Store(true)
	subsMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			subsMu.Lock()
			delete(subs, ch)
			subscribed.Store(len(subs) > 0)
			subsMu.Unlock()
		})
	}
}

func publish(now time.Time, lvl Level, component string, msg []byte) {
	var b strings.Builder
	if component = strings.TrimSpace(component); component != "" {
		b.Grow(len(component) + 3 + len(msg))
		b.WriteByte('[')
		b.WriteString(component)
		b.WriteString("] ")
	}
	writeWithoutColor(&b, msg)
	e := Entry{Time: now, Level: lvl, Text: b.String()}

	subsMu.Lock()
	for ch := range subs {
		select {
		case ch <- e:
		default:
		}
	}
	subsMu.Unlock()
}

// writeWithoutColor copies msg minus the SGR sequences ("\x1b[...m") the color helpers add.
func writeWithoutColor(b *strings.Builder, msg []byte) {
	for len(msg) > 0 {
		i := bytes.Index(msg, []byte("\x1b["))
		if i < 0 {
			b.Write(msg)
			return
		}
		b.Write(msg[:i])
		msg = msg[i+2:]
		end := bytes.IndexByte(msg, 'm')
		if end < 0 {
			return
		}
		msg = msg[end+1:]
	}
}
