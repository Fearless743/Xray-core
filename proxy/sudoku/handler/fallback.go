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
// Vendored from SUDOKU-ASCII/sudoku v0.5.2.0 internal/app/fallback.go,
// adapted to the Xray inbound layout (package handler, exported entry point).
package handler

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/proxy/sudoku/config"
	"github.com/xtls/xray-core/proxy/sudoku/connutil"
	"github.com/xtls/xray-core/proxy/sudoku/logx"
)

const (
	tarpitDelay          = 5 * time.Second
	fallbackDialTimeout  = 3 * time.Second
	fallbackReplayWindow = 3 * time.Second
)

// handshakeRecorder is implemented by conns that kept the bytes a failed handshake consumed.
type handshakeRecorder interface {
	GetBufferedAndRecorded() []byte
}

// HandleSuspicious deals with a connection that failed authentication: it either tarpits it or
// replays what it sent to the fallback address and relays the rest, so probes see a real service.
func HandleSuspicious(wrapper, rawConn net.Conn, cfg *config.Config) {
	remote := rawConn.RemoteAddr().String()

	if cfg.SuspiciousAction == "silent" {
		logx.Warnf("Security", "Suspicious %s. Tarpit.", remote)
		_, _ = io.Copy(io.Discard, rawConn)
		time.Sleep(tarpitDelay)
		_ = rawConn.Close()
		return
	}
	if cfg.FallbackAddr == "" {
		_ = rawConn.Close()
		return
	}

	logx.Warnf("Fallback", "%s -> %s", remote, cfg.FallbackAddr)
	dst, err := net.DialTimeout("tcp", cfg.FallbackAddr, fallbackDialTimeout)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	if rec, ok := wrapper.(handshakeRecorder); ok {
		if consumed := rec.GetBufferedAndRecorded(); len(consumed) > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(fallbackReplayWindow))
			if err := connutil.WriteFull(dst, consumed); err != nil {
				_ = dst.Close()
				_ = rawConn.Close()
				return
			}
			_ = dst.SetWriteDeadline(time.Time{})
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer dst.Close()
		_, _ = io.Copy(dst, rawConn)
	}()
	go func() {
		defer wg.Done()
		defer rawConn.Close()
		_, _ = io.Copy(rawConn, dst)
	}()
	wg.Wait()
}
