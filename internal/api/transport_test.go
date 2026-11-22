package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// L-19: answers over TLS tell the browser to use HTTPS only.
func TestAnswersOverTLSCarryHSTS(t *testing.T) {
	s := noDatabaseServer(t)
	for _, secure := range []bool{true, false} {
		r := httptest.NewRequest("GET", "/v1/version", nil)
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		got := w.Header().Get("Strict-Transport-Security")
		if w.Code != 200 || (secure && got != "max-age=31536000") || (!secure && got != "") {
			t.Fatal("HSTS", secure, w.Code, got)
		}
	}
}

// smallBuffers keeps few bytes in flight on each accepted connection, so
// that a client that does not read holds the server's write.
type smallBuffers struct{ net.Listener }

func (l smallBuffers) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetWriteBuffer(4096)
	}
	return c, err
}

// L-05: a download that takes longer than the server's write timeout to
// reach a slow client is not cut: its handler moves the write deadline.
func TestASlowDownloadOutlivesTheServerWriteTimeout(t *testing.T) {
	l, _, agent, _, bob := tenantInvocationLab(t)
	file := make([]byte, 2<<20)
	_, _ = rand.Read(file)
	w := httptest.NewRecorder()
	l.server.ServeHTTP(w, uploadRequest("/v1/agents/"+agent+"/attachments", bob, "slow", bytes.NewReader(file), int64(len(file))))
	var att controlplane.Attachment
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &att) != nil {
		t.Fatal("upload", w.Code, w.Body.String())
	}
	r := call(t, l.server, "POST", "/v1/attachments/"+att.ID+"/link", bob, "", "")
	var link controlplane.DownloadLink
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &link) != nil {
		t.Fatal("link", r.Code, r.Body.String())
	}
	h := httptest.NewUnstartedServer(l.server)
	h.Config.WriteTimeout = time.Second
	h.Listener = smallBuffers{h.Listener}
	h.Start()
	defer h.Close()
	dialer := &net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096) })
	}}
	client := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}, Timeout: time.Minute}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.URL+link.URL, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	// The client reads nothing past the server's write timeout.
	time.Sleep(2500 * time.Millisecond)
	got, err := io.ReadAll(res.Body)
	if res.StatusCode != 200 || err != nil || !bytes.Equal(got, file) {
		t.Fatal("download cut for a slow client", res.StatusCode, len(got), "of", len(file), err)
	}
}
