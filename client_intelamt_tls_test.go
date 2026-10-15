package bmclib

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bmc-toolbox/bmclib/v2/providers/intelamt"
)

// TestIntelAMTHonoursSecureTLS checks that the client's TLS settings reach the Intel AMT
// provider. The server answers like AMT's WS-Man endpoint: a 401 with a digest challenge,
// which is all the provider's Open needs.
func TestIntelAMTHonoursSecureTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Digest realm="Digest:0000", nonce="abc", stale="false", qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(u.Port(), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	trusted := x509.NewCertPool()
	trusted.AddCert(srv.Certificate())

	tests := map[string]struct {
		opts    []Option
		wantErr string
	}{
		"default client skips verification":      {},
		"WithSecureTLS trusting the server's CA": {opts: []Option{WithSecureTLS(trusted)}},
		"WithSecureTLS with an unrelated CA": {
			opts:    []Option{WithSecureTLS(x509.NewCertPool())},
			wantErr: "certificate",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opts := append([]Option{
				WithIntelAMTHostScheme("https"),
				WithIntelAMTPort(uint32(port)),
			}, tt.opts...)
			cl := NewClient(u.Hostname(), "admin", "pw", opts...)
			cl.Registry.Drivers = cl.Registry.For(intelamt.ProviderName)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := cl.Open(ctx)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("want an error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
