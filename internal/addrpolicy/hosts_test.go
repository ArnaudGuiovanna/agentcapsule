package addrpolicy

import "testing"

// The table moved here from internal/llmgateway with InternalHost.
func TestInternalHostSeesLiteralAddressesAndLocalhost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "10.0.0.7", "192.168.1.20", "169.254.169.254", "168.63.129.16", "fd00:ec2::254",
		"fe80::1%eth0", "::ffff:127.0.0.1", "0.0.0.0", "localhost", "LOCALHOST.", "models.localhost", "127.1", "2130706433", "0x7f000001", "0177.0.0.1"} {
		if !InternalHost(host) {
			t.Errorf("%s not seen as internal", host)
		}
	}
	for _, host := range []string{"api.openai.com", "API.Anthropic.com.", "llm.example.org", "1.1.1.1", "2606:4700::1111", "models.internal", "a1b2.example"} {
		if InternalHost(host) {
			t.Errorf("%s seen as internal", host)
		}
	}
}
