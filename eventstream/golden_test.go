package eventstream

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// Examples from "Event stream encoding" in the Amazon Transcribe streaming
// guide (https://docs.aws.amazon.com/transcribe/latest/dg/streaming-setting-up.html).
// The page wraps the base64 over several lines.
const (
	pageAudioEvent = `AAAA0gAAAIKVoRFcTTcjb250ZW50LXR5cGUHABhhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0LOmV2ZW50LXR5
cGUHAApBdWRpb0V2ZW50DTptZXNzYWdlLXR5cGUHAAVldmVudAxDb256ZW50LVR5cGUHABphcHBsaWNhdGlv
bi94LWFtei1qc29uLTEuMVJJRkY88T0AV0FWRWZtdCAQAAAAAQABAIA+AAAAfQAAAgAQAGRhdGFU8D0AAAAA
AAAAAAAAAAAA//8CAP3/BAC7QLFf`
	pageChunkSignature = `AAAAUwAAAEP1RHpYBTpkYXRlCAAAAWiXUkMLEDpjaHVuay1zaWduYXR1cmUGACCt6Zy+uymwEK2SrLp/zVBI
5eGn83jdBwCaRUBJA+eaDafqjqI=`
)

func unb64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(s, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeOne(t testing.TB, b []byte, lim Limits) (*Message, error) {
	t.Helper()
	return NewDecoder(bytes.NewReader(b), lim).Next()
}

func TestGoldenChunkSignature(t *testing.T) {
	b := unb64(t, pageChunkSignature)
	m, err := decodeOne(t, b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Headers) != 2 || len(m.Payload) != 0 {
		t.Fatalf("headers=%v payload=%d", m.Headers, len(m.Payload))
	}
	d, ok := m.Header(":date")
	if !ok || d.Type() != TypeTimestamp || !d.Time().Equal(time.Date(2019, 1, 29, 1, 56, 17, 291e6, time.UTC)) {
		t.Fatalf(":date = %v", d)
	}
	s, ok := m.Header(":chunk-signature")
	if !ok || s.Type() != TypeBytes || len(s.Bytes()) != 32 {
		t.Fatalf(":chunk-signature = %v", s)
	}
	// the encoder reproduces the page byte for byte
	out, err := Marshal(*m)
	if err != nil || !bytes.Equal(out, b) {
		t.Fatalf("re-encode differs: %v", err)
	}
}

// The first example of the page is not a valid message as printed: its
// prelude CRC holds, but the first header name ("7#ontent-type") and the
// fourth ("Conzent-Type") carry four corrupted bytes (a typo in the page).
// We pin that a strict decoder rejects it as printed, and that with those
// four bytes repaired it decodes, under the page's own trailing CRC, to the
// headers the page states.
func TestGoldenAudioEvent(t *testing.T) {
	b := unb64(t, pageAudioEvent)
	if len(b) != 210 {
		t.Fatalf("page example is %d bytes", len(b))
	}
	if _, err := decodeOne(t, b, Limits{}); !errors.Is(err, ErrHeader) {
		t.Fatalf("page bytes as printed: want ErrHeader, got %v", err)
	}

	fix := append([]byte{}, b...)
	copy(fix[12:], []byte{0x0d, ':', 'c'}) // name_len 13, ":c"
	if i := bytes.Index(fix, []byte("Conzent-Type")); i < 0 {
		t.Fatal("anchor missing")
	} else {
		fix[i+3] = 't'
	}
	// The page's own trailing CRC is valid for the repaired bytes.
	m, err := decodeOne(t, fix, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Header{
		{":content-type", String("application/octet-stream")},
		{":event-type", String("AudioEvent")},
		{":message-type", String("event")},
		{"Content-Type", String("application/x-amz-json-1.1")},
	}
	if len(m.Headers) != len(want) {
		t.Fatalf("headers %v", m.Headers)
	}
	for i, h := range want {
		if m.Headers[i].Name != h.Name || !m.Headers[i].Value.Equal(h.Value) {
			t.Fatalf("header %d = %s %v, want %s %v", i, m.Headers[i].Name, m.Headers[i].Value, h.Name, h.Value)
		}
	}
	if !bytes.HasPrefix(m.Payload, []byte("RIFF")) || len(m.Payload) != 64 {
		t.Fatalf("payload %q", m.Payload)
	}
	out, err := Marshal(*m)
	if err != nil || !bytes.Equal(out, fix) {
		t.Fatalf("re-encode differs: %v", err)
	}
}
