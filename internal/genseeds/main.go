// Command genseeds writes the committed fuzz corpus seeds for FuzzDecode
// (eventstream) and FuzzSign (sigv4). Run from the repository root:
//
//	go run ./internal/genseeds
//
// Seeds are the golden messages, one message per header type, and one
// planted rejection each (bad lengths, bad CRCs, truncation), plus the
// request shapes of the SigV4 test suite.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-llmflow/aws/eventstream"
)

func write(dir, name string, lines ...string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte("go test fuzz v1\n"+strings.Join(lines, "\n")+"\n"), 0o644)
}

func bytesLine(b []byte) string { return "[]byte(" + strconv.Quote(string(b)) + ")" }

func prelude(total, hl uint32) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b, total)
	binary.BigEndian.PutUint32(b[4:], hl)
	binary.BigEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[:8]))
	return b
}

func run() error {
	dec := filepath.Join("eventstream", "testdata", "fuzz", "FuzzDecode")
	var id [16]byte
	for i := range id {
		id[i] = byte(i)
	}
	all, err := eventstream.Marshal(eventstream.Message{
		Headers: []eventstream.Header{
			{Name: "t", Value: eventstream.Bool(true)}, {Name: "f", Value: eventstream.Bool(false)},
			{Name: "i8", Value: eventstream.Int8(-1)}, {Name: "i16", Value: eventstream.Int16(-2)},
			{Name: "i32", Value: eventstream.Int32(-3)}, {Name: "i64", Value: eventstream.Int64(-4)},
			{Name: "b", Value: eventstream.Bytes([]byte{1, 2})}, {Name: "s", Value: eventstream.String("héllo")},
			{Name: "ts", Value: eventstream.Timestamp(time.Unix(1548726977, 291e6))}, {Name: "u", Value: eventstream.UUID(id)},
		},
		Payload: []byte(`{"bytes":"e30="}`),
	})
	if err != nil {
		return err
	}
	empty, _ := eventstream.Marshal(eventstream.Message{})
	event, _ := eventstream.Marshal(eventstream.Message{
		Headers: []eventstream.Header{
			{Name: ":event-type", Value: eventstream.String("chunk")},
			{Name: ":content-type", Value: eventstream.String("application/json")},
			{Name: ":message-type", Value: eventstream.String("event")},
		},
		Payload: []byte(`{"bytes":"eyJ0eXBlIjoibWVzc2FnZV9zdGFydCJ9"}`),
	})
	sig, err := base64.StdEncoding.DecodeString("AAAAUwAAAEP1RHpYBTpkYXRlCAAAAWiXUkMLEDpjaHVuay1zaWduYXR1cmUGACCt6Zy+uymwEK2SrLp/zVBI5eGn83jdBwCaRUBJA+eaDafqjqI=")
	if err != nil {
		return err
	}
	flip := func(b []byte, i int) []byte { c := append([]byte{}, b...); c[i] ^= 0xff; return c }
	seeds := map[string][]byte{
		"all-types":               all,
		"empty":                   empty,
		"bedrock-style-event":     event,
		"page-chunk-signature":    sig,
		"two-messages":            append(append([]byte{}, event...), empty...),
		"underflow-20-100":        prelude(20, 100),
		"total-below-16":          prelude(15, 0),
		"total-max-u32":           prelude(0xffffffff, 0),
		"headers-len-max-u32":     prelude(1<<20, 0xffffffff),
		"bad-prelude-crc":         flip(event, 9),
		"bad-message-crc":         flip(event, len(event)-1),
		"truncated-mid-headers":   event[:30],
		"truncated-before-crc":    event[:len(event)-2],
		"truncated-prelude":       event[:5],
		"announced-16MiB-no-body": append(prelude(16<<20, 0), make([]byte, 40)...),
	}
	for name, b := range seeds {
		if err := write(dec, name, bytesLine(b)); err != nil {
			return err
		}
	}

	sign := filepath.Join("sigv4", "testdata", "fuzz", "FuzzSign")
	type s struct {
		method, url, hn, hv string
		body                []byte
		unix                int64
		service             string
	}
	for name, c := range map[string]s{
		"vanilla":           {"GET", "https://example.amazonaws.com/", "", "", nil, 1440938160, "service"},
		"query-order":       {"GET", "https://example.amazonaws.com/?Param-3=Value3&Param=Value2&%E1%88%B4=Value1", "", "", nil, 1440938160, "service"},
		"header-trim":       {"GET", "https://example.amazonaws.com/", "My-Header2", "  \"a   b   c\"  ", nil, 1440938160, "service"},
		"dots-and-slashes":  {"GET", "https://example.amazonaws.com//example//../x/./", "", "", nil, 1440938160, "service"},
		"post-form":         {"POST", "https://example.amazonaws.com/", "Content-Type", "application/x-www-form-urlencoded; charset=utf-8", []byte("Param1=value1"), 1440938160, "service"},
		"s3":                {"PUT", "https://h/a%20b//c/../d", "X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD", []byte("x"), 0, "s3"},
		"bad-query-escape":  {"GET", "https://h/?a=%zz", "", "", nil, 1, "bedrock"},
		"header-newline":    {"GET", "https://h/", "X-A", "1\nx-amz-forged:yes", nil, -1, "bedrock"},
		"bedrock-model-arn": {"POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fx/converse-stream", "Content-Type", "application/json", []byte("{}"), 1761913200, "bedrock"},
	} {
		if err := write(sign, name,
			"string("+strconv.Quote(c.method)+")", "string("+strconv.Quote(c.url)+")",
			"string("+strconv.Quote(c.hn)+")", "string("+strconv.Quote(c.hv)+")",
			bytesLine(c.body), fmt.Sprintf("int64(%d)", c.unix), "string("+strconv.Quote(c.service)+")"); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
