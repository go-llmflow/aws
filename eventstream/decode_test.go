package eventstream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// --- builders -------------------------------------------------------------

func hdr(name string, typ byte, val ...byte) []byte {
	return append(append([]byte{byte(len(name))}, name...), append([]byte{typ}, val...)...)
}

func hstr(name, v string) []byte {
	return hdr(name, 7, append([]byte{byte(len(v) >> 8), byte(len(v))}, v...)...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// frame builds a message with every length and CRC correct.
func frame(headers, payload []byte) []byte {
	total := 16 + len(headers) + len(payload)
	b := make([]byte, 12, total)
	binary.BigEndian.PutUint32(b, uint32(total))
	binary.BigEndian.PutUint32(b[4:], uint32(len(headers)))
	binary.BigEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[:8]))
	b = append(b, headers...)
	b = append(b, payload...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
}

// prelude builds only a 12-byte prelude with a valid prelude CRC.
func prelude(total, hl uint32) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b, total)
	binary.BigEndian.PutUint32(b[4:], hl)
	binary.BigEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[:8]))
	return b
}

// --- rejections: one planted case each ------------------------------------

func TestRejections(t *testing.T) {
	good := frame(hstr(":a", "b"), []byte("payload"))
	flip := func(b []byte, i int) []byte {
		c := append([]byte{}, b...)
		c[i] ^= 0xff
		return c
	}
	cases := []struct {
		name string
		in   []byte
		lim  Limits
		want error
	}{
		{"total below minimum", prelude(15, 0), Limits{}, ErrLength},
		{"total zero", prelude(0, 0), Limits{}, ErrLength},
		// The reference's PayloadLen() = Length - HeadersLen - 16 underflows
		// a uint32 here (20 - 100 - 16); it only rejects Length == 0.
		{"total below headers_len+16 (reference underflow)", prelude(20, 100), Limits{}, ErrLength},
		{"headers_len = MaxUint32", prelude(1<<20, 0xffffffff), Limits{}, ErrLength},
		{"total MaxUint32, headers 0", prelude(0xffffffff, 0), Limits{}, ErrLimit},
		{"total above MaxMessage", prelude(1000, 0), Limits{MaxMessage: 999}, ErrLimit},
		{"headers_len above MaxHeadersLen", prelude(1000, 600), Limits{MaxHeadersLen: 500}, ErrLimit},
		{"prelude CRC", flip(good, 8), Limits{}, ErrPreludeCRC},
		{"prelude length flipped, CRC stale", flip(good, 3), Limits{}, ErrPreludeCRC},
		{"message CRC", flip(good, len(good)-1), Limits{}, ErrMessageCRC},
		{"payload flipped", flip(good, len(good)-6), Limits{}, ErrMessageCRC},
		{"duplicate header", frame(cat(hstr(":a", "1"), hstr(":a", "2")), nil), Limits{}, ErrHeader},
		{"duplicate header, different types", frame(cat(hstr(":a", "1"), hdr(":a", 0)), nil), Limits{}, ErrHeader},
		{"unknown type 10", frame(hdr(":a", 10), nil), Limits{}, ErrHeader},
		{"unknown type 255", frame(hdr(":a", 255), nil), Limits{}, ErrHeader},
		{"name_len 0", frame([]byte{0, 0}, nil), Limits{}, ErrHeader},
		{"string not UTF-8", frame(hdr(":a", 7, 0, 2, 0xc3, 0x28), nil), Limits{}, ErrHeader},
		{"string overlong UTF-8", frame(hdr(":a", 7, 0, 2, 0xc0, 0x80), nil), Limits{}, ErrHeader},
		{"name runs past headers_len", frame([]byte{9, 'a', 'b'}, nil), Limits{}, ErrHeader},
		{"missing type byte", frame([]byte{1, 'a'}, nil), Limits{}, ErrHeader},
		{"int32 runs past headers_len", frame(hdr(":a", 4, 0, 0), nil), Limits{}, ErrHeader},
		{"int64 runs past headers_len", frame(hdr(":a", 5, 0, 0, 0, 0), nil), Limits{}, ErrHeader},
		{"timestamp runs past headers_len", frame(hdr(":a", 8, 0), nil), Limits{}, ErrHeader},
		{"uuid runs past headers_len", frame(hdr(":a", 9, make([]byte, 15)...), nil), Limits{}, ErrHeader},
		{"string length field cut", frame(hdr(":a", 7, 0), nil), Limits{}, ErrHeader},
		{"string runs past headers_len", frame(hdr(":a", 7, 0, 9, 'x'), nil), Limits{}, ErrHeader},
		{"bytes runs past headers_len", frame(hdr(":a", 6, 0xff, 0xff, 'x'), nil), Limits{}, ErrLimit},
		{"value past headers_len but inside payload", func() []byte {
			// headers_len says 4 but the string value needs 6 bytes; the
			// bytes exist in the message (they are payload), yet are out of bounds.
			h := hdr(":", 7, 0, 3, 'a', 'b', 'c') // 1+1+1+2+3 = 8 bytes
			b := frame(h, nil)
			binary.BigEndian.PutUint32(b[4:], 6) // headers_len 6 (cuts the value)
			binary.BigEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[:8]))
			return b
		}(), Limits{}, ErrHeader},
		{"value above MaxValueLen", frame(hstr(":a", strings.Repeat("x", 11)), nil), Limits{MaxValueLen: 10}, ErrLimit},
		{"too many headers", frame(cat(hdr("a", 0), hdr("b", 0), hdr("c", 1)), nil), Limits{MaxHeaders: 2}, ErrLimit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := decodeOne(t, c.in, c.lim)
			if m != nil || !errors.Is(err, c.want) {
				t.Fatalf("got %v, %v; want %v", m, err, c.want)
			}
		})
	}
}

func TestMaxValueLenAtBoundary(t *testing.T) {
	v := strings.Repeat("x", 10)
	m, err := decodeOne(t, frame(hstr(":a", v), nil), Limits{MaxValueLen: 10})
	if err != nil || m.Headers[0].Value.Str() != v {
		t.Fatal(err)
	}
	// the default is 32767, and 32768 does not pass it
	big := strings.Repeat("y", 32767)
	if _, err = decodeOne(t, frame(hstr(":a", big), nil), Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err = decodeOne(t, frame(hstr(":a", big+"y"), nil), Limits{}); !errors.Is(err, ErrLimit) {
		t.Fatalf("32768: %v", err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// The prelude CRC is checked before the body is read or allocated.
func TestPreludeCRCBeforeBody(t *testing.T) {
	b := frame(nil, make([]byte, 1000))
	b[10] ^= 1
	cr := &countingReader{r: bytes.NewReader(b)}
	if _, err := NewDecoder(cr, Limits{}).Next(); !errors.Is(err, ErrPreludeCRC) {
		t.Fatal(err)
	}
	if cr.n != 12 {
		t.Fatalf("read %d bytes before rejecting, want 12", cr.n)
	}
}

// A peer that announces the largest message and sends nothing costs us
// nothing: the buffer grows with the bytes received.
func TestLyingLengthDoesNotAllocate(t *testing.T) {
	in := cat(prelude(DefaultMaxMessage, 0), make([]byte, 100))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := decodeOne(t, in, Limits{})
	runtime.ReadMemStats(&after)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Fatalf("allocated %d bytes for a 100-byte stream", got)
	}
}

// --- EOF ------------------------------------------------------------------

func TestEOF(t *testing.T) {
	good := frame(hstr(":a", "b"), []byte("xyz"))
	d := NewDecoder(bytes.NewReader(cat(good, good)), Limits{})
	for i := 0; i < 2; i++ {
		if _, err := d.Next(); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := d.Next(); err != io.EOF {
		t.Fatalf("clean boundary: %v", err)
	}
	if _, err := d.Next(); err != io.EOF {
		t.Fatalf("EOF is sticky: %v", err)
	}
	if _, err := NewDecoder(bytes.NewReader(nil), Limits{}).Next(); err != io.EOF {
		t.Fatal(err)
	}
	// truncated at every possible offset inside one message
	for n := 1; n < len(good); n++ {
		_, err := NewDecoder(bytes.NewReader(good[:n]), Limits{}).Next()
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("cut at %d: %v", n, err)
		}
	}
	// the same through a reader that returns one byte at a time
	m, err := NewDecoder(iotest.OneByteReader(bytes.NewReader(good)), Limits{}).Next()
	if err != nil || string(m.Payload) != "xyz" {
		t.Fatal(err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestReaderErrorPassesThroughAndSticks(t *testing.T) {
	boom := errors.New("boom")
	d := NewDecoder(errReader{boom}, Limits{})
	if _, err := d.Next(); err != boom {
		t.Fatal(err)
	}
	if _, err := d.Next(); err != boom {
		t.Fatal(err)
	}
	// error in the middle of the body
	good := frame(nil, make([]byte, 100))
	_, err := NewDecoder(io.MultiReader(bytes.NewReader(good[:50]), errReader{boom}), Limits{}).Next()
	if err != boom {
		t.Fatal(err)
	}
}

func TestMalformedIsSticky(t *testing.T) {
	d := NewDecoder(bytes.NewReader(cat(prelude(3, 0), frame(nil, nil))), Limits{})
	_, err1 := d.Next()
	_, err2 := d.Next()
	if !errors.Is(err1, ErrLength) || err1 != err2 {
		t.Fatal(err1, err2)
	}
}

// --- values, round trip ---------------------------------------------------

func allTypes() Message {
	var id [16]byte
	for i := range id {
		id[i] = byte(i * 17)
	}
	return Message{
		Headers: []Header{
			{"t", Bool(true)}, {"f", Bool(false)},
			{"i8", Int8(-128)}, {"i8p", Int8(127)},
			{"i16", Int16(-32768)}, {"i32", Int32(-2147483648)},
			{"i64", Int64(-9223372036854775808)}, {"i64p", Int64(9223372036854775807)},
			{"b", Bytes([]byte{0, 1, 2})}, {"b0", Bytes([]byte{})},
			{"s", String("héllo ☃")}, {"s0", String("")},
			{"ts", Timestamp(time.Date(2026, 10, 31, 22, 0, 0, 123e6, time.UTC))},
			{"tsneg", TimestampMillis(-1)},
			{"u", UUID(id)},
		},
		Payload: []byte(`{"k":"v"}`),
	}
}

func TestRoundTripAllTypes(t *testing.T) {
	in := allTypes()
	var buf bytes.Buffer
	if err := Encode(&buf, in); err != nil {
		t.Fatal(err)
	}
	wire := buf.Bytes()
	out, err := decodeOne(t, wire, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Equal(in) {
		t.Fatalf("round trip:\n in %v\nout %v", in.Headers, out.Headers)
	}
	again, err := Marshal(*out)
	if err != nil || !bytes.Equal(again, wire) {
		t.Fatal("re-encode differs", err)
	}
	// accessors
	g := func(n string) Value { v, _ := out.Header(n); return v }
	if !g("t").Bool() || g("f").Bool() || g("i8").Int() != -128 || g("i16").Int() != -32768 ||
		g("i32").Int() != -2147483648 || g("i64").Int() != -9223372036854775808 ||
		!bytes.Equal(g("b").Bytes(), []byte{0, 1, 2}) || g("s").Str() != "héllo ☃" ||
		!g("ts").Time().Equal(time.Date(2026, 10, 31, 22, 0, 0, 123e6, time.UTC)) ||
		g("tsneg").Int() != -1 || g("u").UUID()[3] != 51 {
		t.Fatal("accessor mismatch")
	}
	// cross-type accessors are zero
	if g("s").Int() != 0 || g("i8").Str() != "" || g("s").Bytes() != nil || !g("s").Time().IsZero() || g("s").UUID() != [16]byte{} || g("i8").Bool() {
		t.Fatal("cross-type accessor not zero")
	}
	if _, ok := out.Header("nope"); ok {
		t.Fatal("found a header that is not there")
	}
}

func TestMultipleMessagesAndEmpty(t *testing.T) {
	var buf bytes.Buffer
	msgs := []Message{{}, {Payload: []byte("p")}, {Headers: []Header{{"a", Int8(1)}}}, allTypes()}
	for _, m := range msgs {
		if err := Encode(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	d := NewDecoder(&buf, Limits{})
	for i, m := range msgs {
		got, err := d.Next()
		if err != nil || !got.Equal(m) {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := d.Next(); err != io.EOF {
		t.Fatal(err)
	}
}

func TestLargePayloadGrowth(t *testing.T) {
	for _, n := range []int{chunk - 1, chunk, chunk + 1, 3*chunk + 7, 1 << 20} {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(i * 7)
		}
		wire, err := Marshal(Message{Headers: []Header{{"a", String("b")}}, Payload: p})
		if err != nil {
			t.Fatal(err)
		}
		m, err := decodeOne(t, wire, Limits{})
		if err != nil || !bytes.Equal(m.Payload, p) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

func TestPayloadOwnedByCaller(t *testing.T) {
	d := NewDecoder(bytes.NewReader(cat(frame(nil, []byte("one")), frame(nil, []byte("two")))), Limits{})
	a, _ := d.Next()
	b, _ := d.Next()
	if string(a.Payload) != "one" || string(b.Payload) != "two" {
		t.Fatal("messages share memory")
	}
	_ = append(a.Payload, 'X') // must not overwrite the CRC bytes of anything we still use
}

func TestLimitsNormalisation(t *testing.T) {
	l := Limits{MaxValueLen: math.MaxInt, MaxMessage: math.MaxInt, MaxHeadersLen: math.MaxInt}.norm()
	if l.MaxValueLen != 65535 || l.MaxMessage != 1<<31-1 || l.MaxHeadersLen != 1<<31-1-overhead {
		t.Fatalf("%+v", l)
	}
	z := Limits{}.norm()
	if z.MaxMessage != 16<<20 || z.MaxHeadersLen != 128<<10 || z.MaxHeaders != 256 || z.MaxValueLen != 32767 {
		t.Fatalf("%+v", z)
	}
}

func TestInternBounded(t *testing.T) {
	d := NewDecoder(nil, Limits{})
	for i := 0; i < 1000; i++ {
		d.str([]byte{byte(i), byte(i >> 8), 'x'})
	}
	if len(d.intern) > 256 {
		t.Fatal(len(d.intern))
	}
	long := bytes.Repeat([]byte{'z'}, 100)
	if d.str(long) != string(long) || len(d.intern) > 256 {
		t.Fatal("long string")
	}
}

// --- encoder rejections ---------------------------------------------------

func TestMarshalRejects(t *testing.T) {
	big := strings.Repeat("x", 32768)
	cases := []struct {
		name string
		m    Message
		want error
	}{
		{"empty name", Message{Headers: []Header{{"", Int8(1)}}}, ErrHeader},
		{"name of 256", Message{Headers: []Header{{strings.Repeat("n", 256), Int8(1)}}}, ErrHeader},
		{"duplicate", Message{Headers: []Header{{"a", Int8(1)}, {"a", Int8(2)}}}, ErrHeader},
		{"zero Value", Message{Headers: []Header{{"a", Value{}}}}, ErrHeader},
		{"unknown type", Message{Headers: []Header{{"a", Value{set: true, t: 77}}}}, ErrHeader},
		{"string too long", Message{Headers: []Header{{"a", String(big)}}}, ErrLimit},
		{"bytes too long", Message{Headers: []Header{{"a", Bytes([]byte(big))}}}, ErrLimit},
		{"invalid UTF-8", Message{Headers: []Header{{"a", String("\xff")}}}, ErrHeader},
		{"short uuid", Message{Headers: []Header{{"a", Value{set: true, t: TypeUUID, b: []byte{1}}}}}, ErrHeader},
	}
	for _, c := range cases {
		if _, err := Marshal(c.m); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := Encode(io.Discard, Message{Headers: []Header{{"", Int8(1)}}}); err == nil {
		t.Fatal("Encode accepted a bad message")
	}
	if err := Encode(errWriter{}, Message{}); err == nil {
		t.Fatal("write error swallowed")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestValueStringAndTypeString(t *testing.T) {
	var id [16]byte
	for in, want := range map[string]string{
		Bool(true).String(): "true", Bool(false).String(): "false", Int8(-3).String(): "-3",
		String("a\"b").String(): `"a\"b"`, Bytes([]byte{0xab, 1}).String(): "ab01",
		TimestampMillis(0).String(): "1970-01-01T00:00:00Z", UUID(id).String(): "00000000-0000-0000-0000-000000000000",
		Value{}.String(): "<invalid>", Value{set: true, t: 99}.String(): "<invalid>",
	} {
		if in != want {
			t.Errorf("%q != %q", in, want)
		}
	}
	if (Value{}).Valid() || !Int8(1).Valid() {
		t.Fatal("Valid")
	}
	for ty, want := range map[Type]string{TypeTrue: "bool", TypeFalse: "bool", TypeInt8: "int8", TypeInt16: "int16",
		TypeInt32: "int32", TypeInt64: "int64", TypeBytes: "bytes", TypeString: "string", TypeTimestamp: "timestamp",
		TypeUUID: "uuid", 42: "unknown(42)"} {
		if ty.String() != want {
			t.Errorf("%d: %s", ty, ty)
		}
	}
	if (Message{}).Equal(Message{Payload: []byte{1}}) || (Message{Headers: []Header{{"a", Int8(1)}}}).Equal(Message{Headers: []Header{{"a", Int8(2)}}}) ||
		(Message{Headers: []Header{{"a", Int8(1)}}}).Equal(Message{Headers: []Header{{"b", Int8(1)}}}) ||
		(Message{Payload: []byte{1}}).Equal(Message{Payload: []byte{2}}) || Bytes([]byte{1}).Equal(Bytes([]byte{2})) {
		t.Fatal("Equal too lax")
	}
}

// --- fuzz -----------------------------------------------------------------

// FuzzDecode: the decoder never panics, never reads or allocates beyond its
// limits, and everything it accepts re-encodes to exactly the bytes it came from.
func FuzzDecode(f *testing.F) {
	f.Add(frame(nil, nil))
	f.Add(frame(hstr(":event-type", "chunk"), []byte(`{"bytes":"e30="}`)))
	f.Add(prelude(20, 100))
	if wire, err := Marshal(allTypes()); err == nil {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		lim := Limits{MaxMessage: 1 << 20, MaxHeadersLen: 4096, MaxHeaders: 32, MaxValueLen: 1000}
		r := bytes.NewReader(data)
		d := NewDecoder(r, lim)
		for {
			start := len(data) - r.Len()
			m, err := d.Next()
			if err != nil {
				if m != nil {
					t.Fatal("message with error")
				}
				return
			}
			end := len(data) - r.Len()
			if len(m.Payload) > lim.MaxMessage || len(m.Headers) > lim.MaxHeaders {
				t.Fatal("limits exceeded")
			}
			// the 1000-byte value limit is below the encoder's, so Marshal accepts everything decoded
			again, err := Marshal(*m)
			if err != nil {
				t.Fatalf("decoded message does not re-encode: %v", err)
			}
			if !bytes.Equal(again, data[start:end]) {
				t.Fatalf("re-encode differs:\n got %x\nwant %x", again, data[start:end])
			}
		}
	})
}
