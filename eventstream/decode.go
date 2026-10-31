// Package eventstream decodes (and, for tests and tools, encodes) the AWS
// event-stream binary framing used by streaming AWS APIs.
//
// Wire format, from the "Event stream encoding" section of the Amazon
// Transcribe streaming guide
// (https://docs.aws.amazon.com/transcribe/latest/dg/streaming-setting-up.html)
// and the reference implementation
// (https://github.com/aws/aws-sdk-go-v2/tree/main/aws/protocol/eventstream:
// message.go, header_value.go, decode.go):
//
//	total_len u32 | headers_len u32 | prelude_crc u32 | headers | payload | message_crc u32
//
// all big-endian. prelude_crc is the CRC-32 (IEEE) of the first 8 bytes;
// message_crc is the CRC-32 (IEEE) of every byte before it. Each header is
// name_len u8 | name | type u8 | value, see [Type].
//
// The decoder is strict where the reference is lax: the reference
// ValidateLens only rejects total_len == 0, and its PayloadLen() =
// total_len - headers_len - 16 underflows a uint32 when total_len <
// headers_len + 16. Here every length is checked, in this order: prelude
// bounds, prelude CRC (before anything is allocated), the header block,
// the message CRC.
package eventstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"unicode/utf8"
)

const (
	preludeLen  = 12 // total_len + headers_len + prelude_crc
	overhead    = 16 // prelude + message_crc
	maxWireName = 255
)

// Errors returned by the decoder (wrapped with detail; test with errors.Is).
var (
	// ErrLength: total_len or headers_len is inconsistent.
	ErrLength = errors.New("eventstream: invalid length")
	// ErrLimit: a configured [Limits] value is exceeded.
	ErrLimit = errors.New("eventstream: limit exceeded")
	// ErrPreludeCRC: the prelude checksum does not match.
	ErrPreludeCRC = errors.New("eventstream: prelude checksum mismatch")
	// ErrMessageCRC: the message checksum does not match.
	ErrMessageCRC = errors.New("eventstream: message checksum mismatch")
	// ErrHeader: a malformed header block.
	ErrHeader = errors.New("eventstream: invalid header")
)

// Limits bounds what a Decoder accepts. A zero or negative field takes its
// default.
type Limits struct {
	MaxMessage    int // total message size, default 16 MiB
	MaxHeadersLen int // size of the header block, default 128 KiB
	MaxHeaders    int // number of headers, default 256
	MaxValueLen   int // bytes/string header value, default and maximum 32767
}

// Default limits.
const (
	DefaultMaxMessage    = 16 << 20
	DefaultMaxHeadersLen = 128 << 10
	DefaultMaxHeaders    = 256
	DefaultMaxValueLen   = 1<<15 - 1
)

func (l Limits) norm() Limits {
	if l.MaxMessage <= 0 {
		l.MaxMessage = DefaultMaxMessage
	}
	if l.MaxHeadersLen <= 0 {
		l.MaxHeadersLen = DefaultMaxHeadersLen
	}
	if l.MaxHeaders <= 0 {
		l.MaxHeaders = DefaultMaxHeaders
	}
	if l.MaxValueLen <= 0 {
		l.MaxValueLen = DefaultMaxValueLen
	}
	// The wire length of a value is a u16; total_len is a u32 (int is 32 bits
	// on some targets: never let a limit exceed what int can hold).
	l.MaxValueLen = min(l.MaxValueLen, math.MaxUint16)
	l.MaxMessage = min(l.MaxMessage, math.MaxInt32)
	l.MaxHeadersLen = min(l.MaxHeadersLen, l.MaxMessage-overhead)
	return l
}

// Decoder reads messages from a stream. It is not safe for concurrent use.
type Decoder struct {
	r      io.Reader
	lim    Limits
	err    error
	intern map[string]string
}

// NewDecoder returns a Decoder reading from r under limits.
func NewDecoder(r io.Reader, limits Limits) *Decoder {
	return &Decoder{r: r, lim: limits.norm()}
}

// Next reads the next message. It returns io.EOF at a clean message
// boundary, io.ErrUnexpectedEOF inside a message, and an error wrapping one
// of the Err* values for malformed input. After an error other than io.EOF
// the stream is desynchronised and Next keeps returning that error.
//
// The returned Message and its Payload are owned by the caller.
func (d *Decoder) Next() (*Message, error) {
	if d.err != nil {
		return nil, d.err
	}
	m, err := d.next()
	if err != nil {
		d.err = err
		return nil, err
	}
	return m, nil
}

func (d *Decoder) next() (*Message, error) {
	var pre [preludeLen]byte
	if _, err := io.ReadFull(d.r, pre[:]); err != nil {
		return nil, err // io.EOF only if zero bytes were read
	}
	total := binary.BigEndian.Uint32(pre[0:4])
	hl := binary.BigEndian.Uint32(pre[4:8])

	// 1. prelude bounds (uint64 arithmetic: no overflow on any target).
	switch {
	case total < overhead:
		return nil, fmt.Errorf("%w: total length %d < %d", ErrLength, total, overhead)
	case uint64(hl)+overhead > uint64(total):
		return nil, fmt.Errorf("%w: headers length %d does not fit in total length %d", ErrLength, hl, total)
	case uint64(total) > uint64(d.lim.MaxMessage):
		return nil, fmt.Errorf("%w: message of %d bytes (max %d)", ErrLimit, total, d.lim.MaxMessage)
	case uint64(hl) > uint64(d.lim.MaxHeadersLen):
		return nil, fmt.Errorf("%w: headers of %d bytes (max %d)", ErrLimit, hl, d.lim.MaxHeadersLen)
	}
	// 2. prelude CRC, before the body is allocated.
	if crc32.ChecksumIEEE(pre[0:8]) != binary.BigEndian.Uint32(pre[8:12]) {
		return nil, ErrPreludeCRC
	}

	// Read the rest. The buffer grows with the bytes actually received, so a
	// peer that announces 16 MiB and sends nothing costs us nothing.
	body, err := readBody(d.r, int(total)-preludeLen)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	// 3. headers parse exactly to headers_len.
	hdrs, err := d.parseHeaders(body[:hl])
	if err != nil {
		return nil, err
	}
	// 4. message CRC.
	n := len(body) - 4
	sum := crc32.Update(crc32.ChecksumIEEE(pre[:]), crc32.IEEETable, body[:n])
	if sum != binary.BigEndian.Uint32(body[n:]) {
		return nil, ErrMessageCRC
	}
	return &Message{Headers: hdrs, Payload: body[hl:n:n]}, nil
}

const chunk = 64 << 10

// readBody reads exactly n bytes without trusting n for the allocation.
func readBody(r io.Reader, n int) ([]byte, error) {
	if n <= chunk {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	b := make([]byte, 0, chunk)
	for len(b) < n {
		if len(b) == cap(b) {
			nc := min(2*cap(b), n)
			nb := make([]byte, len(b), nc)
			copy(nb, b)
			b = nb
		}
		want := min(cap(b), n) - len(b)
		m, err := io.ReadFull(r, b[len(b):len(b)+want])
		b = b[:len(b)+m]
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (d *Decoder) str(b []byte) string {
	if len(b) > 64 {
		return string(b)
	}
	if s, ok := d.intern[string(b)]; ok {
		return s
	}
	s := string(b)
	if d.intern == nil {
		d.intern = make(map[string]string)
	}
	if len(d.intern) < 256 {
		d.intern[s] = s
	}
	return s
}

func (d *Decoder) parseHeaders(b []byte) ([]Header, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var hs []Header
	for p := 0; p < len(b); {
		if len(hs) >= d.lim.MaxHeaders {
			return nil, fmt.Errorf("%w: more than %d headers", ErrLimit, d.lim.MaxHeaders)
		}
		nl := int(b[p])
		p++
		if nl == 0 {
			return nil, fmt.Errorf("%w: empty header name", ErrHeader)
		}
		if p+nl+1 > len(b) {
			return nil, fmt.Errorf("%w: header name runs past the header block", ErrHeader)
		}
		// The key "is a UTF-8 string" (Transcribe guide); a caller compares
		// names as text, so an invalid one is refused like an invalid value.
		if !utf8.Valid(b[p : p+nl]) {
			return nil, fmt.Errorf("%w: header name is not valid UTF-8", ErrHeader)
		}
		name := d.str(b[p : p+nl])
		p += nl
		t := Type(b[p])
		p++
		var v Value
		switch t {
		case TypeTrue, TypeFalse:
			v = Bool(t == TypeTrue)
		case TypeInt8, TypeInt16, TypeInt32, TypeInt64, TypeTimestamp:
			sz := 8
			switch t {
			case TypeInt8:
				sz = 1
			case TypeInt16:
				sz = 2
			case TypeInt32:
				sz = 4
			}
			if p+sz > len(b) {
				return nil, fmt.Errorf("%w: %q value runs past the header block", ErrHeader, name)
			}
			var u uint64
			for _, c := range b[p : p+sz] {
				u = u<<8 | uint64(c)
			}
			p += sz
			// sign-extend big-endian two's complement
			n := int64(u<<(64-8*uint(sz))) >> (64 - 8*uint(sz))
			v = Value{set: true, t: t, n: n}
		case TypeBytes, TypeString:
			if p+2 > len(b) {
				return nil, fmt.Errorf("%w: %q value runs past the header block", ErrHeader, name)
			}
			vl := int(binary.BigEndian.Uint16(b[p:]))
			p += 2
			if vl > d.lim.MaxValueLen {
				return nil, fmt.Errorf("%w: header %q value of %d bytes (max %d)", ErrLimit, name, vl, d.lim.MaxValueLen)
			}
			if p+vl > len(b) {
				return nil, fmt.Errorf("%w: %q value runs past the header block", ErrHeader, name)
			}
			raw := b[p : p+vl]
			p += vl
			if t == TypeString {
				if !utf8.Valid(raw) {
					return nil, fmt.Errorf("%w: header %q is not valid UTF-8", ErrHeader, name)
				}
				v = Value{set: true, t: t, s: d.str(raw)}
			} else {
				v = Value{set: true, t: t, b: append([]byte{}, raw...)}
			}
		case TypeUUID:
			if p+16 > len(b) {
				return nil, fmt.Errorf("%w: %q value runs past the header block", ErrHeader, name)
			}
			v = Value{set: true, t: t, b: append([]byte{}, b[p:p+16]...)}
			p += 16
		default:
			return nil, fmt.Errorf("%w: header %q has unknown type %d", ErrHeader, name, uint8(t))
		}
		for i := range hs {
			if hs[i].Name == name {
				return nil, fmt.Errorf("%w: duplicate header %q", ErrHeader, name)
			}
		}
		hs = append(hs, Header{Name: name, Value: v})
	}
	return hs, nil
}
