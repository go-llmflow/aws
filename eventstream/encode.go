package eventstream

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"unicode/utf8"
)

// Marshal returns the wire form of m. It rejects what the decoder would:
// an empty or over-long (>255) header name, a duplicate name, an invalid
// Value, a bytes/string value over 32767 bytes, a string that is not UTF-8,
// and a message whose size does not fit a u32.
func Marshal(m Message) ([]byte, error) {
	hl := 0
	for i, h := range m.Headers {
		if h.Name == "" || len(h.Name) > maxWireName {
			return nil, fmt.Errorf("%w: header name of %d bytes", ErrHeader, len(h.Name))
		}
		for j := 0; j < i; j++ {
			if m.Headers[j].Name == h.Name {
				return nil, fmt.Errorf("%w: duplicate header %q", ErrHeader, h.Name)
			}
		}
		n, err := valueSize(h)
		if err != nil {
			return nil, err
		}
		hl += 1 + len(h.Name) + n // name_len, name, then type byte + value (n)
	}
	if uint64(hl)+uint64(len(m.Payload))+overhead > math.MaxInt32 {
		return nil, fmt.Errorf("%w: message too large", ErrLength)
	}
	total := overhead + hl + len(m.Payload)
	b := make([]byte, preludeLen, total)
	binary.BigEndian.PutUint32(b[0:], uint32(total))
	binary.BigEndian.PutUint32(b[4:], uint32(hl))
	binary.BigEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[:8]))
	for _, h := range m.Headers {
		b = append(b, byte(len(h.Name)))
		b = append(b, h.Name...)
		v := h.Value
		b = append(b, byte(v.t))
		switch v.t {
		case TypeInt8:
			b = append(b, byte(v.n))
		case TypeInt16:
			b = binary.BigEndian.AppendUint16(b, uint16(v.n))
		case TypeInt32:
			b = binary.BigEndian.AppendUint32(b, uint32(v.n))
		case TypeInt64, TypeTimestamp:
			b = binary.BigEndian.AppendUint64(b, uint64(v.n))
		case TypeString:
			b = binary.BigEndian.AppendUint16(b, uint16(len(v.s)))
			b = append(b, v.s...)
		case TypeBytes:
			b = binary.BigEndian.AppendUint16(b, uint16(len(v.b)))
			b = append(b, v.b...)
		case TypeUUID:
			b = append(b, v.b...)
		}
	}
	b = append(b, m.Payload...)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b)), nil
}

func valueSize(h Header) (int, error) {
	v := h.Value
	if !v.set {
		return 0, fmt.Errorf("%w: header %q has no value", ErrHeader, h.Name)
	}
	switch v.t {
	case TypeTrue, TypeFalse:
		return 1, nil
	case TypeInt8:
		return 2, nil
	case TypeInt16:
		return 3, nil
	case TypeInt32:
		return 5, nil
	case TypeInt64, TypeTimestamp:
		return 9, nil
	case TypeString:
		if len(v.s) > DefaultMaxValueLen {
			return 0, fmt.Errorf("%w: header %q value of %d bytes", ErrLimit, h.Name, len(v.s))
		}
		if !utf8.ValidString(v.s) {
			return 0, fmt.Errorf("%w: header %q is not valid UTF-8", ErrHeader, h.Name)
		}
		return 3 + len(v.s), nil
	case TypeBytes:
		if len(v.b) > DefaultMaxValueLen {
			return 0, fmt.Errorf("%w: header %q value of %d bytes", ErrLimit, h.Name, len(v.b))
		}
		return 3 + len(v.b), nil
	case TypeUUID:
		if len(v.b) != 16 {
			return 0, fmt.Errorf("%w: header %q uuid is %d bytes", ErrHeader, h.Name, len(v.b))
		}
		return 17, nil
	}
	return 0, fmt.Errorf("%w: header %q has unknown type %d", ErrHeader, h.Name, uint8(v.t))
}

// Encode writes the wire form of m to w in a single Write. Intended for
// tests and tools; see [Marshal] for what it rejects.
func Encode(w io.Writer, m Message) error {
	b, err := Marshal(m)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
