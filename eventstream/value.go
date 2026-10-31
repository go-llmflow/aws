package eventstream

import (
	"fmt"
	"strconv"
	"time"
)

// Type is the wire type of a header value. The numbers are the ones on the
// wire (see the "Event stream encoding" table of the Amazon Transcribe
// streaming guide, and header_value.go of aws-sdk-go-v2).
type Type uint8

// Header value types.
const (
	TypeTrue      Type = 0 // boolean true, no value bytes
	TypeFalse     Type = 1 // boolean false, no value bytes
	TypeInt8      Type = 2
	TypeInt16     Type = 3
	TypeInt32     Type = 4
	TypeInt64     Type = 5
	TypeBytes     Type = 6 // u16 length, then data
	TypeString    Type = 7 // u16 length, then UTF-8 data
	TypeTimestamp Type = 8 // int64 milliseconds since the Unix epoch
	TypeUUID      Type = 9 // 16 raw bytes
)

func (t Type) String() string {
	switch t {
	case TypeTrue, TypeFalse:
		return "bool"
	case TypeInt8:
		return "int8"
	case TypeInt16:
		return "int16"
	case TypeInt32:
		return "int32"
	case TypeInt64:
		return "int64"
	case TypeBytes:
		return "bytes"
	case TypeString:
		return "string"
	case TypeTimestamp:
		return "timestamp"
	case TypeUUID:
		return "uuid"
	}
	return "unknown(" + strconv.Itoa(int(t)) + ")"
}

// Value is a typed header value. The zero Value is invalid (Valid reports
// false) and cannot be encoded; build values with the constructors.
type Value struct {
	set bool
	t   Type
	n   int64  // bool (0/1), ints, timestamp milliseconds
	s   string // TypeString
	b   []byte // TypeBytes, TypeUUID
}

// Bool returns a boolean value.
func Bool(v bool) Value {
	if v {
		return Value{set: true, t: TypeTrue, n: 1}
	}
	return Value{set: true, t: TypeFalse}
}

// Int8 returns an int8 value.
func Int8(v int8) Value { return Value{set: true, t: TypeInt8, n: int64(v)} }

// Int16 returns an int16 value.
func Int16(v int16) Value { return Value{set: true, t: TypeInt16, n: int64(v)} }

// Int32 returns an int32 value.
func Int32(v int32) Value { return Value{set: true, t: TypeInt32, n: int64(v)} }

// Int64 returns an int64 value.
func Int64(v int64) Value { return Value{set: true, t: TypeInt64, n: v} }

// Bytes returns a byte-array value. The slice is not copied.
func Bytes(v []byte) Value { return Value{set: true, t: TypeBytes, b: v} }

// String returns a string value.
func String(v string) Value { return Value{set: true, t: TypeString, s: v} }

// TimestampMillis returns a timestamp value from milliseconds since the Unix
// epoch, the exact wire quantity.
func TimestampMillis(ms int64) Value { return Value{set: true, t: TypeTimestamp, n: ms} }

// Timestamp returns a timestamp value, truncated to milliseconds.
func Timestamp(t time.Time) Value { return TimestampMillis(t.UnixMilli()) }

// UUID returns a UUID value.
func UUID(id [16]byte) Value {
	b := make([]byte, 16)
	copy(b, id[:])
	return Value{set: true, t: TypeUUID, b: b}
}

// Valid reports whether v was built by a constructor or a decoder.
func (v Value) Valid() bool { return v.set }

// Type returns the wire type; meaningful only if Valid.
func (v Value) Type() Type { return v.t }

// Bool returns the boolean; false for other types.
func (v Value) Bool() bool { return v.set && v.t == TypeTrue }

// Int returns the integer of an int8/16/32/64 value or the milliseconds of a
// timestamp; 0 for other types.
func (v Value) Int() int64 {
	switch v.t {
	case TypeInt8, TypeInt16, TypeInt32, TypeInt64, TypeTimestamp:
		return v.n
	}
	return 0
}

// Str returns the string of a TypeString value, "" for other types.
func (v Value) Str() string {
	if v.t == TypeString {
		return v.s
	}
	return ""
}

// Bytes returns the data of a TypeBytes value, nil for other types. The slice
// is owned by the value; do not modify it.
func (v Value) Bytes() []byte {
	if v.t == TypeBytes {
		return v.b
	}
	return nil
}

// Time returns the instant of a timestamp value (UTC); the zero time for
// other types.
func (v Value) Time() time.Time {
	if v.t == TypeTimestamp {
		return time.UnixMilli(v.n).UTC()
	}
	return time.Time{}
}

// UUID returns the 16 bytes of a UUID value; zero for other types.
func (v Value) UUID() (id [16]byte) {
	if v.t == TypeUUID {
		copy(id[:], v.b)
	}
	return id
}

// Equal reports whether two values have the same type and content.
func (v Value) Equal(o Value) bool {
	if v.set != o.set || v.t != o.t || v.n != o.n || v.s != o.s || len(v.b) != len(o.b) {
		return false
	}
	for i := range v.b {
		if v.b[i] != o.b[i] {
			return false
		}
	}
	return true
}

// String renders the value for humans.
func (v Value) String() string {
	if !v.set {
		return "<invalid>"
	}
	switch v.t {
	case TypeTrue:
		return "true"
	case TypeFalse:
		return "false"
	case TypeInt8, TypeInt16, TypeInt32, TypeInt64:
		return strconv.FormatInt(v.n, 10)
	case TypeString:
		return strconv.Quote(v.s)
	case TypeBytes:
		return fmt.Sprintf("%x", v.b)
	case TypeTimestamp:
		return v.Time().Format(time.RFC3339Nano)
	case TypeUUID:
		b := v.b
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}
	return "<invalid>"
}

// Header is a named, typed header of a Message.
type Header struct {
	Name  string
	Value Value
}

// Message is one decoded event-stream message.
type Message struct {
	Headers []Header
	Payload []byte
}

// Header returns the value of the named header.
func (m *Message) Header(name string) (Value, bool) {
	for i := range m.Headers {
		if m.Headers[i].Name == name {
			return m.Headers[i].Value, true
		}
	}
	return Value{}, false
}

// Equal reports whether two messages have identical headers (in order) and
// payload.
func (m Message) Equal(o Message) bool {
	if len(m.Headers) != len(o.Headers) || len(m.Payload) != len(o.Payload) {
		return false
	}
	for i := range m.Headers {
		if m.Headers[i].Name != o.Headers[i].Name || !m.Headers[i].Value.Equal(o.Headers[i].Value) {
			return false
		}
	}
	for i := range m.Payload {
		if m.Payload[i] != o.Payload[i] {
			return false
		}
	}
	return true
}
