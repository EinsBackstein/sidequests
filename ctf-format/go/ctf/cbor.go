package ctf

import (
	"bytes"
	"unicode/utf8"
)

// ValueKind is one of the canonical-CBOR subset's major types (spec §7.1).
type ValueKind uint8

const (
	ValueUint ValueKind = iota
	ValueNint
	ValueBytes
	ValueText
	ValueArray
	ValueMap
	ValueBool
	ValueNull
)

// Value is a decoded canonical CBOR value. Nint stores the CBOR argument n of
// major type 1, whose mathematical value is -1-n, so every value representable
// in the subset round-trips exactly.
type Value struct {
	Kind ValueKind
	U    uint64 // uint argument, nint argument, or 0/1 for bool
	B    []byte
	T    string
	A    []Value
	M    []Pair
}

// Pair is one map entry. Pairs are held in canonical key order.
type Pair struct {
	Key Value
	Val Value
}

func Uint(v uint64) Value  { return Value{Kind: ValueUint, U: v} }
func Nint(v uint64) Value  { return Value{Kind: ValueNint, U: v} }
func Bytes(b []byte) Value { return Value{Kind: ValueBytes, B: b} }
func Text(s string) Value  { return Value{Kind: ValueText, T: s} }
func Array(vs ...Value) Value {
	return Value{Kind: ValueArray, A: vs}
}
func Bool(b bool) Value {
	var u uint64
	if b {
		u = 1
	}
	return Value{Kind: ValueBool, U: u}
}
func Null() Value { return Value{Kind: ValueNull} }

// MapValue builds a map value from pairs. Encode sorts them canonically.
func MapValue(pairs ...Pair) Value { return Value{Kind: ValueMap, M: pairs} }

func (v Value) IsUint() bool  { return v.Kind == ValueUint }
func (v Value) IsText() bool  { return v.Kind == ValueText }
func (v Value) IsBytes() bool { return v.Kind == ValueBytes }
func (v Value) IsArray() bool { return v.Kind == ValueArray }
func (v Value) IsMap() bool   { return v.Kind == ValueMap }

// ---- decoding ----

type cborDecoder struct {
	b   []byte
	pos int
}

func decodeCBOR(b []byte) (Value, error) {
	d := &cborDecoder{b: b}
	v, err := d.value(1)
	if err != nil {
		return Value{}, err
	}
	if d.pos != len(b) {
		return Value{}, errf(CatCBOR, "M1i", "%d trailing bytes after outermost value", len(b)-d.pos)
	}
	return v, nil
}

func (d *cborDecoder) value(depth int) (Value, error) {
	var v Value
	if depth > MaxCBORDepth {
		return v, errf(CatCBOR, "M1h", "nesting exceeds %d", MaxCBORDepth)
	}
	if d.pos >= len(d.b) {
		return v, errf(CatCBOR, "M1i", "input ends inside a value")
	}
	first := d.b[d.pos]
	d.pos++
	major := first >> 5
	ai := first & 0x1f

	var arg uint64
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai == 24:
		if d.pos+1 > len(d.b) {
			return v, errf(CatCBOR, "M1i", "input ends inside an argument")
		}
		arg = uint64(d.b[d.pos])
		d.pos++
		if arg < 24 {
			return v, errf(CatCBOR, "M1c", "non-shortest argument")
		}
	case ai == 25:
		if d.pos+2 > len(d.b) {
			return v, errf(CatCBOR, "M1i", "input ends inside an argument")
		}
		arg = uint64(d.b[d.pos])<<8 | uint64(d.b[d.pos+1])
		d.pos += 2
		if arg <= 0xff {
			return v, errf(CatCBOR, "M1c", "non-shortest argument")
		}
	case ai == 26:
		if d.pos+4 > len(d.b) {
			return v, errf(CatCBOR, "M1i", "input ends inside an argument")
		}
		arg = uint64(d.b[d.pos])<<24 | uint64(d.b[d.pos+1])<<16 | uint64(d.b[d.pos+2])<<8 | uint64(d.b[d.pos+3])
		d.pos += 4
		if arg <= 0xffff {
			return v, errf(CatCBOR, "M1c", "non-shortest argument")
		}
	case ai == 27:
		if d.pos+8 > len(d.b) {
			return v, errf(CatCBOR, "M1i", "input ends inside an argument")
		}
		for i := 0; i < 8; i++ {
			arg = arg<<8 | uint64(d.b[d.pos+i])
		}
		d.pos += 8
		if arg <= 0xffffffff {
			return v, errf(CatCBOR, "M1c", "non-shortest argument")
		}
	case ai == 31:
		return v, errf(CatCBOR, "M1a", "indefinite-length item")
	default: // 28, 29, 30
		return v, errf(CatCBOR, "M1b", "reserved additional information %d", ai)
	}

	switch major {
	case 0:
		return Value{Kind: ValueUint, U: arg}, nil
	case 1:
		return Value{Kind: ValueNint, U: arg}, nil
	case 2:
		if arg > uint64(len(d.b)-d.pos) {
			return v, errf(CatCBOR, "M1i", "byte string length %d exceeds remaining %d", arg, len(d.b)-d.pos)
		}
		b := d.b[d.pos : d.pos+int(arg)]
		d.pos += int(arg)
		return Value{Kind: ValueBytes, B: b}, nil
	case 3:
		if arg > uint64(len(d.b)-d.pos) {
			return v, errf(CatCBOR, "M1i", "text string length %d exceeds remaining %d", arg, len(d.b)-d.pos)
		}
		b := d.b[d.pos : d.pos+int(arg)]
		d.pos += int(arg)
		if !utf8.Valid(b) {
			return v, errf(CatCBOR, "M1f", "text string is not valid UTF-8")
		}
		return Value{Kind: ValueText, T: string(b)}, nil
	case 4:
		if arg > uint64(len(d.b)-d.pos) {
			return v, errf(CatCBOR, "M1i", "array count %d exceeds remaining bytes %d", arg, len(d.b)-d.pos)
		}
		n := int(arg)
		if n == 0 {
			return Value{Kind: ValueArray}, nil
		}
		vals := make([]Value, 0, n)
		for i := 0; i < n; i++ {
			item, err := d.value(depth + 1)
			if err != nil {
				return v, err
			}
			vals = append(vals, item)
		}
		return Value{Kind: ValueArray, A: vals}, nil
	case 5:
		if arg > uint64(len(d.b)-d.pos)/2 {
			return v, errf(CatCBOR, "M1i", "map count %d exceeds remaining bytes %d", arg, len(d.b)-d.pos)
		}
		n := int(arg)
		if n == 0 {
			return Value{Kind: ValueMap}, nil
		}
		pairs := make([]Pair, 0, n)
		var prev []byte
		for i := 0; i < n; i++ {
			k, err := d.value(depth + 1)
			if err != nil {
				return v, err
			}
			keyBytes, err := encodeValue(k)
			if err != nil {
				return v, err
			}
			if prev != nil {
				cmp := bytes.Compare(prev, keyBytes)
				if cmp == 0 {
					return v, errf(CatCBOR, "M1g", "duplicate map key at entry %d", i)
				}
				if cmp > 0 {
					return v, errf(CatCBOR, "M1g", "map keys not in canonical order at entry %d", i)
				}
			}
			prev = keyBytes
			val, err := d.value(depth + 1)
			if err != nil {
				return v, err
			}
			pairs = append(pairs, Pair{Key: k, Val: val})
		}
		return Value{Kind: ValueMap, M: pairs}, nil
	case 6:
		return v, errf(CatCBOR, "M1d", "tag")
	case 7:
		switch ai {
		case 20:
			return Value{Kind: ValueBool, U: 0}, nil
		case 21:
			return Value{Kind: ValueBool, U: 1}, nil
		case 22:
			return Value{Kind: ValueNull}, nil
		default:
			return v, errf(CatCBOR, "M1e", "major type 7 additional information %d", ai)
		}
	}
	// Unreachable: major is three bits.
	return v, errf(CatCBOR, "M1", "unsupported major type %d", major)
}

// ---- encoding ----

func appendHead(dst []byte, major byte, arg uint64) []byte {
	switch {
	case arg < 24:
		return append(dst, major<<5|byte(arg))
	case arg <= 0xff:
		return append(dst, major<<5|24, byte(arg))
	case arg <= 0xffff:
		return append(dst, major<<5|25, byte(arg>>8), byte(arg))
	case arg <= 0xffffffff:
		return append(dst, major<<5|26, byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	default:
		return append(dst, major<<5|27,
			byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
}

// encodeValue returns the canonical encoding of v. Map entries are emitted in
// the order held; decoded maps are already canonical and writer-built maps are
// canonicalized by Manifest.Encode.
func encodeValue(v Value) ([]byte, error) {
	return appendValue(nil, v)
}

func appendValue(dst []byte, v Value) ([]byte, error) {
	switch v.Kind {
	case ValueUint:
		return appendHead(dst, 0, v.U), nil
	case ValueNint:
		return appendHead(dst, 1, v.U), nil
	case ValueBytes:
		dst = appendHead(dst, 2, uint64(len(v.B)))
		return append(dst, v.B...), nil
	case ValueText:
		dst = appendHead(dst, 3, uint64(len(v.T)))
		return append(dst, v.T...), nil
	case ValueArray:
		dst = appendHead(dst, 4, uint64(len(v.A)))
		for _, item := range v.A {
			var err error
			dst, err = appendValue(dst, item)
			if err != nil {
				return nil, err
			}
		}
		return dst, nil
	case ValueMap:
		dst = appendHead(dst, 5, uint64(len(v.M)))
		for _, p := range v.M {
			var err error
			dst, err = appendValue(dst, p.Key)
			if err != nil {
				return nil, err
			}
			dst, err = appendValue(dst, p.Val)
			if err != nil {
				return nil, err
			}
		}
		return dst, nil
	case ValueBool:
		if v.U != 0 {
			return append(dst, 0xf5), nil
		}
		return append(dst, 0xf4), nil
	case ValueNull:
		return append(dst, 0xf6), nil
	}
	return nil, errf(CatCBOR, "M1", "unknown value kind %d", v.Kind)
}

// canonicalize recursively sorts every map by its encoded key. The result is a
// deep copy, so the caller's value is untouched.
func canonicalize(v Value) (Value, error) {
	switch v.Kind {
	case ValueArray:
		out := make([]Value, len(v.A))
		for i, item := range v.A {
			c, err := canonicalize(item)
			if err != nil {
				return Value{}, err
			}
			out[i] = c
		}
		return Value{Kind: ValueArray, A: out}, nil
	case ValueMap:
		type sortable struct {
			key []byte
			p   Pair
		}
		ss := make([]sortable, len(v.M))
		for i, p := range v.M {
			k, err := canonicalize(p.Key)
			if err != nil {
				return Value{}, err
			}
			val, err := canonicalize(p.Val)
			if err != nil {
				return Value{}, err
			}
			kb, err := encodeValue(k)
			if err != nil {
				return Value{}, err
			}
			ss[i] = sortable{key: kb, p: Pair{Key: k, Val: val}}
		}
		// Insertion sort keeps the code small and the maps tiny.
		for i := 1; i < len(ss); i++ {
			for j := i; j > 0 && bytes.Compare(ss[j-1].key, ss[j].key) > 0; j-- {
				ss[j-1], ss[j] = ss[j], ss[j-1]
			}
		}
		for i := 1; i < len(ss); i++ {
			if bytes.Equal(ss[i-1].key, ss[i].key) {
				return Value{}, errf(CatCBOR, "M1g", "duplicate map key")
			}
		}
		out := make([]Pair, len(ss))
		for i := range ss {
			out[i] = ss[i].p
		}
		return Value{Kind: ValueMap, M: out}, nil
	default:
		return v, nil
	}
}
