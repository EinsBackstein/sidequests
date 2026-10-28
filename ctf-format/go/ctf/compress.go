package ctf

import (
	"bytes"
	"io"
	"math"

	"github.com/klauspost/compress/zstd"
)

// zstdEncodingLevel is the writer's compression level. Like the reference
// writer it is a middle default: the gain over level 1 is small for challenge
// content and the cost is negligible against the hashing and I/O around it.
const zstdEncodingLevel = zstd.SpeedDefault

// compressFrames compresses a plaintext into one zstd frame per chunk (§5.4).
// A chunk_size of 0 produces a single frame covering the whole plaintext, and
// an empty plaintext is always a single (empty) frame, whatever the chunk size:
// zero frames would leave a comp = 1 section no decoder can open.
func compressFrames(plain []byte, chunkSize uint32) ([][]byte, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstdEncodingLevel))
	if err != nil {
		return nil, errf(CatUsage, "", "zstd encoder setup failed")
	}
	defer enc.Close()

	if chunkSize == 0 || len(plain) == 0 {
		return [][]byte{enc.EncodeAll(plain, nil)}, nil
	}
	frames := make([][]byte, 0, len(plain)/int(chunkSize)+1)
	for start := 0; start < len(plain); start += int(chunkSize) {
		end := start + int(chunkSize)
		if end > len(plain) {
			end = len(plain)
		}
		frames = append(frames, enc.EncodeAll(plain[start:end], nil))
	}
	return frames, nil
}

// compressSection returns the concatenated frames a comp = 1 section stores
// (§5.4). Frame i covers [i × chunk_size, min((i+1) × chunk_size, len_plain)).
func compressSection(plain []byte, chunkSize uint32) ([]byte, error) {
	frames, err := compressFrames(plain, chunkSize)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, frame := range frames {
		out = append(out, frame...)
	}
	return out, nil
}

// decompressExact decodes a sequence of concatenated zstd frames and requires
// exactly want bytes. It does not apply D1/D2: those are section-level rules
// over declared totals and belong to the caller (§5.4).
//
// The decoder output is bounded by want+1, so a frame that expands beyond its
// declaration is truncated and then rejected by the exact-length check rather
// than allowed to allocate freely. The output buffer grows with the bytes that
// actually arrive; it is never sized from the declaration.
func decompressExact(stored []byte, want uint64) ([]byte, error) {
	// Bound the decoder's own window/decoded-size allocation as well as the
	// bytes returned: never size anything from an unvalidated length.
	memLimit := want
	if memLimit < 1<<20 {
		memLimit = 1 << 20
	} else if memLimit < math.MaxUint64 {
		memLimit++
	}
	dec, err := zstd.NewReader(bytes.NewReader(stored),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(memLimit))
	if err != nil {
		return nil, errf(CatSection, "§5.4", "zstd decoder setup failed")
	}
	defer dec.Close()

	limit := int64(math.MaxInt64)
	if want < math.MaxInt64 {
		limit = int64(want) + 1
	}
	bounded := io.LimitReader(dec, limit)
	var out []byte
	buf := make([]byte, 64*1024)
	for {
		n, rerr := bounded.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, errf(CatSection, "§5.4", "zstd decode failed")
		}
	}
	if uint64(len(out)) != want {
		return nil, errf(CatSection, "§5.4", "zstd decoded %d bytes, declared len_plain %d", len(out), want)
	}
	return out, nil
}

// decodeSection applies D1 and D2 to the authenticated declaration and only
// then runs the decoder (§5.4). The order is normative: a decompression bomb is
// refused before a single frame is read.
func decodeSection(r SectionRecord, stored []byte) ([]byte, error) {
	if r.Comp != CompZstd {
		return stored, nil
	}
	if err := decompressionCaps(r); err != nil {
		return nil, err
	}
	return decompressExact(stored, r.LenPlain)
}
