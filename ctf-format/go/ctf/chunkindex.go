package ctf

import (
	"encoding/binary"
	"io"
	"math/bits"

	"lukechampine.com/blake3"
	"lukechampine.com/blake3/guts"
)

// ChunkHash is one 32-byte BLAKE3 chaining value of a chunk index.
type ChunkHash [RootLen]byte

func wordsToHash(cv [8]uint32) (h ChunkHash) {
	for i, w := range cv {
		binary.LittleEndian.PutUint32(h[i*4:], w)
	}
	return h
}

func hashToWords(h ChunkHash) (cv [8]uint32) {
	for i := range cv {
		cv[i] = binary.LittleEndian.Uint32(h[i*4:])
	}
	return cv
}

func parentCV(left, right ChunkHash) ChunkHash {
	return wordsToHash(guts.ChainingValue(guts.ParentNode(hashToWords(left), hashToWords(right), &guts.IV, 0)))
}

func parentRoot(left, right ChunkHash) ChunkHash {
	out := guts.CompressNode(guts.ParentNode(hashToWords(left), hashToWords(right), &guts.IV, guts.FlagRoot))
	return wordsToHash([8]uint32(out[:8]))
}

// mergeCV implements §9.2's merge(a..b) over non-root subtree chaining values.
func mergeCV(entries []ChunkHash, a, b int) ChunkHash {
	if b-a == 1 {
		return entries[a]
	}
	k := 1 << (bits.Len(uint(b-a-1)) - 1)
	return parentCV(mergeCV(entries, a, a+k), mergeCV(entries, a+k, b))
}

// mergeRoot implements §9.2's root(count) finalization, count >= 2.
func mergeRoot(entries []ChunkHash) ChunkHash {
	count := len(entries)
	k := 1 << (bits.Len(uint(count-1)) - 1)
	return parentRoot(mergeCV(entries, 0, k), mergeCV(entries, k, count))
}

// subtreeCV returns the non-root chaining value of up to 2^k BLAKE3 chunks,
// with the first leaf's global BLAKE3 chunk counter equal to counter.
func subtreeCV(data []byte, counter uint64) ChunkHash {
	if len(data) <= 1024 {
		return wordsToHash(guts.ChainingValue(guts.CompressChunk(data, &guts.IV, counter, 0)))
	}
	n := (len(data) + 1023) / 1024
	if n&(n-1) != 0 {
		// Not a power of two: build the BLAKE3 tree shape explicitly.
		k := 1 << (bits.Len(uint(n-1)) - 1)
		left := subtreeCV(data[:k*1024], counter)
		right := subtreeCV(data[k*1024:], counter+uint64(k))
		return parentCV(left, right)
	}
	// n is a power of two: balanced merge.
	cvs := make([]ChunkHash, n)
	for i := 0; i < n; i++ {
		start := i * 1024
		end := start + 1024
		if end > len(data) {
			end = len(data)
		}
		cvs[i] = wordsToHash(guts.ChainingValue(guts.CompressChunk(data[start:end], &guts.IV, counter+uint64(i), 0)))
	}
	for len(cvs) > 1 {
		next := make([]ChunkHash, 0, len(cvs)/2)
		for i := 0; i < len(cvs); i += 2 {
			next = append(next, parentCV(cvs[i], cvs[i+1]))
		}
		cvs = next
	}
	return cvs[0]
}

// sectionChunkCV computes entry i of a chunk index: the non-root chaining value
// of plaintext[i*chunkSize : min((i+1)*chunkSize, len(plaintext))].
func sectionChunkCV(plaintext []byte, chunkSize uint64, i uint64) ChunkHash {
	start := i * chunkSize
	end := start + chunkSize
	if end > uint64(len(plaintext)) {
		end = uint64(len(plaintext))
	}
	// chunkSize is a power of two >= 4096, so the BLAKE3 leaf counter is
	// i * (chunkSize/1024).
	leafChunk := i * (chunkSize / 1024)
	return subtreeCV(plaintext[start:end], leafChunk)
}

// BuildChunkIndex returns the chunk index entries for plaintext under a
// non-zero chunk_size. The caller decides whether to emit them (an index with
// fewer than two entries is unrepresentable, R19).
func BuildChunkIndex(plaintext []byte, chunkSize uint32) ([]ChunkHash, error) {
	if chunkSize == 0 {
		return nil, errf(CatChunkIndex, "C1", "chunk_size is zero")
	}
	count, ok := chunkCount(uint64(len(plaintext)), uint64(chunkSize))
	if !ok {
		return nil, errf(CatChunkIndex, "C1", "chunk count overflows")
	}
	entries := make([]ChunkHash, int(count))
	for i := uint64(0); i < count; i++ {
		entries[i] = sectionChunkCV(plaintext, uint64(chunkSize), i)
	}
	return entries, nil
}

// indexRoot reduces an index to the section root it must equal.
func indexRoot(entries []ChunkHash) (ChunkHash, error) {
	if len(entries) < 2 {
		return ChunkHash{}, errf(CatChunkIndex, "C2", "index has %d entries", len(entries))
	}
	return mergeRoot(entries), nil
}

// parseChunkIndexAt reads exactly count entries of 32 bytes at off.
func parseChunkIndexAt(file []byte, off, count uint64) ([]ChunkHash, error) {
	length, ok := checkedMul(count, RootLen)
	if !ok {
		return nil, errf(CatChunkIndex, "C3", "index length overflows")
	}
	end, ok := checkedAdd(off, length)
	if !ok || end > uint64(len(file)) {
		return nil, errf(CatChunkIndex, "C3", "index range [%d,%d) beyond file", off, end)
	}
	entries := make([]ChunkHash, int(count))
	for i := uint64(0); i < count; i++ {
		copy(entries[i][:], file[off+i*RootLen:off+(i+1)*RootLen])
	}
	return entries, nil
}

// VerifyChunkIndex applies C1, C3 and C4 to an inline, unencoded section and
// returns its entries. It is an on-use check, never a parse-time check (§9.3).
func (b *Bundle) VerifyChunkIndex(nameID uint16) ([]ChunkHash, error) {
	rec, ok := b.Section(nameID)
	if !ok {
		return nil, errf(CatUsage, "", "no section with name_id %d", nameID)
	}
	if rec.Has(FlagSealed) || !rec.Understood() {
		return nil, errf(CatChunkIndex, "C8", "chunk index of section %d is not exposable", nameID)
	}
	if rec.ChunkIndexOff == 0 {
		return nil, errf(CatChunkIndex, "C1", "section %d has no chunk index", nameID)
	}
	count, ok := chunkCount(rec.LenPlain, uint64(rec.ChunkSize))
	if !ok {
		return nil, errf(CatChunkIndex, "C1", "chunk count overflows")
	}
	entries, err := parseChunkIndexAt(b.raw, rec.ChunkIndexOff, count)
	if err != nil {
		return nil, err
	}
	got, err := indexRoot(entries)
	if err != nil {
		return nil, err
	}
	if got != ChunkHash(rec.Root) {
		return nil, errf(CatChunkIndex, "C4", "index root does not equal section %d root", nameID)
	}
	return entries, nil
}

// VerifyChunk applies C5 to chunk i of a plain inline section. It always runs
// C4 first (C6). The caller gets the chunk bytes only after the check passes.
func (b *Bundle) VerifyChunk(nameID uint16, i uint64) ([]byte, error) {
	entries, err := b.VerifyChunkIndex(nameID)
	if err != nil {
		return nil, err
	}
	rec, _ := b.Section(nameID)
	if rec.External() || rec.Enc != EncNone || rec.Comp != CompNone {
		return nil, errf(CatUsage, "", "chunk verification requires an inline unencoded section")
	}
	if i >= uint64(len(entries)) {
		return nil, errf(CatChunkIndex, "C5", "chunk %d outside index of %d entries", i, len(entries))
	}
	// The section's plaintext is rec.LenPlain bytes at rec.Offset. Bound that
	// payload against the file once; plaintext offsets are never compared to file
	// offsets. sectionChunkCV takes the whole plaintext and selects chunk i, so
	// the leaf counter is i*(chunkSize/1024) and the bytes are the chunk.
	payloadEnd, ok := checkedAdd(rec.Offset, rec.LenPlain)
	if !ok || payloadEnd > uint64(len(b.raw)) {
		return nil, errf(CatChunkIndex, "C5", "section %d payload beyond file", nameID)
	}
	start := i * uint64(rec.ChunkSize)
	if start >= rec.LenPlain {
		return nil, errf(CatChunkIndex, "C5", "chunk %d outside plaintext of %d bytes", i, rec.LenPlain)
	}
	plaintext := b.raw[rec.Offset:payloadEnd]
	got := sectionChunkCV(plaintext, uint64(rec.ChunkSize), i)
	if got != entries[i] {
		return nil, errf(CatChunkIndex, "C5", "chunk %d does not match its index entry", i)
	}
	end := start + uint64(rec.ChunkSize)
	if end > rec.LenPlain {
		end = rec.LenPlain
	}
	return plaintext[start:end], nil
}

// VerifyExternal streams an external payload through BLAKE3, checking the exact
// length and the record's root (§5.7, §9.4).
func (r SectionRecord) VerifyExternal(rd io.Reader) error {
	if !r.External() {
		return errf(CatUsage, "", "section is not EXTERNAL")
	}
	h := blake3.New(RootLen, nil)
	n, err := io.Copy(h, io.LimitReader(rd, int64(r.LenPlain)+1))
	if err != nil {
		return errf(CatExternal, "", "read failed")
	}
	if uint64(n) != r.LenPlain {
		return errf(CatExternal, "", "external length %d != declared %d", n, r.LenPlain)
	}
	var got [RootLen]byte
	copy(got[:], h.Sum(nil))
	if got != r.Root {
		return errf(CatExternal, "", "external root mismatch")
	}
	return nil
}
