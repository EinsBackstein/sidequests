package ctf

import "fmt"

// Category groups a rejection by the structure that failed. Error identity is
// not normative (spec §2.1); the category and Rule are diagnostics, never part
// of the accept/reject decision.
type Category string

const (
	CatHeader      Category = "header"
	CatSection     Category = "section"
	CatTable       Category = "table"
	CatFooter      Category = "footer"
	CatCommitment  Category = "commitment"
	CatManifest    Category = "manifest"
	CatCBOR        Category = "cbor"
	CatChunkIndex  Category = "chunk-index"
	CatExternal    Category = "external"
	CatLegacy      Category = "legacy"
	CatUsage       Category = "usage"
	CatEntitlement Category = "entitlement"
)

// Error is the single error type returned by this package. Detail contains
// offsets, lengths, indices and name_ids only — never bytes echoed from the
// input (spec §13).
type Error struct {
	Category Category
	Rule     string
	Detail   string
}

func (e *Error) Error() string {
	if e.Rule == "" {
		return fmt.Sprintf("ctf: %s: %s", e.Category, e.Detail)
	}
	return fmt.Sprintf("ctf: %s: %s: %s", e.Category, e.Rule, e.Detail)
}

func errf(cat Category, rule, format string, args ...any) *Error {
	return &Error{Category: cat, Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

// Is lets callers test the category without depending on the exact rule.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return t.Category == e.Category
}

// checkedAdd reports a+b and whether it fits in uint64.
func checkedAdd(a, b uint64) (uint64, bool) {
	c := a + b
	return c, c >= a
}

// checkedMul reports a*b and whether it fits in uint64.
func checkedMul(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	c := a * b
	return c, c/b == a
}

// alignUp returns v rounded up to a multiple of align, rejecting overflow.
func alignUp(v, align uint64) (uint64, bool) {
	rem := v % align
	if rem == 0 {
		return v, true
	}
	return checkedAdd(v, align-rem)
}

// chunkCount returns ceil(n/chunk) for a non-zero chunk.
func chunkCount(n, chunk uint64) (uint64, bool) {
	q := n / chunk
	if n%chunk != 0 {
		if q == ^uint64(0) {
			return 0, false
		}
		q++
	}
	return q, true
}
