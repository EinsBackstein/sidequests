/*
 * ctf_generator.h — C guest SDK for `.ctf` deterministic generators.
 *
 * A `.ctf` generator is a WebAssembly module that is a pure function of a seed
 * (design §8): the host runs it on the reference seed and on the seed for a
 * subject, and accepts the result only when it is byte-identical across runs.
 * The container stores a commitment to that function, so identical output is
 * not a nicety — it is what makes a committed bundle still reconstructible
 * after the author's machine is gone.
 *
 * That property is why this ABI is deliberately *capability-free*. The module
 * imports nothing: no WASI, no clock, no filesystem, no network, no
 * `getrandom`. It cannot observe a timestamp, a build path, or the host's
 * locale, so there is nothing for it to accidentally vary on. The host supplies
 * the seed; the module returns bytes. Everything else is the module's own
 * arithmetic.
 *
 * ---------------------------------------------------------------------------
 * Interface version
 * ---------------------------------------------------------------------------
 *
 * CTF_GENERATOR_INTERFACE_VERSION is the version of the ABI described below,
 * pinned here rather than negotiated at runtime. It is deliberately separate
 * from the container format version and from the manifest's `generate.profile`
 * (spec §23.5; design §8 calls it `wasm_profile`): the byte layout of a `.ctf`
 * generator may use, and the host-to-guest calling convention are three
 * independent things that retire on their own schedules. Tying them together
 * would mean a spec bump that touches nothing about generators silently
 * changes the ABI. A host that reads a module built against a different
 * interface version MUST refuse it rather than guess.
 *
 * ---------------------------------------------------------------------------
 * ABI
 * ---------------------------------------------------------------------------
 *
 * Export `memory`, the module's linear memory. The host reads the output block
 * out of this memory by offset, so `--export-memory` is required at link time.
 *
 *   uint32_t ctf_alloc(uint32_t len);
 *     Allocate `len` zeroed bytes and return their offset into linear memory,
 *     or 0 on failure. The host uses this to place the seed: it allocates
 *     `seed_len` bytes, writes the seed there, then calls `ctf_generate` with
 *     that offset. A guest with no allocator may ignore this call shape, but it
 *     must implement the export. 0 is a failure sentinel, so a valid module
 *     never hands out offset 0.
 *
 *   uint32_t ctf_generate(uint32_t seed_ptr, uint32_t seed_len);
 *     Read `seed_len` bytes at `seed_ptr` and deterministically derive the
 *     outputs. Return the offset of an output block held in linear memory that
 *     stays valid until the next `ctf_generate` call, or 0 on failure. Must not
 *     import or call anything host-provided.
 *
 *   uint32_t ctf_output_len(void);
 *     The byte length of the block produced by the most recent
 *     `ctf_generate`. The host reads exactly this many bytes starting at the
 *     pointer the last `ctf_generate` returned. Before the first
 *     `ctf_generate` it reports 0.
 *
 * ---------------------------------------------------------------------------
 * Output-block wire format
 * ---------------------------------------------------------------------------
 *
 * All integers are unsigned 32-bit little-endian, written explicitly so a
 * generator built by any toolchain produces identical bytes. Lengths are byte
 * counts, not element counts.
 *
 *   u32 count
 *   count × { u32 name_len; name bytes (UTF-8); u32 data_len; data bytes }
 *   u32 flag_len; flag bytes (UTF-8)
 *
 * `count` is the number of named outputs. Each name is a UTF-8 byte string;
 * the host maps it to a section name through the manifest's name table. The
 * flag follows the last output and is a single UTF-8 byte string. A caller that
 * emits nothing still writes `count = 0` and a `flag_len`.
 *
 * The helpers below build this block in a buffer the caller owns. They do not
 * allocate: a generator with no allocator, or with a fixed arena it cannot
 * grow, can still use them. `ctf_output_finish` writes the trailing flag and
 * patches `count`, so entries may be added in any order before it is called.
 * After it returns, `writer.used` holds the block length to be reported from
 * `ctf_output_len`.
 */

#ifndef CTF_GENERATOR_H
#define CTF_GENERATOR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CTF_GENERATOR_INTERFACE_VERSION 1

/*
 * ABI exports. The module must define these three with exactly these names and
 * signatures; the link command in README.md exports them by name.
 */
uint32_t ctf_alloc(uint32_t len);
uint32_t ctf_generate(uint32_t seed_ptr, uint32_t seed_len);
uint32_t ctf_output_len(void);

/*
 * Writer state for building an output block in a caller-provided buffer.
 *
 * Treat the fields as read-only except for `used` after `ctf_output_finish`,
 * which reports the finished block's length. `flag` and `flag_len` are only
 * meaningful between `ctf_output_set_flag` and `ctf_output_finish`; the flag
 * bytes are copied into the buffer at finish time, so they must stay readable
 * until then.
 */
typedef struct ctf_output_writer {
    uint8_t *base;             /* start of the caller's buffer                */
    uint32_t capacity;         /* buffer size in bytes                        */
    uint32_t used;             /* bytes written; final block length at finish */
    uint32_t count;            /* named outputs added so far                  */
    const uint8_t *flag;       /* pending flag bytes, not yet copied          */
    uint32_t flag_len;         /* pending flag length in bytes                */
    int failed;                /* sticky: set once any step could not fit     */
} ctf_output_writer;

/* Write `v` as four little-endian bytes at `p`. */
static inline void ctf_store_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* Copy `n` bytes without reaching for <string.h>, which a freestanding guest
 * may not have. Overlap is not supported and never happens here. */
static inline void ctf_copy_bytes(uint8_t *dst, const uint8_t *src, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

/*
 * Begin a block in `buf` (capacity `cap`). Reserves room for the leading
 * `count` field. Returns 1 on success and 0 on failure; on failure the writer
 * is marked failed and every later call is a no-op returning 0.
 */
static inline int ctf_output_begin(ctf_output_writer *w, void *buf, uint32_t cap)
{
    if (w == NULL || buf == NULL || cap < 4u) {
        if (w != NULL) {
            w->failed = 1;
        }
        return 0;
    }
    w->base = (uint8_t *)buf;
    w->capacity = cap;
    w->used = 4u;
    w->count = 0u;
    w->flag = NULL;
    w->flag_len = 0u;
    w->failed = 0;
    return 1;
}

/*
 * Append one named output: `name_len` UTF-8 bytes followed by `data_len` data
 * bytes. `name` and `data` must be readable for the duration of the call; the
 * bytes are copied into the buffer. Returns 1 on success, 0 on failure.
 */
static inline int ctf_output_add(ctf_output_writer *w,
                                 const char *name, uint32_t name_len,
                                 const void *data, uint32_t data_len)
{
    uint32_t remaining;

    if (w == NULL || w->failed) {
        return 0;
    }
    if ((name == NULL && name_len != 0u) || (data == NULL && data_len != 0u)) {
        w->failed = 1;
        return 0;
    }

    /* Bounds are checked with subtraction so no sum can wrap: 4 for name_len,
     * then name bytes, 4 for data_len, then data bytes. */
    remaining = w->capacity - w->used;
    if (name_len > remaining) {
        w->failed = 1;
        return 0;
    }
    remaining -= name_len;
    if (remaining < 4u) {
        w->failed = 1;
        return 0;
    }
    remaining -= 4u;
    if (data_len > remaining) {
        w->failed = 1;
        return 0;
    }

    ctf_store_u32le(w->base + w->used, name_len);
    w->used += 4u;
    ctf_copy_bytes(w->base + w->used, (const uint8_t *)name, name_len);
    w->used += name_len;

    ctf_store_u32le(w->base + w->used, data_len);
    w->used += 4u;
    ctf_copy_bytes(w->base + w->used, (const uint8_t *)data, data_len);
    w->used += data_len;

    w->count += 1u;
    return 1;
}

/*
 * Record the flag to be written after the last output. The bytes are not
 * copied yet, so `flag` must stay readable until `ctf_output_finish`; a string
 * literal satisfies this trivially. Calling this again replaces the previous
 * flag. Returns 1 on success and 0 on failure. A NULL flag with length 0 is an
 * empty flag and is allowed.
 */
static inline int ctf_output_set_flag(ctf_output_writer *w,
                                      const char *flag, uint32_t flag_len)
{
    if (w == NULL || w->failed) {
        return 0;
    }
    if (flag == NULL && flag_len != 0u) {
        w->failed = 1;
        return 0;
    }
    /* Reject at once the case that cannot fit even before more outputs are
     * added, so a hopeless block fails here rather than at finish. */
    if (flag_len > w->capacity - w->used || w->capacity - w->used - flag_len < 4u) {
        w->failed = 1;
        return 0;
    }
    w->flag = (const uint8_t *)flag;
    w->flag_len = flag_len;
    return 1;
}

/*
 * Write `count`, append the flag, and return the block's offset into linear
 * memory, or 0 on failure. On success `w->used` is the length the module must
 * report from `ctf_output_len`. The block is contiguous and byte-exact to the
 * wire format above, so a Rust host reading it produces the same artifacts the
 * Rust generator would.
 */
static inline uint32_t ctf_output_finish(ctf_output_writer *w)
{
    uint32_t remaining;

    if (w == NULL || w->failed || w->base == NULL) {
        return 0u;
    }

    remaining = w->capacity - w->used;
    if (w->flag_len > remaining || remaining - w->flag_len < 4u) {
        w->failed = 1;
        return 0u;
    }

    ctf_store_u32le(w->base, w->count);

    ctf_store_u32le(w->base + w->used, w->flag_len);
    w->used += 4u;

    if (w->flag_len > 0u) {
        ctf_copy_bytes(w->base + w->used, w->flag, w->flag_len);
    }
    w->used += w->flag_len;

    return (uint32_t)(uintptr_t)w->base;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTF_GENERATOR_H */
