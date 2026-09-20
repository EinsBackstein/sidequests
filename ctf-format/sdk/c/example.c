/*
 * example.c — a complete `.ctf` generator using the C guest SDK.
 *
 * It computes the same two outputs as the Rust sample generator
 * (`sdk/sample-generator`), so the two SDKs demonstrably agree byte for byte:
 * `chal` is the seed transformed by a fixed arithmetic, and `key.bin` is the
 * seed reversed. The flag is the fixed string `ctf{example}`. The point is not
 * the challenge, it is to show the whole contract in one file — the three ABI
 * exports, a build of the output block with the helpers, and the absence of any
 * import.
 *
 * Build (see README.md for the why of each flag):
 *
 *   clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export-memory \
 *     -Wl,--export=ctf_alloc -Wl,--export=ctf_generate -Wl,--export=ctf_output_len \
 *     -o gen.wasm example.c
 *
 * The module has no imports, so it cannot read a clock, a file, or a socket,
 * and its output is a pure function of the seed. That is what lets the host run
 * it twice and compare roots, and what makes the commitment in the container
 * meaningful.
 */

#include "ctf_generator.h"

/*
 * A bump allocator over a static arena. `ctf_alloc` must return zeroed bytes
 * backed by linear memory; with no WASI there is no `malloc` to call, and a
 * freestanding module may not have one at all. This one never frees, which is
 * correct for the ABI's use: the host allocates once per call to place the
 * seed, reads the output block, and lets the instance go. A module that does
 * more allocation should track its own free list, but it still must never rely
 * on a host-provided allocator.
 */
#define CTF_EXAMPLE_ARENA_SIZE (64u * 1024u)

static uint8_t g_arena[CTF_EXAMPLE_ARENA_SIZE];
static uint32_t g_arena_used;

uint32_t ctf_alloc(uint32_t len)
{
    uint32_t start;
    uint32_t i;
    uint8_t *p;

    /* Align the returned offset to 8 bytes so a caller can place any seed
     * without worrying about alignment. */
    if (g_arena_used > CTF_EXAMPLE_ARENA_SIZE) {
        return 0u;
    }
    start = (g_arena_used + 7u) & ~7u;
    if (start < g_arena_used) {
        return 0u; /* the round-up wrapped; the arena is already at the top */
    }
    if (len > CTF_EXAMPLE_ARENA_SIZE - start) {
        return 0u;
    }

    p = &g_arena[start];
    for (i = 0; i < len; i++) {
        p[i] = 0u;
    }
    g_arena_used = start + len;
    return (uint32_t)(uintptr_t)p;
}

/*
 * The output block lives in static storage so it stays valid after
 * `ctf_generate` returns, as the ABI requires. It is written, not allocated,
 * because the ABI promises nothing about when the host reads it beyond the next
 * `ctf_generate` call, and a bump allocator cannot hand the same block back
 * every time.
 */
#define CTF_EXAMPLE_OUT_CAPACITY (64u * 1024u)

static uint8_t g_out[CTF_EXAMPLE_OUT_CAPACITY];
static uint32_t g_out_len;

/* Scratch for the two derived outputs. Sized to half the block each, which is
 * far more than any seed this example expects. */
static uint8_t g_artifact[CTF_EXAMPLE_OUT_CAPACITY / 2u];
static uint8_t g_key[CTF_EXAMPLE_OUT_CAPACITY / 2u];

/* `artifact-v1:` — the same prefix the Rust sample uses. */
static const uint8_t ARTIFACT_PREFIX[] = {
    'a', 'r', 't', 'i', 'f', 'a', 'c', 't', '-', 'v', '1', ':'
};
#define ARTIFACT_PREFIX_LEN 12u

uint32_t ctf_generate(uint32_t seed_ptr, uint32_t seed_len)
{
    ctf_output_writer w;
    const uint8_t *seed = (const uint8_t *)(uintptr_t)seed_ptr;
    uint32_t i;

    if (seed == NULL && seed_len != 0u) {
        g_out_len = 0u;
        return 0u;
    }
    if (seed_len > sizeof(g_key) - ARTIFACT_PREFIX_LEN) {
        g_out_len = 0u;
        return 0u;
    }

    if (!ctf_output_begin(&w, g_out, (uint32_t)sizeof(g_out))) {
        g_out_len = 0u;
        return 0u;
    }

    /* `chal` = "artifact-v1:" followed by seed[i] + (i * 31) mod 256, the same
     * wrapping arithmetic the Rust sample performs. */
    ctf_copy_bytes(g_artifact, ARTIFACT_PREFIX, ARTIFACT_PREFIX_LEN);
    for (i = 0; i < seed_len; i++) {
        g_artifact[ARTIFACT_PREFIX_LEN + i] =
            (uint8_t)(seed[i] + (uint8_t)((i & 0xFFu) * 31u));
    }
    if (!ctf_output_add(&w, "chal", 4u, g_artifact,
                        ARTIFACT_PREFIX_LEN + seed_len)) {
        g_out_len = 0u;
        return 0u;
    }

    /* `key.bin` = the seed reversed. */
    for (i = 0; i < seed_len; i++) {
        g_key[i] = seed[seed_len - 1u - i];
    }
    if (!ctf_output_add(&w, "key.bin", 7u, g_key, seed_len)) {
        g_out_len = 0u;
        return 0u;
    }

    /* The flag. It never comes from the container; the generator derives it. */
    if (!ctf_output_set_flag(&w, "ctf{example}", 12u)) {
        g_out_len = 0u;
        return 0u;
    }

    {
        uint32_t block = ctf_output_finish(&w);
        if (block == 0u) {
            g_out_len = 0u;
            return 0u;
        }
        /* `ctf_output_len` must report exactly what was written. */
        g_out_len = w.used;
        return block;
    }
}

uint32_t ctf_output_len(void)
{
    return g_out_len;
}
