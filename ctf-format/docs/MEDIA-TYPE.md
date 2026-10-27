# Media type: `application/vnd.ctf.bundle.v1`

**Decision:** a bundle is carried as an OCI image layer with media type
`application/vnd.ctf.bundle.v1`. The type is intentionally not registered with
IANA. The identifier is stable.

## Identifier

| Use | Media type |
|---|---|
| the `.ctf` bundle, as the image's single layer | `application/vnd.ctf.bundle.v1` |
| the empty image config | `application/vnd.ctf.bundle.config.v1+json` |
| the OCI image manifest | `application/vnd.oci.image.manifest.v1+json` |
| the OCI image index | `application/vnd.oci.image.index.v1+json` |

The layer blob is the bundle bytes exactly. There is no wrapper and no
re-serialization, so a registry push and pull round trip is byte-for-byte (spec
§30.3). The `+json` suffix on the config type is the registered structured syntax
suffix for JSON. The two OCI types belong to OCI, not to this project.

## Status: intentionally unregistered

No IANA media type registration exists for either `application/vnd.ctf.bundle.v1`
or `application/vnd.ctf.bundle.config.v1+json`, and this repository has not filed
one. The `vnd.` facet marks a vendor-specific type. It does not assert a registry
entry, and an unregistered type is still usable by this project's tools and by OCI
registries, which treat the layer media type as opaque. The IANA registry is a
naming authority, not a parser.

If a registration is wanted later, a change controller (the vendor or organization
responsible for the format) submits the RFC 6838 §5.6 template to IANA at
`iana@iana.org` or through <https://www.iana.org/form/media-types>. The template
must name the type and subtype, required and optional parameters, encoding
considerations, security and interoperability considerations, the published
specification (`spec/SPEC.md`), applications that use the type, fragment identifier
handling, magic number and file extension, contact, intended usage, restrictions on
usage, author, and change controller. Vendor-tree requests go to IANA and are
reviewed by the media types expert. Posting the request to `media-types@iana.org`
for comment is encouraged. Filing that request is a project decision, not something
this repository can do on its own.

The missing registration affects discovery, not parsing. A registry entry would not
change the bytes or the identifier.

## File extension and the Compact C Type Format collision

The customary file extension is `.ctf` (spec §12). The same extension belongs to
Compact C Type Format, the debug-info format implemented by `libctf` and dumped by
`ctfdump`. A Compact C Type Format file begins with the 16-bit magic `0xcff1`, so
its first byte is `0xcf` or `0xf1` depending on the writer's byte order. A `.ctf`
bundle begins with the 8-byte signature `89 43 54 46 0d 0a 1a 0a`, whose first byte
is `0x89`. The first byte already separates the two, and the full 8-byte signature
confirms it, so `file`/libmagic and any reader that checks magic can disambiguate
cleanly. The shared extension is a naming collision, not an ambiguity in the bytes.

The media type applies only to the bundle. A Compact C Type Format file has no
`.ctf` media type, and a bundle is never a Compact C Type Format file.

## Compatibility rule

A media type never changes meaning. `application/vnd.ctf.bundle.v1` identifies the
v1 media type for the life of the format. It does not track the container's
`version_major` (currently 0) or `version_minor` (currently 3). A compatible
revision, including this document's format 0.3, keeps the same identifier.

An incompatible change to the bundle, the kind §15 sends to a new major version,
gets a new identifier, by convention `application/vnd.ctf.bundle.v2`. The `v1`
identifier is never reused or redefined. A reader that does not know `v2` refuses
it rather than guessing. Older bundles keep their `v1` type and stay readable by
readers that implement v1.

The config type follows the same rule: `application/vnd.ctf.bundle.config.v1+json`,
with a new version for an incompatible config change.
