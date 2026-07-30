# org-ietf-dnssec

[![CI](https://github.com/kotoba-lang/org-ietf-dnssec/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/org-ietf-dnssec/actions/workflows/ci.yml)

**DNSSEC zone signing** — RFC 4034 / 4035, RFC 8080 (Ed25519), RFC 8624
(algorithm selection). Canonical forms, RRSIG, DNSKEY, DS and the NSEC chain,
as portable `.cljc` with **zero dependencies, including crypto**.

[`org-ietf-dns`](https://github.com/kotoba-lang/org-ietf-dns) explicitly scopes
DNSSEC out; this is that piece. It reads and produces the same `:zone/*` record
shape as [`zone`](https://github.com/kotoba-lang/zone), so signed records go
straight back into a zone with no translation.

## Crypto is injected, never imported

```clojure
(sign/rrsig records {:algorithm :ed25519
                     :key        key-handle          ; opaque to this library
                     :sign-fn    (fn [algo key octets] …)
                     :key-tag 12345 :signer "example.com."
                     :original-ttl 3600 :inception … :expiration …})
```

Not portability theatre. A library that imported a signing implementation would
also have to hold, or at least touch, the zone-signing key. Keeping the
primitive outside means the key can live in an HSM, in `kagi`, or in a JVM
`KeyStore` and this code never sees it — the same discipline
`cloud-itonami.dns-provider` uses to make "the actor reads a secret"
structurally impossible rather than merely discouraged.

It also makes the *serialization* testable on its own, which is the half that
actually breaks. A DNSSEC bug is almost never in the signature arithmetic; it is
in **which bytes got signed**. The test suite's "signer" returns the blob it was
handed, so every assertion is about exactly those bytes — with no crypto at all.

## Canonical form is the whole foundation

A signature is over bytes. If a validator serializes an RRset one byte
differently from the signer, every signature fails and the zone goes bogus —
which looks like a key problem, a clock problem, or a resolver problem, and is
none of them.

**Names are lowercased and uncompressed.** This library has its own encoder
rather than reusing `nameserver.wire`'s, because that one applies RFC 1035 name
compression — correct for a message, fatal here, since a compressed name's bytes
depend on what *else* is in the message. The same RRset would sign differently
depending on which query produced it.

**The original TTL is used, not the record's.** The RRSIG carries the TTL the
RRset had at the authoritative server; a cached copy has a decremented one.
Signing with the current TTL produces a signature that validates at the origin
and fails everywhere else — the hardest DNSSEC failure to reproduce, which is
why `encode-rr` takes `original-ttl` as a required argument instead of reading
it off the record.

**Names sort right-to-left, not as strings.** `z.a.example.com` precedes
`a.b.example.com`: the rightmost labels tie, then `a` beats `b`, and the
leftmost label never gets a say. Every place string order disagrees produces an
NSEC chain that proves the nonexistence of names that do exist. The RFC 4034
§6.1 worked example is in the test suite — with `\001` and `\200` as the real
octets 0x01 and 0x80, since spelling them as literal backslash text would
compare 0x5C and test nothing.

**RRsets sort by RDATA as unsigned octets.** So `192.0.2.2` precedes
`192.0.2.10`. Two servers that order an RRset differently produce different
signed blobs from the same records.

## What gets signed

RFC 4035 §5.3.2, and the order matters:

```
RRSIG_RDATA (signature field empty) || RR(1) || RR(2) || …
```

Signing only the records — omitting the RRSIG rdata prefix — is a real and
common mistake that produces signatures no validator accepts, because a
validator *rebuilds* the blob from the RRSIG it received. `sign/signing-blob`
is exposed for exactly this: when a signature will not validate, compare this
blob between signer and validator and the disagreement is always visible in it.

## Other things that fail quietly

**The key tag is a checksum, not a hash**, and two keys can collide — a
validator must try every DNSKEY with a matching tag rather than assuming the
first is right. Algorithm 1 (RSA/MD5) uses a *different* tag rule; it is
deprecated and unsupported, so passing it raises rather than returning a
silently wrong tag.

**The RRSIG `labels` field excludes the root and a leading wildcard.** An
off-by-one here breaks wildcard proofs specifically — everything else keeps
validating, which is why it survives testing.

**The NSEC type bitmap counts bits from the most significant end**, and only
non-empty windows are emitted. The endianness reads backwards and is the usual
source of a bitmap claiming the wrong types exist.

**The NSEC chain is circular** — the last name's `next` is the apex. A chain
that stops at the last name leaves every name sorting after it unprovable, so
those queries fail to validate instead of returning a proven NXDOMAIN.

**A DS never published in the parent means the zone is unsigned.** To every
validator, a correctly signed zone with no DS in its parent is just an unsigned
zone. The DS is the single link, and it is the one artifact this library
produces that has to leave the registry.

**Deprecated algorithms are absent, not discouraged.** RSA/SHA-1, the DSA
family and SHA-1 digests are not in `algorithms`/`digests` at all, so nobody
picks one by autocompleting (RFC 8624).

## EDNS0 is a prerequisite

A single signed response routinely exceeds 512 octets. A signed zone served
without EDNS0 pushes every query to TCP — so `nameserver.edns` in
`org-ietf-dns` is a dependency of deploying this, not an optimization.

## Scope

- **In:** canonical name/RR/RRset forms and ordering, DNSKEY, key tag, DS
  digest input and record, RRSIG signing blob and record, NSEC records and the
  full chain, the type bitmap.
- **Not yet:** NSEC3 (RFC 5155) — the hashed denial-of-existence that stops an
  NSEC walk from enumerating the zone. A registry that considers its name list
  confidential needs it, and should know it is absent rather than discover it.
  Also absent: signature *validation* (this is a signer), key rollover
  scheduling, and CDS/CDNSKEY (RFC 7344) for automated parent updates.
- **Never:** a key, a clock, or a crypto implementation.

## Test

```
clojure -M:test
```

16 tests / 60 assertions.
