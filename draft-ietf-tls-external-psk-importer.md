---
title: Importing External PSKs for TLS
abbrev: Importing External PSKs for TLS
docname: draft-ietf-tls-external-psk-importer-latest
category: exp

ipr: trust200902
area: General
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
       ins: D. Benjamin
       name: David Benjamin
       organization: Google, LLC.
       email: davidben@google.com
 -
       ins: C. A. Wood
       name: Christopher A. Wood
       organization: Apple, Inc.
       email: cawood@apple.com


normative:
  RFC1035:
  RFC2119:
  RFC6234:

informative:
  CCB: DOI.10.14722/ndss.2015.23277
  Selfie:
     title: "Selfie: reflections on TLS 1.3 with PSK"
     author:
         -
             ins: N. Drucker
             name: Nir Drucker
         -
             ins: S. Gueron
             name: Shay Gueron
     date: 2019
     target: https://eprint.iacr.org/2019/347.pdf

--- abstract

This document describes an interface for importing external PSK (Pre-Shared Key) into
TLS 1.3.

--- middle

# Introduction

TLS 1.3 {{!RFC8446}} supports pre-shared key (PSK) authentication, wherein PSKs
can be established via session tickets from prior connections or externally via some out-of-band
mechanism. The protocol mandates that each PSK only be used with a single hash function.
This was done to simplify protocol analysis. TLS 1.2 {{!RFC5246}}, in contrast, has no such requirement, as
a PSK may be used with any hash algorithm and the TLS 1.2 PRF. This means that external PSKs
could possibly be re-used in two different contexts with the same hash functions during key
derivation. Moreover, it requires external PSKs to be provisioned for specific hash
functions.

To mitigate these problems, external PSKs can be bound to a specific hash function when used
in TLS 1.3, even if they are associated with a different key
derivation function (KDF) and hash function when provisioned. This document
specifies an interface by which external PSKs may be imported for use in a TLS 1.3 connection
to achieve this goal. In particular, it describes how KDF-bound PSKs can be differentiated by
different hash algorithms to produce a set of candidate PSKs, each of which are bound to a specific
hash function. This expands what would normally have been a single PSK identity into a set of
PSK identities. However, it requires no change to the TLS 1.3 key schedule.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Overview

Intuitively, key importers mirror the concept of key exporters in TLS in that they
diversify a key based on some contextual information before use in a connection. In contrast to
key exporters, wherein differentiation is done via an explicit label and context string,
the key importer defined herein uses a combination of protocol version, KDF
identifier, and optional context string to differentiate an external PSK into one or more
PSKs for use.

Imported keys do not require negotiation for use, as a client and server will not agree upon
identities if not imported correctly. Thus, importers induce no protocol changes with
the exception of expanding the set of PSK identities sent on the wire. Endpoints may incrementally
deploy PSK importer support by offering non-imported keys for TLS versions prior to TLS 1.3.
(Negotiation and use of imported PSKs requires both endpoints support the importer API described herein.)

## Terminology {#terminology}

- External PSK (EPSK): A PSK established or provisioned out-of-band, i.e., not from a TLS connection, which is
a tuple of (Base Key, External Identity, KDF). The associated KDF (and hash function) may be undefined.
- Base Key: The secret value of an EPSK.
- External Identity: The identity of an EPSK.
- Imported Identity: The identity of a PSK as sent on the wire.

## Notation and Cryptographic Dependencies

The key importer API depends on a generic KDF which provides the following interface.

- Nh: The output size of the Extract function.
- Extract(salt, IKM): Extract a pseudorandom key of fixed length Nh
  from input keying material `IKM` and an optional octet string
  `salt`.
- Expand(PRK, info, L): Expand a pseudorandom key `PRK` using
  optional string `info` into `L` bytes of output keying material.

It also depends on the following utility function.

- `concat(x0, ..., xN)`: Concatenation of octet strings.
  `concat(0x01, 0x0203, 0x040506) = 0x010203040506`

# Key Import

A key importer takes as input an EPSK with external identity 'external_identity' and base key 'epsk',
as defined in {{terminology}}, along with an optional context string, and transforms
it into a set of PSKs and imported identities for use in a connection based on the (D)TLS protocol
version and a specific KDF. In particular, for each supported protocol version 'protocol' and KDF
function 'kdf', the importer constructs an ImportedIdentity structure as follows:

~~~
   struct {
       opaque external_identity<1...2^16-1>;
       opaque context<0..2^16-1>;
       uint16 protocol;
       uint16 kdf;
   } ImportedIdentity;
~~~

ImportedIdentity.context MUST include the context used to derive the EPSK, if any exists.  If the EPSK is a key derived
from some other protocol or sequence of protocols, ImportedIdentity.context MUST include a channel binding for the deriving protocols
{{!RFC5056}}.  If any secrets are agreed in earlier protocols they SHOULD be included in ImportedIdentity.context {{CCB}}.

ImportedIdentity.protocol MUST be the (D)TLS protocol version for which the PSK is being imported.
For example, TLS 1.3 and QUICv1 {{!I-D.ietf-quic-transport}} MUST use 0x0304, whereas TLS 1.2 uses 0x0303.
Note that this means future versions of TLS will increase the number of PSKs derived from an external PSK.

ImportedIdentity.kdf MUST be one of the KDF identifiers specified in {{kdf-registry}}.

A unique and imported PSK (IPSK) with base key 'ipskx' bound to this identity is then computed as follows:

~~~
   epskx = KDF.Extract(0, epsk)
   ipskx = KDF.Expand(epskx, concat("derived psk", Hash(ImportedIdentity)), KDF.Nh)
~~~

[[TODO: The length of ipskx MUST match that of the corresponding and supported ciphersuites.]]

The hash function used for HKDF {{!RFC5869}} is that which is associated with the external PSK. It is not
bound to ImportedIdentity.kdf. If no hash function is specified, SHA-256 MUST be used.
Differentiating EPSK by ImportedIdentity.kdf ensures that each imported PSK is only used with at most one
hash function, since each KDF is associated with one hash function, thereby satisfying the
requirements in {{!RFC8446}}.

Endpoints MUST import and derive an ipsk for each hash function used by each ciphersuite they support.
For example, importing a key for TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 would yield two PSKs,
one for SHA256 and another for SHA384. In contrast, if TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256
are supported, only one derived key is necessary.

The resulting IPSK base key 'ipskx' is then used as the binder key in TLS 1.3 with identity
ImportedIdentity. With knowledge of the supported hash functions, one may import PSKs before
the start of a connection.

EPSKs may be imported for early data use if they are bound to protocol settings and configurations that would
otherwise be required for early data with normal (ticket-based PSK) resumption. Minimally, that means ALPN,
QUIC transport settings, etc., must be provisioned alongside these EPSKs.

# Deprecating Hash Functions

If a client or server wish to deprecate a hash function and no longer use it for TLS 1.3, they may remove this
hash function from the set of hashes used during while importing keys. This does not affect the KDF operation
used to derive concrete PSKs.

# Backwards Compatibility and Incremental Deployment

Recall that TLS 1.2 permits computing the TLS PRF with any hash algorithm and PSK.
Thus, an external PSK may be used with the same KDF (and underlying
HMAC hash algorithm) as TLS 1.3 with importers. However, critically, the derived PSK will not
be the same since the importer differentiates the PSK via the identity and hash function. Thus,
PSKs imported for TLS 1.3 are distinct from those used in TLS 1.2, and thereby avoid
cross-protocol collisions. Note that this does not preclude endpoints from using non-imported
PSKs for TLS 1.2. Indeed, this is necessary for incremental deployment.

# KDF Identifier Registry {#kdf-registry}

The following table specifies KDF identities used in ImportedIdentity structures.

| Value  | KDF         | Nh  | Reference    |
|:-------|:------------|-----|:-------------|
| 0x0000 | (reserved)  | N/A | N/A          |
| 0x0001 | HKDF-SHA256 | 32  | {{?RFC5869}} |
| 0x0002 | HKDF-SHA512 | 64  | {{?RFC5869}} |

# Security Considerations

This is a WIP draft and has not yet seen significant security analysis.

# Privacy Considerations

External PSK identities are typically static by design so that endpoints may use them to
lookup keying material. However, for some systems and use cases, this identity may become a
persistent tracking identifier.

# IANA Considerations

This document makes no IANA requests.

--- back

# Acknowledgements

The authors thank Eric Rescorla and Martin Thomson for discussions that led to the production of this document,
as well as Christian Huitema for input regarding privacy considerations of external PSKs. John Mattsson
provided input regarding PSK importer deployment considerations.

# Addressing Selfie

The Selfie attack {{Selfie}} relies on a misuse of the PSK interface.
The PSK interface makes the implicit assumption that each PSK
is known only to one client and one server. If multiple clients or
multiple servers with distinct roles share a PSK, TLS only
authenticates the entire group. A node successfully authenticates
its peer as being in the group whether the peer is another node or itself.

Applications which require authenticating finer-grained roles while still
configuring a single shared PSK across all nodes can resolve this
mismatch either by exchanging roles over the TLS connection after
the handshake or by incorporating the roles of both the client and server
into the imported PSK context string. For instance, if an application
identifies each node by MAC address, it could use the following context string.

~~~
  struct {
    opaque client_mac<0..2^16-1>;
    opaque server_mac<0..2^16-1>;
  } Context;
~~~

If an attacker then redirects a ClientHello intended for one node to a different
node, the receiver will compute a different context string and the handshake
will not complete.

Note that, in this scenario, there is still a single shared PSK across all nodes,
so each node must be trusted not to impersonate another node's role.
