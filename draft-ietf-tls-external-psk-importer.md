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
       ins: J. G. Hoyland
       name: Jonathan G. Hoyland
       organization: Cloudflare, Inc.
       email: jhoyland@cloudflare.com
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

TLS 1.3 supports PSK-based handshakes, wherein PSKs can be established either via session tickets from prior TLS connections or via an out-of-band mechanism.
TLS 1.3 mandates that each PSK be associated with a single hash function.
This makes it easier for formal analysis to exclude cross-protocol attacks where the same key is used in multiple different contexts.
TLS 1.2 also supports PSK-based handshakes, but does not require they be provisioned with a single hash function.
Any PSK may be used with any supported hash function and the TLS 1.2 PRF.
This means that PSKs can be used in different contexts within TLS 1.2, and further can be used in TLS 1.2 and TLS 1.3 with the same hash function.
Therefore a server that accepts both TLS 1.2 and TLS 1.3 PSK handshakes with the same PSK could potentially be vulnerable to cross-protocol attacks.

This draft describes a method for processing PSKs such that they can be securely used with both TLS 1.2 and TLS 1.3.
The design allows for a PSK to be imported into TLS 1.3 with any supported hash function.
PSKs provisioned with one hash function can be processed to produce a set of candidate PSKs, each of which is bound to a potentially different and specific hash function.
This expands what would normally have been a single PSK identity into a set of PSK identities.
Notably, this makes no wire format changes and requires no change to the TLS 1.3 key schedule.


# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Overview

Intuitively, key importers mirror the concept of key exporters in TLS in that they
diversify a key based on some contextual information before use in a connection. In contrast to
key exporters, wherein differentiation is done via an explicit label and context string,
the key importer defined herein uses a label and set of hash algorithms to
differentiate an external PSK into one or more PSKs for use.
The goal of both key exporters and key importers is to produce a unique channel binding that ensures that both parties agree on all relevant context.

Imported keys do not require negotiation for use, as a client and server will not agree upon
identities if not imported correctly unless the adversary is able to choose the out-of-band (OOB) PSK for one of the parties.
Thus, importers induce no protocol changes with
the exception of expanding the set of PSK identities sent on the wire. Endpoints may incrementally
deploy PSK importer support by offering non-imported keys for TLS versions prior to TLS 1.3.
(Negotiation and use of imported PSKs requires both endpoints support the importer API described herein.)

## Terminology {#terminology}

- External PSK (EPSK): A PSK established or provisioned out-of-band, i.e., not from a TLS connection, which is
a tuple of (Base Key, External Identity, KDF). The associated KDF (and hash function) may be undefined.
- Base Key: The secret value of an EPSK.
- External Identity: The identity of an EPSK.
- Imported Identity: The identity of a PSK as sent on the wire.

# Key Import

A key importer takes as input an EPSK with external identity 'external_identity' and base key 'epsk',
as defined in {{terminology}}, along with an optional label, and transforms
it into a set of PSKs and imported identities for use in a connection based on supported HashAlgorithms.
In particular, for each supported HashAlgorithm 'hash', the importer constructs an ImportedIdentity
structure as follows:

~~~
   struct {
       opaque external_identity<1...2^16-1>;
       opaque label<0..2^8-1>;
       HashAlgorithm hash;
   } ImportedIdentity;
~~~

[[TODO: An alternative design might combine label and hash into the same field so that future
protocols which don't have a notion of HashAlgorithm don't need this field.]]

ImportedIdentity.label MUST be bound to the protocol into which the key is imported. Thus,
TLS 1.3 and QUICv1 {{!I-D.ietf-quic-transport}} MUST use the label "tls13". Similarly, TLS 1.2 and
all prior TLS versions should use "tls12" as ImportedIdentity.label, as well as SHA256 as ImportedIdentity.hash.
Note that this means future versions of TLS will increase the number of PSKs derived from an external PSK.

A unique and imported PSK (IPSK) with base key 'ipskx' bound to this identity is then computed as follows:

~~~
   epskx = HKDF-Extract(0, epsk)
   ipskx = HKDF-Expand-Label(epskx, "external psk importer",
                             Hash(Context), Hash.length)
~~~

The `Context` in this case includes the `ImportedIdentity` plus any necessary additional security context information.

~~~
  struct {
    opaque channel_binding<1..2^16>;
    opaque secrets<0..2^16>;
  } PriorContext
~~~
~~~
  struct {
      ImportedIdentity imported_psk;
      opaque client_id<0..2^16>;
      PriorContext prior_contexts<0..2^16>;
  } Context;
~~~

The `client_id` is an optional field that is required to be unique for each actor that knows the the EPSK.
This is to prevent Selfie-style reflections.
This is only necessary in scenarios where more than two actors use the same key, including the case where a single agent will complete PSK handshakes as both the client and the server using the same key.
The Selfie attack {{!Selfie}} abuses an underlying assumption of TLS, that only one client and one server know a PSK.
A pair of agents that both act as both client *and* server, and use the same PSK in both roles violate this assumption.
There are two clients and two servers that know the PSK.
The agents are thus both vulnerable to reflection attacks where the attacker forces the agent to act as both client and server in a single connection.
This is because neither agent can distinguish between itself and its peer.
By hashing a distinguishing value into PSK binder, a server that recieved a reflected `ClientHello` would be unable to verify the binder, and would reject the connection.

For example a distinguishing string for IoT devices could be a MAC address, and for VMs it could be a namespace.
The decision to use this field, and what it should contain must be agreed OOB.
N.B. this value is never sent on the wire, as this would identify the client even to passive adverseries.


`prior_contexts` is a list of prior security contexts, consisting of channel bindings and any associated keys.
In the standard case this list will be empty, as the TLS connection is not wrapped in a prior security context.
However if the OOB PSK was established through a protocol, or series of protocols, that provide a continuing security context, then including the channel binding for these contexts, as well as any keys established, binds the security contexts together.
This makes it easier to reason formally about the exact properties are provided by the combined series of protocols.
For example consider chaining together two TLS sessions, but using OOB PSK importers rather than resumption.
One could then include the prior context `<exporter_key, master_secret>`, where `exporter key` is computed using the exporter interface and a label that uniquely defines this particular setup.
This allows reasoning about the security contexts of both sessions at once.

[[TODO: The length of ipskx MUST match that of the corresponding and supported ciphersuites.]]

The hash function used for HKDF {{!RFC5869}} is that which is associated with the external PSK. It is not
bound to ImportedIdentity.hash. If no hash function is specified, SHA-256 MUST be used.
Differentiating epsk by ImportedIdentity.hash ensures that each imported PSK is only used with at most one
hash function, thus satisfying the requirements in {{!RFC8446}}. Endpoints MUST import and derive an ipsk
for each hash function used by each ciphersuite they support. For example, importing a key for
TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 would yield two PSKs, one for SHA256 and another
for SHA384. In contrast, if TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256 are supported,
only one derived key is necessary.

The resulting IPSK base key 'ipskx' is then used as the binder key in TLS 1.3 with identity
ImportedIdentity. With knowledge of the supported hash functions, one may import PSKs before
the start of a connection.

EPSKs may be imported for early data use if they are bound to protocol settings and configurations that would
otherwise be required for early data with normal (ticket-based PSK) resumption. Minimally, that means ALPN,
QUIC transport settings, etc., must be provisioned alongside these EPSKs.

# Label Values

For clarity, the following table specifies PSK importer labels for varying instances of the TLS handshake.

| Protocol   | Label   |
|:----------:|:-------:|
| TLS 1.3 {{!RFC8446}} | "tls13" |
| QUICv1 {{!I-D.ietf-quic-transport}} | "tls13" |
| TLS 1.2 {{!RFC5246}} | "tls12" |
| DTLS 1.2 {{!RFC6347}} | "dtls12" |
| DTLS 1.3 {{!I-D.ietf-tls-dtls13}} | "dtls13" |

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

# Security Considerations

This is a WIP draft and has not yet seen significant security analysis.

# Privacy Considerations

DISCLAIMER: This section contains a sketch of a design for protecting external PSK identities.
It is not meant to be implementable as written.

External PSK identities are typically static by design so that endpoints may use them to
lookup keying material. For some systems and use cases, this identity may become a persistent
tracking identifier. One mitigation to this problem is encryption. Future drafts may specify
a way for encrypting PSK identities using a mechanism similar to that of the Encrypted
SNI proposal {{?I-D.ietf-tls-esni}}. Another approach is to replace the identity with an
unpredictable or "obfuscated" value derived from the corresponding PSK. One such proposal, derived
from a design outlined in {{?I-D.ietf-dnssd-privacy}}, is as follows. Let ipskx be the imported
PSK with identity ImportedIdentity, and N be a unique nonce of length equal to that of ImportedIdentity.hash.
With these values, construct the following "obfuscated" identity:

~~~
   struct {
       opaque nonce[hash.length];
       opaque obfuscated_identity<1..2^16-1>;
       HashAlgorithm hash;
   } ObfuscatedIdentity;
~~~

ObfuscatedIdentity.nonce carries N, ObfuscatedIdentity.obfuscated_identity carries HMAC(ipskx, N),
where HMAC is computed with ImportedIdentity.hash, and ObfuscatedIdentity.hash is ImportedIdentity.hash.

Upon receipt of such an obfuscated identity, a peer must lookup the corresponding PSK by exhaustively
trying to compute ObfuscatedIdentity.obfuscated_identity using ObfuscatedIdentity.nonce and each of its
known imported PSKs. If N is chosen in a predictable fashion, e.g., as a timestamp, it may be possible
for peers to precompute these obfuscated identities to ease the burden of trial decryption.

# IANA Considerations

This document makes no IANA requests.

--- back

# Acknowledgements

The authors thank Eric Rescorla and Martin Thomson for discussions that led to the production of this document,
as well as Christian Huitema for input regarding privacy considerations of external PSKs. John Mattsson
provided input regarding PSK importer deployment considerations.

