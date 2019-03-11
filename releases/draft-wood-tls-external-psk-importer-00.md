---
title: Importing External PSKs for TLS 1.3
abbrev: Importing External PSKs for TLS 1.3
docname: draft-wood-tls-external-psk-importer-00
category: exp

ipr: trust200902
area: General
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
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



--- abstract

This document describes an interface for importing external PSK (Pre-Shared Key) into
TLS 1.3.

--- middle

# Introduction

TLS 1.3 {{!RFC8446}} supports pre-shared key (PSK) resumption, wherein PSKs
can be established via session tickets from prior connections or externally via some out-of-band
mechanism. The protocol mandates that each PSK only be used with a single hash function.
This was done to simplify protocol analysis. TLS 1.2, in contrast, has no such requirement, as
a PSK may be used with any hash algorithm and the TLS 1.2 PRF. This means that external PSKs
could possibly be re-used in two different contexts with the same hash functions during key
derivation. Moreover, it requires external PSKs to be provisioned for specific hash
functions.

To mitigate these problems, external PSKs can be bound to a specific hash function when used
in TLS 1.3, even if they are associated with a different KDF (and hash function) when provisioned. This document
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
the key importer defined herein uses a label and set of hash algorithms to
differentiate an external PSK into one or more PSKs for use.

Imported keys do not require negotiation for use, as a client and server will not agree upon
identities if not imported correctly. Thus, importers induce no protocol changes with
the exception of expanding the set of PSK identities sent on the wire.

## Terminology {#terminology}

- External PSK (EPSK): A PSK established or provisioned out-of-band, i.e., not from a TLS connection, which is
a tuple of (Base Key, External Identity, KDF). The associated KDF (and hash function) may be undefined.
- Base Key: The secret value of an EPSK.
- External Identity: The identity of an EPSK.
- Imported Identity: The identity of a PSK as sent on the wire.

# Key Import

A key importer takes as input an EPSK with external identity 'external_identity' and base key 'epsk',
as defined in {{terminology}}, along with an optional label, and transforms it into a set of PSKs and
imported identities for use in a connection based on supported HashAlgorithms. In particular, for each
supported HashAlgorithm 'hash', the importer constructs an ImportedIdentity structure as follows:

~~~
   struct {
       opaque external_identity<1...2^16-1>;
       opaque label<0..2^8-1>;
       HashAlgorithm hash;
   } ImportedIdentity;
~~~

A unique and imported PSK (IPSK) with base key 'ipskx' bound to this identity is then computed as follows:

~~~
   epskx = HKDF-Extract(0, epsk)
   ipskx = HKDF-Expand-Label(epskx, "derived psk", Hash(ImportedIdentity), Hash.length)
~~~

The hash function used for HKDF {{!RFC5869}} is that which is associated with the external PSK. It is not
bound to ImportedIdentity.hash. If no hash function is specified, SHA-256 MUST be used.

The resulting IPSK base key 'ipskx' is then used as the binder key in TLS 1.3 with identity ImportedIdentity.

With knowledge of the supported hash functions, one may import PSKs before the start of
a connection.

EPSKs may be imported for early data use if they are bound to protocol settings and configurations that would
otherwise be required for early data with normal (ticket-based PSK) resumption. Minimally, that means ALPN,
QUIC transport settings, etc., must be provisioned alongside these EPSKs.

# Deprecating Hash Functions

If a client or server wish to deprecate a hash function and no longer use it for TLS 1.3, they may remove this
hash function from the set of hashes used during while importing keys. This does not affect the KDF operation
used to derive concrete PSKs.

# TLS 1.2 Compatibility

Key importers do not affect TLS 1.2 in any way. Recall that TLS 1.2 permits computing the TLS PRF with
any hash algorithm and PSK. Thus, a PSK may be used with the same KDF (and underlying HMAC hash algorithm) as
TLS 1.3 with importers. However, critically, the derived PSK will not be the same since the importer
differentiates the PSK via the identity and hash function. Thus, TLS 1.3 imported PSKs are distinct
from those used in TLS 1.2 and avoid cross-protocol collisions.

# Security Considerations

This is a WIP draft and has not yet seen significant security analysis.

# IANA Considerations

This document has no IANA requirements.

--- back

# Acknowledgements

The authors thank David Benjamin, Eric Rescorla, and Martin Thomson for discussions that led to the production of this document.

