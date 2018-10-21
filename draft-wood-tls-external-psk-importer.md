---
title: External PSK Importers for TLS 1.3
abbrev: TLS 1.3 External PSK Importers
docname: draft-rw-tls-external-psk-importer-latest
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

This document describes a TLS interface for importing external PSK (Pre-Shared Key) into
TLS 1.3.

--- middle

# Introduction

TLS 1.3 {{!I-D.ietf-tls-tls13}} supports pre-shared key (PSK) resumption, wherein PSKs
can be established via session tickets from prior connections or externally via some out-of-band
mechanism. The protocol mandates that each PSK only be used with a single hash function.
This was done to simplify protocol analysis. TLS 1.2, in contrast, has no such requirement, as
a PSK may be used with any hash algorithm and the TLS 1.2 PRF. This means that external PSKs
could possibly be re-used in two different contexts with the same hash functions during key
derivation, which is possibly insecure.

To mitigate this problem, external PSKs should be bound to the specific hash function when used
in TLS 1.3, even if they are provisioned with a KDF using a different hash function. This document
specifies an interface by which external PSKs may be imported for use in a TLS 1.3 connection
to achieve this goal. In particular, it describes how KDF-bound PSKs can be differentiated by
different hash algorithms to produce a set of candidate PSKs, each of which bound to a specific
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
the key importer interface defined herein uses a label and set of hash algorithms to
differentiate an external PSK into one or more PSKs for use.

Imported keys do not require negotiation for use, as client and server will not agree upon
identities if not imported correctly. Thus, importers induce no protocol changes with
the exception of expanding the set of PSK identities sent on the wire.

## Terminology {#terminology}

- External PSK (EPSK): A PSK established or provisioned out-of-band, i.e., not from a TLS connection, which is
a tuple of (Key, External Identity, KDF). The associated KDF (and hash function) may be undefined,
in which case HKDF with SHA-256 should used.
- Base Key: The secret value of a EPSK.
- External Identity: The identity of an EPSK.
- Imported Identity: The identity of a PSK as sent on the wire.

# Key Import

A key importer takes as input an EPSK with external identity 'external_identity' and key 'epsk',
as defined in {{terminology}}, along with
an optional label, and transforms it into a set of PSKs and imported identities for use in a connection
based on supported HashAlgorithms. In particular, for each HashAlgorithm hash, the importer constructs
an ImportedIdentity structure as follows:

~~~
   struct {
       opaque external_identity<1...2^16-1>;
       HashAlgorithm hash;
       opaque label<0..2^8-1>;
   } ImportedIdentity;
~~~

A unique and imported PSK (IPSK) bound to this identity is then computed as follows:

~~~
   epskx = HKDF-Extract(0, epsk)
    PSKi = HKDF-Expand-Label(epskx, "derived psk", Hash(ImportedIdentity), Hash.length)
~~~

The hash function used for this KDF is that which is associated with the external PSK. It is not
bound to ImportedIdentity.hash. If no hash function is specified, SHA-256 MUST be used.

The resulting IPSK value PSKi is then used as a PSK in TLS 1.3 with identity ImportedIdentity.

With knowledge of the supported hash functions, one may import PSKs before the start of
a connection.

# Deprecating Hash Functions

If a client or server wish to deprecate a hash function and no longer use it for TLS, they simply remove this
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

The authors thank David Benjamin and Eric Rescorla for discussions that led to the production of this document.

