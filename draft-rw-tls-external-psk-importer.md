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
       ins: E. Rescorla
       name: Eric Rescorla
       organization: RTFM, Inc.
       email: ekr@rtfm.com


normative:
  RFC1035:
  RFC2119:
  RFC6234:

informative:



--- abstract

TODO

--- middle

# Introduction

TLS 1.3 {{!I-D.ietf-tls-tls13}} supports pre-shared key (PSK) resumption, wherein PSKs
can be established via session tickets from prior connections or externally via some out-of-band
mechanism. The protocol mandates that each PSK only be used with a single hash function. 
This was done to simplify protocol analysis. TLS 1.2, in contrast, has no such requirement, as
a PSK may be used with any hash algorithm and the TLS 1.2 PRF. This means that PSKs external PSKs 
could possibly be re-used in two different contexts with the same hash functions during key 
derivation, which is possibly insecure.

To mitigate this problem, external PSKs should be bound to the specific hash function when used
in TLS 1.3, even if they are provisioned with a KDF using a different hash function. This document
specifies an interface by which external PSKs may be imported to achieve this goal. In particular,
it describes how KDF-bound PSKs can be differentiated by different hash algorithms to produce
a set of candidate PSKs, each of which bound to a specific hash function. This expands what would
normally have been a single PSK identity into a set of PSK identities. However, it requires
no change to the TLS 1.3 key schedule. 

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Overview

Intuitively, key importers mirror the concept of key exporters in TLS, in that they
diversify a key based on some contextual information before use in a connection. In contrast to
key exporters, wherein differentiation is done via an explicit context string, the key importer
interface defined herein uses hash algorithms to differentiate an external PSK into 
one or more PSKs for use. 

Imported keys do not require negotiation for use, as client and server will not agree upon
identities if not imported correctly. Thus, importers induce no protocol changes with 
the exception of expanding the set of PSK identities sent on the wire.

## Terminology {#terminology}

- External PSK: A PSK established or provisioned out-of-band, i.e., not from a TLS connection, which is 
a tuple of (BaseKey, ExternalIdentity, KDF).
- ExternalIdentity: The identity of an external PSK. 
- ImportedIdentity: The identity of a PSK as sent on the wire.
- ...

# Key Import

A key importer takes as input an external PSK as defined in Section {{terminology}} and transforms it
into a set of PSKs for use in a connection based on the supported HashAlgorithms. In particular, it 
builds an ExternalIdentity into an InternalIdentity as follows:

```
   struct {
       opaque external_identity<1...2^16-1>;
       HashAlgorithm hash;
   } imported_identity;
```

Using an ImportedIdentity, and an external PSK epsk, one then derives a concrete PSK for use in TLS
as follows:

```
   epskx = HKDF-Extract(0, epsk)
   PSKx = HKDF-Expand-Label(epskx, "derived psk", Hash(imported_identity), Hash.length)
```

The hash function used for this KDF is that which is associated with the external PSK. It is not bound to 
the hash function included in the ImportedIdentity.

# Deprecating Hash Functions

If a client or server wish to deprecate a hash function and no longer use it for TLS, they simply remove this
hash function from the set of hashes used during the import stage. This does not affect the KDF operation used
to derive concrete PSKs.

# Security Considerations

This is a WIP draft and has not yet seen significant security analysis.

# IANA Considerations

This document has no IANA requirements.

--- back

# Acknowledgements

The authors thank David Benjamin for discussions that led to the production of this document.

