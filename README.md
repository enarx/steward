# steward


## Overview

Steward is a critical element of the Confidential Computing infrastructure.
The promise of Confidential Computing is fully utilized when the workload
runtime (Enarx WebAssembly) deployed into a Trusted Execution Environment
(TEE) is assessed and verified for correctness before an actual workload
is released into a TEE from the registry (Drawbridge). An external
**attestation service** must perform evidence verification and assessment
of the hardware's trustworthiness.

**Steward implements such attestation service in a modular, pluggable
and scalable way.**

**Modular:** The architecture of the Trusted Execution Environments
significantly differs between hardware vendors. As a result, the content
and structure of the evidence information are vendor-specific. The Steward
employs modular design to process specific types of evidence in different
backends.

**Pluggable:** Steward employs a pluggable and extensible architecture
to allow the addition of new evidence information to the evidence payload
as well as the support of new hardware architectures.

**Scalable:** Steward service is stateless. It receives a request with
all the information from the client and makes an assessment. As a result,
it is very lightweight and can be scaled up and down in response to
the request load.

Attesting the hardware and workload runtime is only one part of
the Steward's responsibility. The other is the translation of the vendor
and use-case-specific attestation evidence into a format that standard
services and interfaces on the Internet can trust. Such a standard is PKI,
so Steward acts as a Certificate Authority that assesses the attestation
evidence and issues a certificate based on this evidence. The certificate
is returned to the workload and used by it to participate in
the authenticated data exchanges with other services over the encrypted
connections.

## Design Materials

- [Attestation Concept](https://hackmd.io/@enarx/r1Yg2kb_s)
- [Attestation Flow](https://hackmd.io/@enarx/SySK2_tHo)
- [Full Provisioning Flow](https://hackmd.io/@enarx/rJ55urrvo)

## Licensing and Copyright

Contributions to this project require copyright assignment to Profian.

License: AGPL-3.0
