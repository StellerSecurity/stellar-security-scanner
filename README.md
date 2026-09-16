# Stellar shared scanner

Generic first-party static source and dependency-content scanners. Repository files and package archives are data; they are never installed or executed. Reusable workflows embed the reviewed module bytes and verify them before execution. No mutable remote code is fetched.

The four thin callers use `StellerSecurity/stellar-security-scanner/.github/workflows/…@main`. Updates to this main branch therefore change future scanner executions. Native proofs bind the actual reusable workflow commit resolved for each run, its workflow bytes and scanner manifest. Caller contract and scanner implementation version are separate.

Public reusable code receives no repository contents-write or actions-write permission and no onboarding App credential. Collection, durable queue writes and onboarding run separately in fixed repository-local or private code. Only the two explicitly named Pushover secrets reach notification steps; no secret is stored here.

Incomplete package coverage is not clean evidence. Capability-only correlations remain named diagnostics and do not cause malware push notifications. A verified malware indicator can alert; old source-only results cannot prove new package coverage. Device delivery cannot be established from Pushover API acceptance alone.

Public exports contain only generic first-party scanner sources and workflow templates. The independently pinned proof verifier stays in the local/private broker; it never imports executable public code. No private application inventory, operator state, credentials, samples or private onboarding code is included.
