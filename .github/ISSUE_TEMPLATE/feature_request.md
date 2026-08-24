---
name: Feature request
about: Suggest a capability or a change to the runtime contract
title: ''
labels: enhancement
assignees: ''
---

**The problem**
What are you trying to enforce that scannerctl does not support today?

**Proposed solution**
What you would like to see, and which command or contract field it touches.

**Alternatives considered**
Other approaches you have thought about.

**Scope note**
scannerctl is a provider-neutral scanning and egress-enforcement runtime. Rules,
routes, credentials, deployment topology, and target identities belong to the
deployment that configures it, not to this repository. A proposal that requires
this repo to know about a specific fleet, host, or tenant is out of scope.

**Contract impact**
Would this change the four-verdict result, the exit codes, or a published
schema? Those are versioned; say which version you expect to change.
