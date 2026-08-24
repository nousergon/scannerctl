---
name: Bug report
about: Something in the runtime does not behave as the contract says
title: ''
labels: bug
assignees: ''
---

**What happened**
A clear description of the behaviour.

**What the contract says should happen**
Quote the relevant line of `docs/contract.md` or `README.md` where you can.

**Steps to reproduce**
1.
2.
3.

**Environment**
- scannerctl version: <!-- `scannerctl version --format json` -->
- Platform: <!-- darwin-arm64 / linux-amd64 / ... -->
- Install: <!-- release bundle / OCI image / source checkout -->

**Output**
```
paste the scan result, self-test output, or traceback here
```

**Please do not paste real secrets.** scannerctl redacts findings; a reproducer
should use a synthetic credential such as the one in the must-detect canary.
