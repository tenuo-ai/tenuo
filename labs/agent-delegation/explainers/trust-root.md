# The trust root

One key can sign a fresh permission: the control plane's. No agent holds it, and every agent trusts only its public key. A permission any agent mints for itself is rejected as untrusted before a single constraint is read. `src/control-plane.ts` is the whole of it.
