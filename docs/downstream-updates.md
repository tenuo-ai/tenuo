---
title: Downstream release updates
description: Propose integration dependency updates after a published Tenuo release
---

# Downstream release updates

The **Notify downstream integrations** workflow sends a release event to a configured repository after the Release or Authorizer Binaries workflow succeeds. It accepts stable published releases only, checks the completed run against the release tag's immutable commit, and supports manual replay.

The destination controller owns its integration registry, update rules, and PR creation. Keeping that controller private allows an organization to include private integrations without exposing their inventory or logs in core's public Actions runs. Core sends release coordinates only; it does not check out downstream repositories or modify their dependencies.

Configure these Actions settings in core:

| Name | Type | Purpose |
| --- | --- | --- |
| `TENUO_OPS_APP_ID` | Variable | GitHub App used to notify the controller |
| `TENUO_OPS_APP_PRIVATE_KEY` | Secret | The App's private-key PEM |
| `TENUO_DOWNSTREAM_CONTROLLER` | Variable | Controller repository name in the same organization |
| `TENUO_DOWNSTREAM_AUTOMATION_ENABLED` | Variable | Set to `true` when the controller is configured |

The notification token is limited to the controller repository with Contents write permission, as required for `repository_dispatch`. The workflow checks out trusted default-branch code and does not execute code or consume artifacts from the triggering workflow run.

The controller should independently verify publication readiness, read Python, Rust, and npm versions from the release commit, regenerate native lockfiles, and create ordinary PRs with integration CI. Package versions need not equal the Git tag. A scheduled reconciliation should recover missed notifications. Existing or declined PRs should not be recreated by retries.

The workflow stays inactive until explicitly enabled. Replaying the same release is safe when the controller implements idempotent PR creation.
