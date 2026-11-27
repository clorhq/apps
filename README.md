# Clor Apps SDK for Go

Build self-hosted apps that ship on [Clor Apps](https://apps.clor.com): verify
license files and signed configuration, sign people in through Apps, check MCP
access tokens, and give your app's CLI account and team commands.

```bash
go get github.com/clorhq/apps
```

| Package | What it holds |
|---|---|
| `sdk` | Application configuration, Apps sign-in for browsers and terminals, licenses, TLS, and MCP access-token verification |
| `sdk/echo` | An Echo v4 adapter for `sdk` |
| `sdk/account` | The Apps account API: teams, instances, and identity tokens |
| `sdk/cli` | Cobra commands for an app's CLI: account, team, instance, login, and license |
| `license` | Signed license files: verification, key rotation, and armor |
| `identity` | Verification of Apps identity tokens |
| `model` | The protocol's names: environment variables, headers, routes, and documents |
| `security` | Sealed cookies and tokens, and checked file downloads |

`license.VerifyLicense` checks a license's signature against keys your app
trusts; enforcing its start and expiry is your app's decision. Keys from the
environment never establish trust on their own.

Terminal sign-in (an app CLI's `login`) exchanges each sign-in once. By
default the SDK remembers exchanged sign-ins in the app process's memory, so
within a sign-in's 5-minute lifetime a restart, or a second replica of the
instance, does not know it was used. An app that runs replicas, or wants that
window closed, sets `NewClientArgs.SpentNonces` to a store every process
shares.

This module is generated from Clor's source; changes are made there.
