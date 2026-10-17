# Incident kill switches

Every switch in `lib/ops/flags.ts` → `PAUSABLE`, where it is enforced, and what an
operator should expect when it is flipped. For the step-by-step response to a
compromised agent key, see [`AGENT_INCIDENT_RUNBOOK.md`](AGENT_INCIDENT_RUNBOOK.md).

## Admin authentication is separate from user sessions

Admin routes do **not** accept user sessions. An operator reaches an admin route
only with a dedicated admin credential, and a user session cookie is never
sufficient, even for an account that happens to be an admin. This keeps a
compromised user session from reaching operational actions and keeps the funded
state governed by Soroban rather than by a browser cookie.

- **Malformed credential.** A missing, malformed or unparseable admin credential
  is rejected as unauthenticated. No admin action runs and no operational state
  changes.
- **Stale credential.** A credential that no longer validates (rotated secret,
  expired token) is rejected the same way. Operators rotate the admin secret and
  retry; nothing is cached across the rotation.
- **Duplicate / replay.** Admin actions are idempotent where the underlying
  operation is idempotent. A replayed request cannot double-apply a funded
  action; the Soroban state remains authoritative.
- **Cancelled / paused.** A paused capability still rejects admin-triggered
  writes exactly as it rejects user-triggered ones. Admin auth does not bypass a
  kill switch.
- **Dependency failure.** If the admin credential store or its dependency is
  unavailable, admin routes fail closed: they reject rather than fall back to
  user-session auth.
- **Secrets.** Admin credentials are read from the environment at call time and
  are never logged, echoed in responses, or included in audit payloads. No
  response reveals whether a credential was malformed versus stale.
- **Rollback.** Reverting to the previous admin-auth configuration is a config
  change only; no migration or contract change is involved. Funded flows are
  unaffected because they never depended on admin auth.

## The switches

Set `MIMIR_PAUSE_<CAPABILITY>=1` to pause one capability, or `MIMIR_PAUSE_ALL=1` to
pause every one of them. Only the exact value `1` pauses; `true`, `yes` or a typo
is a no-op. Optional: `MIMIR_PAUSE_<CAPABILITY>_REASON`, or `MIMIR_PAUSE_REASON` for
all of them, is shown to callers in place of the default message.

| Capability | Enforced at | Stops | Keeps running |
| --- | --- | --- | --- |
| `create_market` | `createClaim`, `createRematch`, `createSquadMarket` (`lib/contract.ts`); agent API `createMarket` | New binary markets, rematches and squad pools, including the demo relay and the market-creator worker | Staking into existing markets, settlement, cancel, withdraw |
| `stake` | `challengeClaim`, `squadDeposit` (`lib/contract.ts`); agent API `stake`, `vote` | Every new position: browser, demo relay, oracle auto-challenge, council and trader personas | Creating markets, settlement, payouts, withdraw |
| `oracle_settlement` | `resolveClaim` (`lib/contract.ts`); the oracle poll skips its settle loop | Resolution of expired markets. The oracle also stops researching and calling the LLM for them | Oracle auto-challenge (governed by `stake`), payouts of markets that are already resolved, withdraw |
| `copy_execution` | `evaluateCopy` (`lib/copy-trading.ts`), which reads the switch itself | Every copied position (skip reason `global_paused`) | Creating and revoking copy permissions |
| `x402_selling` | `paidRoute` via `lib/x402/kill-switch.ts` | Paid endpoints answer `503` with `Retry-After: 60` rather than `402` | Free endpoints, council-pass requests |
| `x402_buying` | `assertX402BuyingEnabled` (`lib/x402/buyer.ts`) | Agent purchases, refused before a paying client is built. `MIMIR_PAUSED_X402_BUYERS` pauses individual `G…` wallets | Callers treat a refused purchase as missing input and carry on without it |
| `research` | `gatewayFetch` (`lib/research/gateway.ts`) | Outbound source fetches. `RESEARCH_PAUSED_AGENT_IDS` pauses individual agents | Cached results already fetched |
| `agent_registration` | Agent API `register` | New BYOA registrations | Every call by already-registered agents |
| `market_creator_worker` | `reportingPoll` in `agents/market-creator` | The whole creation cycle | The process itself, plus its heartbeat |
| `council_worker` | `reportingPoll` in `agents/council` | The whole persona cycle | The process itself, plus its heartbeat |

**No switch on purpose:** `withdraw`, `claimChallengerPayout`, `claimFees`,
`squadClaim`, `squadWithdrawBeforeDeadline`, `cancelClaim`, every read path, and the
agent API's `revoke`, `revokeKey`, `revokeSpend`, `dryRun`, `proposeMarket` and
`heartbeat`. Users can always pull funds out, and owners can always contain a
compromised agent, including during the incident that paused everything else.

## Behavior

- **Failure.** A paused contract write throws with the operator's reason or
  `"<capability> is temporarily paused"`. Paid endpoints answer `503`. The agent
  API answers the standard retryable `agent_paused` error from
  `lib/server/pause-registry.ts`, which carries `capability` and `viaGlobal`, so an
  agent can branch without parsing the message. No response contains env names,
  addresses or keys. A paused agent API call is audited as `rejected / paused` and
  is checked before idempotent replay, so a cached success cannot be served while
  paused. A paused worker logs one line per cycle
  (`paused by MIMIR_PAUSE_…`) and records a healthy heartbeat. It does not exit,
  because `npm run workers` runs with `--kill-others-on-fail` and one exit would
  stop every worker.
- **Rollback.** Unset the variable, or set it to anything other than `1`. Nothing is
  cached: the first call after the process sees the new environment goes through.
  A paused settlement is delayed, never lost. Expired markets are settled on the
  first oracle poll after the switch clears.
- **Environment.** Switches are read from `process.env` at call time, so a flip
  needs no code change or build. It takes effect once the service has the new
  environment, which on Railway or Vercel means the restart or redeploy that
  changing a variable triggers. Workers and the web app each need their own copy
  of the variable.
- **Secrets.** None. A switch is a plain boolean, and no switch reads, logs or needs
  a key.
- **Artifacts.** None. No build output, migration or contract change is involved.
  The Soroban contracts are not aware of these switches: they stop Mimir's own
  off-chain callers, not a user who calls the contract directly.

## Verifying

From a clean checkout, with no `.env.local` and no network:

```sh
npm ci
npm run test:kill-switches
```

`tests/node/incident-kill-switches.test.ts` drives each switch at its enforcement
point. It checks that the capability runs when nothing is paused, stops under its
own switch and under `MIMIR_PAUSE_ALL`, and that pausing it leaves every other
capability running. It also checks that the exit paths above stay open with
everything paused. The probe table is typed as `Record<Pausable, Probe>`, so adding
a capability to `PAUSABLE` without wiring and testing it fails `npm run typecheck`.
The suite also runs as part of `npm run test:smoke` in CI.
