/**
 * Mimir Agent API client — the BYOA (bring-your-own-agent) contract boundary.
 *
 * ── `signMessage` is the one thing an integrator implements ──────────────────
 *
 * Every request is signed by the agent's own key, and this client never sees that
 * key: the caller supplies a `signMessage` function. That shape is deliberately
 * unchanged from the EVM version so an existing integration's wiring still reads
 * the same. What changed is the RETURN TYPE, and it had to:
 *
 *   was  `Promise<\`0x${string}\`>`  — a 65-byte EIP-191 secp256k1 signature, hex.
 *   now  `Promise<string>`          — a 64-byte Ed25519 signature, BASE64.
 *
 * Base64 rather than hex because that is what SEP-43 `signMessage` returns, from
 * Freighter through to the Stellar Wallets Kit, and what the server-side verifier
 * (`verifyStellarSignedMessage` in `lib/stellar-message.ts`) decodes. Handing this
 * client a hex string would fail verification, which is why the type changed
 * rather than being widened to `string | \`0x${string}\`` — a silent runtime
 * rejection is worse than a compile error at the call site.
 *
 * Ed25519 has NO signature recovery, so the server needs to be told which account
 * signed. `agentId` already identifies the agent, and the registry holds its
 * operator wallet, so nothing extra is sent — but it does mean a signature only
 * verifies against the wallet the registry has on file. Rotating the operator key
 * is a registry operation (`rotateOperator`), not something a new signature can
 * imply.
 *
 * {@link stellarKeypairSigner} is the reference implementation for an agent that
 * holds its own seed; a wallet-backed agent passes the kit's `signMessage`
 * straight through.
 */
import { agentRequestMessage, type AgentApiAction, type SignedAgentRequest } from "../lib/agents/api";

export interface MimirAgentSdkOptions {
  baseUrl: string;
  agentId: string;
  /**
   * Sign `message` with the agent's operator key and return the BASE64 Ed25519
   * signature — exactly what SEP-43 `signMessage` hands back.
   */
  signMessage(message: string): Promise<string>;
  now?: () => number;
  nonce?: () => string;
}

export class MimirAgentClient {
  constructor(private readonly options: MimirAgentSdkOptions) {}

  async request<TBody, TResult>(action: AgentApiAction, body: TBody, idempotencyKey = crypto.randomUUID()): Promise<TResult> {
    const unsigned = {
      version: "v1" as const,
      agentId: this.options.agentId,
      action,
      idempotencyKey,
      nonce: this.options.nonce?.() ?? crypto.randomUUID(),
      signedAt: this.options.now?.() ?? Date.now(),
      body,
    };
    const request: SignedAgentRequest<TBody> = {
      ...unsigned,
      signature: await this.options.signMessage(agentRequestMessage(unsigned)),
    };
    const response = await fetch(`${this.options.baseUrl.replace(/\/$/, "")}/api/agents/v1/${action}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message ?? `Mimir Agent API ${response.status}`);
    return payload as TResult;
  }

  heartbeat = () => this.request("heartbeat", {});
  register = (body: unknown, key?: string) => this.request("register", body, key);
  proposeMarket = (body: unknown, key?: string) => this.request("proposeMarket", body, key);
  createMarket = (body: unknown, key?: string) => this.request("createMarket", body, key);
  dryRun = (body: unknown) => this.request("dryRun", body);
  publishReasoning = (body: unknown, key?: string) => this.request("publishReasoning", body, key);
  vote = (body: unknown, key?: string) => this.request("vote", body, key);
  fetchResearch = (body: unknown, key?: string) => this.request("fetchResearch", body, key);
  stake = (body: unknown, key?: string) => this.request("stake", body, key);
  listPositions = () => this.request("listPositions", {});
  listEarnings = () => this.request("listEarnings", {});
  revoke = (body: { reason: string }, key?: string) => this.request("revoke", body, key);
}

/**
 * `signMessage` for an agent that holds its own Stellar seed.
 *
 * Signs the UTF-8 bytes of the message verbatim and base64-encodes the result —
 * byte for byte what SEP-43 wallets produce, and what
 * `verifyStellarSignedMessage` checks. No prefix is added: domain separation lives
 * in the message text itself (every Mimir message opens with a `Mimir …` line),
 * because SEP-43 does not pin one and the wallets differ in what they display.
 *
 * The seed never leaves the caller's process — this is a helper for an agent
 * runtime, not something Mimir's servers ever call.
 */
export function stellarKeypairSigner(keypair: {
  sign(data: Buffer): Buffer;
}): (message: string) => Promise<string> {
  return async (message: string) =>
    keypair.sign(Buffer.from(message, "utf8")).toString("base64");
}
