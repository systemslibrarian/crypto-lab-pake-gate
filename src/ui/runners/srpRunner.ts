// SRP-6a runner. Client/Server, augmented. A one-time register() must happen before
// stepping; the runner is constructed with an already-stored {salt, v} record and the
// client's password (which may differ from the registered one for "wrong password").

import { Wire } from "../../pake/wire.ts";
import { makeSrpClient, makeSrpServer } from "../../pake/factories.ts";
import type {
  SrpClientSession,
  SrpServerSession,
  SrpVerifierRecord,
} from "../../pake/srp6a.ts";
import type { Password, WireMsg } from "../../pake/types.ts";
import {
  bigHex,
  bytesHex,
  type KeyView,
  type PeerView,
  type Runner,
  type ScratchRow,
  type TamperOp,
  type WireCard,
} from "../model.ts";
import { StepMachine, eqBytes } from "./base.ts";

const TAMPER: TamperOp[] = [
  {
    id: "srp-m1",
    label: "Corrupt the client proof M1",
    step: "client-proof",
    field: "M1",
    expect: "Server recomputes M1 from K and rejects — 'M1 mismatch' — handshake aborts before it sends M2.",
  },
  {
    id: "srp-m2",
    label: "Corrupt the server proof M2",
    step: "server-proof",
    field: "M2",
    expect: "Client recomputes M2 and rejects — 'M2 mismatch' — mutual auth fails; the client's key is never confirmed.",
  },
];

export class SrpRunner extends StepMachine implements Runner {
  readonly protocol = "srp6a" as const;
  private readonly wire = new Wire();
  private readonly client: SrpClientSession;
  private readonly server: SrpServerSession;

  constructor(
    private readonly I: string,
    clientPassword: Password,
    private readonly record: SrpVerifierRecord,
  ) {
    super();
    this.client = makeSrpClient(I, clientPassword);
    this.server = makeSrpServer(record);
    this.build();
  }

  private build(): void {
    let clientHello: WireMsg, serverHello: WireMsg, clientProof: WireMsg, serverProof: WireMsg;
    let clientProofCard: WireCard, serverProofCard: WireCard;
    this.stages.push(
      {
        label: "Client → hello (A)",
        run: () => { clientHello = this.client.hello(); return this.push(clientHello, ["A"], "The client sends its public Diffie–Hellman share A = g^a — useless to an eavesdropper without the password."); },
      },
      {
        label: "Server → hello (salt, B)",
        run: () => {
          const delivered = this.wire.send(clientHello);
          serverHello = this.server.hello(delivered);
          return this.push(serverHello, ["salt", "B"], "The server replies with the public salt and its own share B, blinded by the stored verifier — the password itself is never sent.");
        },
      },
      {
        label: "Client → proof (M1)",
        run: () => {
          const delivered = this.wire.send(serverHello);
          clientProof = this.maybeTamper(this.client.proof(delivered));
          return (clientProofCard = this.push(clientProof, ["M1"], "The client proves it derived the same secret S by sending a MAC M1 — this is evidence, not the key or the password."));
        },
      },
      {
        label: "Server verifies M1 → proof (M2)",
        run: () => {
          const delivered = this.wire.send(clientProof);
          this.consuming = clientProofCard;
          serverProof = this.maybeTamper(this.server.proof(delivered));
          return (serverProofCard = this.push(serverProof, ["M2"], "The server checks M1, then proves it back with M2 — mutual confirmation that both landed on the same key."));
        },
      },
      {
        label: "Client verifies M2 → confirmed",
        run: () => {
          const delivered = this.wire.send(serverProof);
          this.consuming = serverProofCard;
          this.client.confirm(delivered);
          this.finish();
          return null;
        },
      },
    );
  }

  private finish(): void {
    const lk = this.client.sessionKeyBytes;
    const rk = this.server.sessionKeyBytes;
    const confirmed = this.client.phase === "confirmed" && this.server.phase === "confirmed";
    this.status_ = confirmed && eqBytes(lk, rk)
      ? { kind: "confirmed" }
      : { kind: "mismatch", message: "Keys differ or confirmation incomplete — handshake did not confirm." };
  }

  leftPeer(): PeerView {
    const t = this.client.trace;
    const scratch: ScratchRow[] = [
      { label: "a (private nonce)", plain: "my private nonce", term: "nonce", value: t.a !== undefined ? bigHex(t.a) : "—", secret: true },
      { label: "x = H(salt, H(I:P))", plain: "my password-derived secret", term: "premaster", value: t.x !== undefined ? bigHex(t.x) : "—", secret: true },
      { label: "A = g^a", plain: "my public share", term: "gpow", value: t.A !== undefined ? bigHex(t.A) : "—", secret: false },
      { label: "u = H(A,B)", plain: "shared scrambler", value: t.u !== undefined ? bigHex(t.u) : "—", secret: false },
      { label: "S (premaster)", plain: "my raw shared secret", term: "premaster", value: t.S !== undefined ? bigHex(t.S) : "—", secret: true },
    ];
    return { title: "Client", role: `identity "${this.I}"`, scratch };
  }

  rightPeer(): PeerView {
    const t = this.server.trace;
    const scratch: ScratchRow[] = [
      { label: "stored salt", plain: "stored salt (public)", term: "salt", value: bytesHex(this.record.salt), secret: false },
      { label: "stored v (verifier)", plain: "stored verifier (NOT the password)", term: "verifier", value: bigHex(this.record.v), secret: true },
      { label: "b (private nonce)", plain: "my private nonce", term: "nonce", value: t.b !== undefined ? bigHex(t.b) : "—", secret: true },
      { label: "B = k·v + g^b", plain: "my public share", term: "gpow", value: t.B !== undefined ? bigHex(t.B) : "—", secret: false },
      { label: "S (premaster)", plain: "my raw shared secret", term: "premaster", value: t.S !== undefined ? bigHex(t.S) : "—", secret: true },
    ];
    return { title: "Server", role: "holds only {salt, v}", scratch };
  }

  leftKey(): KeyView {
    const k = this.client.sessionKeyBytes;
    return { present: !!k, keyBytes: k, confirmed: this.client.phase === "confirmed" };
  }
  rightKey(): KeyView {
    const k = this.server.sessionKeyBytes;
    return { present: !!k, keyBytes: k, confirmed: this.server.phase === "confirmed" };
  }
  tamperMenu(): TamperOp[] {
    return TAMPER;
  }
}
