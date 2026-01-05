import { useMemo, useState, useEffect, useRef } from "react";
import * as secp from "@noble/secp256k1";

import {
  encryptTextRaw,
  validateEnvelope,
  wrapDEK_secp256k1,
  unwrapDEK_secp256k1,
  decryptTextFromEnvelope,
} from "@privacyx/pxp201";

import { downloadText, hexToU8, nowUnix, u8ToHex } from "./lib/format.js";

const tabs = [
  { id: "encrypt", label: "Encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "wk1", label: "WK1 Wrap/Unwrap" },
  { id: "vectors", label: "Test vectors" },
];

function classNames(...xs) {
  return xs.filter(Boolean).join(" ");
}

function Pill({ children }) {
  return (
    <span className="inline-flex items-center rounded-full bg-zinc-900 px-2 py-1 text-xs text-zinc-300 ring-1 ring-zinc-800">
      {children}
    </span>
  );
}

function Field({ label, hint, children }) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3">
        <div className="text-sm font-medium text-zinc-200">{label}</div>
        {hint ? <div className="text-xs text-zinc-500">{hint}</div> : null}
      </div>
      <div className="mt-2">{children}</div>
    </div>
  );
}

function Textarea(props) {
  return (
    <textarea
      {...props}
      className={classNames(
        "w-full min-h-[120px] resize-y rounded-xl bg-zinc-900/50 px-3 py-3 text-sm",
        "text-zinc-100 placeholder:text-zinc-500 ring-1 ring-zinc-800 focus:outline-none focus:ring-2 focus:ring-emerald-400/40",
        props.className
      )}
    />
  );
}

function Input(props) {
  return (
    <input
      {...props}
      className={classNames(
        "w-full rounded-xl bg-zinc-900/50 px-3 py-2.5 text-sm",
        "text-zinc-100 placeholder:text-zinc-500 ring-1 ring-zinc-800 focus:outline-none focus:ring-2 focus:ring-emerald-400/40",
        props.className
      )}
    />
  );
}

function Button({ variant = "primary", className, ...props }) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-xl px-3 py-2 text-sm font-medium ring-1 transition focus:outline-none";
  const styles =
    variant === "primary"
      ? "bg-emerald-400/15 text-emerald-200 ring-emerald-400/30 hover:bg-emerald-400/20"
      : variant === "ghost"
      ? "bg-zinc-950 text-zinc-200 ring-zinc-800 hover:bg-zinc-900/40"
      : "bg-zinc-900 text-zinc-200 ring-zinc-800 hover:bg-zinc-800/40";

  return <button className={classNames(base, styles, className)} {...props} />;
}

function CodeBlock({ value }) {
  return (
    <pre className="overflow-auto rounded-xl bg-zinc-900/40 p-3 text-xs text-zinc-200 ring-1 ring-zinc-800">
      <code>{value}</code>
    </pre>
  );
}

// --- helpers (top-level) ---
function parseWk1(wrappedKey) {
  if (typeof wrappedKey !== "string") throw new Error("wrappedKey must be a string");
  const prefix = "pxp201:wk1:";
  if (!wrappedKey.startsWith(prefix)) throw new Error("Not a wk1 key (expected prefix pxp201:wk1:)");

  const b64url = wrappedKey.slice(prefix.length);
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const json = atob(b64);
  return JSON.parse(json);
}

// ✅ 1) helper: okBadge
function okBadge(ok) {
  return ok ? "✅ PASS" : "❌ FAIL";
}

function EncryptPanel({ onStatus }) {
  const [plaintext, setPlaintext] = useState("hello from PXP-201");
  const [aadText, setAadText] = useState("app:pxp201-ui|v0.1");

  // ✅ multi-recipient state
  const [recipients, setRecipients] = useState([
    {
      rid: "did:pkh:eip155:1:0xDEMO_RECIPIENT",
      recipientPrivHex: "",
      recipientPubHex: "",
    },
  ]);

  // outputs
  const [rawOut, setRawOut] = useState(null);
  const [wrappedKey, setWrappedKey] = useState("");
  const [envelope, setEnvelope] = useState(null);
  const [decryptCheck, setDecryptCheck] = useState("");

  // ✅ helpers (replace ensureRecipient)
  const ensureRecipientAt = (i) => {
    const r = recipients[i];
    if (!r) throw new Error("recipient index out of range");

    // already set
    if (r.recipientPrivHex && r.recipientPubHex) return r;

    const priv = secp.utils.randomSecretKey();
    const pub = secp.getPublicKey(priv, true);

    const next = [...recipients];
    next[i] = {
      ...r,
      recipientPrivHex: u8ToHex(priv),
      recipientPubHex: u8ToHex(pub),
    };
    setRecipients(next);
    return next[i];
  };

  const addRecipient = () => {
    setRecipients((prev) => [
      ...prev,
      {
        rid: `did:pkh:eip155:1:0xDEMO_RECIPIENT_${prev.length + 1}`,
        recipientPrivHex: "",
        recipientPubHex: "",
      },
    ]);
  };

  const removeRecipient = (i) => {
    setRecipients((prev) => prev.filter((_, idx) => idx !== i));
  };

  const updateRecipient = (i, patch) => {
    setRecipients((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  };

  const regenRecipient = (i) => {
    const priv = secp.utils.randomSecretKey();
    const pub = secp.getPublicKey(priv, true);
    updateRecipient(i, { recipientPrivHex: u8ToHex(priv), recipientPubHex: u8ToHex(pub) });
  };

  const runEncrypt = async () => {
    onStatus?.({ sdk: "running" });
    setDecryptCheck("");
    setRawOut(null);
    setWrappedKey("");
    setEnvelope(null);

    try {
      // 1) encrypt payload
      const raw = await encryptTextRaw({
        plaintext,
        cipher: "AES-256-GCM",
        aadText: aadText || undefined,
      });

      // 2) ensure/gather recipients, wrap DEK for each (wk1)
      const recipReady = recipients.map((_, i) => ensureRecipientAt(i));

      const recipientEntries = await Promise.all(
        recipReady.map(async (r) => {
          const wk = await wrapDEK_secp256k1({
            dek: raw.dek,
            recipientPubKeyHex: r.recipientPubHex,
            kid: r.rid,
            aadText: aadText || undefined,
          });
          return { rid: r.rid, wrappedKey: wk };
        })
      );

      // 3) build envelope (multi-recipient)
      const env = {
        v: "0.1",
        typ: "PXP201",
        cipher: "AES-256-GCM",
        kdf: "HKDF-SHA256",
        access: {
          mode: "RECIPIENTS",
          kem: "RECIPIENTS-SECP256K1-ECIES",
          recipients: recipientEntries,
        },
        uri: "ipfs://<your-ciphertext-uri>",
        ciphertextHash: raw.ciphertextHash,
        ...(raw.aadHash ? { aadHash: raw.aadHash } : {}),
        meta: { mime: "text/plain" },
        createdAt: nowUnix(),
      };

      validateEnvelope(env);

      setRawOut(raw);
      setEnvelope(env);

      // (optional) keep a “primary” wrappedKey for convenience/UI display:
      setWrappedKey(recipientEntries[0]?.wrappedKey || "");

      onStatus?.({ sdk: "ok" });

      // 4) local sanity decrypt using first recipient (optional)
      const first = recipReady[0];
      if (first?.recipientPrivHex && recipientEntries[0]?.wrappedKey) {
        const dek2 = await unwrapDEK_secp256k1({
          wrappedKey: recipientEntries[0].wrappedKey,
          recipientPrivKeyHex: first.recipientPrivHex,
          aadText: aadText || undefined,
        });

        const out = await decryptTextFromEnvelope({
          envelope: env,
          dek: dek2,
          ciphertextB64url: raw.ciphertextB64url,
          nonceB64url: raw.nonceB64url,
          aadText: aadText || undefined,
        });

        setDecryptCheck(out);
      }
    } catch (e) {
      console.error(e);
      onStatus?.({ sdk: "error" });
      setDecryptCheck(String(e?.message || e));
    }
  };

  const downloadBundle = () => {
    if (!rawOut || !envelope) return;

    const recipReady = recipients.map((_, i) => ensureRecipientAt(i));

    const recipientPrivHexByRid = Object.fromEntries(recipReady.map((r) => [r.rid, r.recipientPrivHex]));
    const recipientPubHexByRid = Object.fromEntries(recipReady.map((r) => [r.rid, r.recipientPubHex]));

    const payload = {
      aadText: aadText || "",
      raw: {
        ciphertextB64url: rawOut.ciphertextB64url,
        nonceB64url: rawOut.nonceB64url,
        ciphertextHash: rawOut.ciphertextHash,
        ...(rawOut.aadHash ? { aadHash: rawOut.aadHash } : {}),
      },
      envelope, // contains ALL recipients w/ wrappedKey
      // demo-only: private keys map
      recipientPrivHexByRid,
      // optional (nice for UI/debug)
      recipientPubHexByRid,
    };

    downloadText("pxp201-bundle.json", JSON.stringify(payload, null, 2));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <Pill>AES-256-GCM</Pill>
        <Pill>HKDF-SHA256</Pill>
        <Pill>wk1 secp256k1 ECIES</Pill>
      </div>

      <div className="grid gap-5 md:grid-cols-2">
        <Field label="Plaintext">
          <Textarea value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
        </Field>

        <div className="space-y-5">
          <Field label="AAD (optional)" hint="Keep stable between wrap + decrypt">
            <Input
              value={aadText}
              onChange={(e) => setAadText(e.target.value)}
              placeholder="app:my-app|chain:eip155:1|epoch:..."
            />
          </Field>

          <div className="flex flex-wrap gap-2">
            <Button onClick={runEncrypt}>Encrypt → Wrap → Envelope</Button>
            <Button variant="ghost" onClick={downloadBundle} disabled={!rawOut || !envelope}>
              Download bundle JSON
            </Button>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-12">
        <div className="md:col-span-7 space-y-4">
          {/* ✅ UI: recipients list (demo) */}
          <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium">Recipients (demo)</div>
              <div className="flex gap-2">
                <Button variant="ghost" onClick={addRecipient}>
                  Add
                </Button>
              </div>
            </div>

            <div className="mt-3 grid gap-4">
              {recipients.map((r, i) => (
                <div key={i} className="rounded-xl bg-zinc-900/30 ring-1 ring-zinc-800 p-3">
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-zinc-400">Recipient #{i + 1}</div>
                    <div className="flex gap-2">
                      <Button variant="ghost" onClick={() => regenRecipient(i)}>
                        Regenerate
                      </Button>
                      <Button variant="ghost" onClick={() => removeRecipient(i)} disabled={recipients.length <= 1}>
                        Remove
                      </Button>
                    </div>
                  </div>

                  <div className="mt-3 grid gap-3">
                    <Field label="rid / kid">
                      <Input value={r.rid} onChange={(e) => updateRecipient(i, { rid: e.target.value })} />
                    </Field>
                    <Field label="recipientPrivHex (demo only)">
                      <Input
                        value={r.recipientPrivHex}
                        onChange={(e) => updateRecipient(i, { recipientPrivHex: e.target.value })}
                        placeholder="0x..."
                      />
                    </Field>
                    <Field label="recipientPubHex">
                      <Input
                        value={r.recipientPubHex}
                        onChange={(e) => updateRecipient(i, { recipientPubHex: e.target.value })}
                        placeholder="0x..."
                      />
                    </Field>
                  </div>
                </div>
              ))}

              <div className="text-xs text-zinc-500">
                ⚠️ Demo only: in real apps, pubkeys come from wallet/DID key material. Never paste private keys into
                websites.
              </div>
            </div>
          </div>

          <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
            <div className="text-sm font-medium">Decrypt sanity check</div>
            <div className="mt-3">
              {decryptCheck ? (
                <CodeBlock value={decryptCheck} />
              ) : (
                <div className="text-sm text-zinc-500">Run the flow to verify local decrypt.</div>
              )}
            </div>
          </div>
        </div>

        <div className="md:col-span-5 space-y-4">
          <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
            <div className="text-sm font-medium">RAW output</div>
            <div className="mt-3 text-xs text-zinc-400">ciphertextB64url / nonceB64url / hashes</div>
            <div className="mt-3">
              {rawOut ? (
                <CodeBlock
                  value={JSON.stringify(
                    {
                      nonceB64url: rawOut.nonceB64url,
                      ciphertextB64url: rawOut.ciphertextB64url,
                      ciphertextHash: rawOut.ciphertextHash,
                      ...(rawOut.aadHash ? { aadHash: rawOut.aadHash } : {}),
                    },
                    null,
                    2
                  )}
                />
              ) : (
                <div className="text-sm text-zinc-500">No output yet.</div>
              )}
            </div>
          </div>

          <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
            <div className="text-sm font-medium">wrappedKey (wk1) — first recipient</div>
            <div className="mt-3">
              {wrappedKey ? (
                <CodeBlock value={wrappedKey} />
              ) : (
                <div className="text-sm text-zinc-500">No wrappedKey yet.</div>
              )}
            </div>
          </div>

          <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
            <div className="text-sm font-medium">Envelope</div>
            <div className="mt-3">
              {envelope ? (
                <CodeBlock value={JSON.stringify(envelope, null, 2)} />
              ) : (
                <div className="text-sm text-zinc-500">No envelope yet.</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function DecryptPanel({ bundleInput, setBundleInput, onStatus }) {
  const [out, setOut] = useState({ ok: false, plaintext: "", info: "", error: "" });
  const [aadOverride, setAadOverride] = useState("app:pxp201-ui|v0.1");

  // ✅ Auto-decrypt toggle state (OFF by default so the button is meaningful)
  const [autoDecrypt, setAutoDecrypt] = useState(false);

  // ✅ recipient selector
  const [selectedRid, setSelectedRid] = useState("");

  // ✅ run execution ref
  const runIdRef = useRef(0);

  const run = async () => {
    const runId = ++runIdRef.current;

    onStatus?.({ sdk: "running" });
    setOut({ ok: false, plaintext: "", info: "", error: "" });

    try {
      const bundle = JSON.parse(bundleInput || "{}");
      const { raw, envelope } = bundle;

      const aadText =
        typeof bundle.aadText === "string" && bundle.aadText.length > 0 ? bundle.aadText : aadOverride || "";

      if (!raw?.ciphertextB64url || !raw?.nonceB64url) throw new Error("bundle.raw missing ciphertextB64url/nonceB64url");
      if (!envelope) throw new Error("bundle.envelope missing");

      validateEnvelope(envelope);

      // ✅ resolver: supports multi-recipient demo bundle AND legacy vector/import bundle
      const recips = envelope?.access?.recipients || [];
      if (!Array.isArray(recips) || recips.length === 0) throw new Error("envelope.access.recipients missing/empty");

      // pick rid
      const ridToUse = selectedRid || recips[0]?.rid;
      if (!ridToUse) throw new Error("No recipient rid available");

      const entry = recips.find((x) => x.rid === ridToUse) || recips[0];
      if (!entry?.wrappedKey) throw new Error("No wrappedKey for selected recipient");

      // ✅ Resolve privkey from either:
      // A) multi-recipient demo bundle: recipientPrivHexByRid[rid]
      // B) legacy vector/import bundle: recipient.recipientPrivHex
      const privMap = bundle?.recipientPrivHexByRid;
      const privHex =
        (privMap && typeof privMap === "object" && entry?.rid ? privMap[entry.rid] : "") ||
        bundle?.recipient?.recipientPrivHex ||
        "";

      if (!privHex) {
        throw new Error(
          "No recipient privkey in bundle (expected recipientPrivHexByRid[rid] or recipient.recipientPrivHex). " +
            "If you imported a vector, export it with 'include demo privkey' enabled."
        );
      }

      // unwrap + decrypt
      const dek = await unwrapDEK_secp256k1({
        wrappedKey: entry.wrappedKey,
        recipientPrivKeyHex: privHex,
        aadText: aadText || undefined,
      });

      const plaintext = await decryptTextFromEnvelope({
        envelope,
        dek,
        ciphertextB64url: raw.ciphertextB64url,
        nonceB64url: raw.nonceB64url,
        aadText: aadText || undefined,
      });

      if (runId !== runIdRef.current) return;

      setOut({
        ok: true,
        plaintext,
        info: JSON.stringify(
          {
            ciphertextHash: envelope.ciphertextHash,
            aadHash: envelope.aadHash,
            rid: entry.rid,
            createdAt: envelope.createdAt,
          },
          null,
          2
        ),
        error: "",
      });

      onStatus?.({ sdk: "ok" });
    } catch (e) {
      console.error(e);
      if (runId !== runIdRef.current) return;
      setOut({ ok: false, plaintext: "", info: "", error: String(e?.message || e) });
      onStatus?.({ sdk: "error" });
    }
  };

  // ✅ Sync AAD override with bundle.aadText on bundleInput change (+ auto-sync rid)
  useEffect(() => {
    try {
      const b = JSON.parse(bundleInput || "{}");
      if (typeof b?.aadText === "string" && b.aadText.length > 0) {
        setAadOverride(b.aadText);
      }

      // auto-sync selectedRid (optional)
      if (!selectedRid) {
        const recips = b?.envelope?.access?.recipients || [];
        if (recips?.[0]?.rid) setSelectedRid(recips[0].rid);
      }
    } catch {}
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bundleInput]);

  // ✅ Debounced auto-run when bundle changes (only if autoDecrypt is enabled)
  useEffect(() => {
    if (!autoDecrypt) return;

    const t = setTimeout(() => {
      try {
        const b = JSON.parse(bundleInput || "{}");
        const recips = b?.envelope?.access?.recipients || [];
        const hasAnyRecipient = Array.isArray(recips) && recips.length > 0;

        // ✅ map OR legacy priv
        const hasPrivMap = b?.recipientPrivHexByRid && typeof b.recipientPrivHexByRid === "object";
        const hasLegacyPriv =
          typeof b?.recipient?.recipientPrivHex === "string" && b.recipient.recipientPrivHex.length > 0;

        if (
          b?.raw?.ciphertextB64url &&
          b?.raw?.nonceB64url &&
          b?.envelope &&
          hasAnyRecipient &&
          (hasPrivMap || hasLegacyPriv)
        ) {
          run();
        }
      } catch {}
    }, 300);

    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bundleInput, autoDecrypt, selectedRid]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <Pill>Paste bundle JSON</Pill>
        <Pill>validateEnvelope</Pill>
        <Pill>wk1 unwrap</Pill>
        <Pill>AES-GCM decrypt</Pill>
      </div>

      <Field label="AAD (optional)" hint="Must match Encrypt AAD to decrypt">
        <Input value={aadOverride} onChange={(e) => setAadOverride(e.target.value)} />
      </Field>

      {/* ✅ auto-decrypt toggle */}
      <label className="inline-flex items-center gap-2 text-xs text-zinc-400 select-none">
        <input
          type="checkbox"
          checked={autoDecrypt}
          onChange={(e) => setAutoDecrypt(e.target.checked)}
          className="h-4 w-4 rounded border-zinc-700 bg-zinc-900"
        />
        auto-decrypt
      </label>

      {/* ✅ Recipient dropdown (above Bundle JSON) */}
      <Field label="Recipient (rid)" hint="Select which recipient key to use">
        <select
          value={selectedRid}
          onChange={(e) => setSelectedRid(e.target.value)}
          className="w-full rounded-xl bg-zinc-900/50 px-3 py-2.5 text-sm text-zinc-100 ring-1 ring-zinc-800 focus:outline-none focus:ring-2 focus:ring-emerald-400/40"
        >
          <option value="">Auto (first recipient)</option>
          {(() => {
            try {
              const b = JSON.parse(bundleInput || "{}");
              const recips = b?.envelope?.access?.recipients || [];
              return recips.map((r, idx) => (
                <option key={idx} value={r.rid}>
                  {r.rid}
                </option>
              ));
            } catch {
              return null;
            }
          })()}
        </select>
      </Field>

      <Field label="Bundle JSON" hint="Use 'Download bundle JSON' from Encrypt tab (demo includes recipientPrivHexByRid)">
        <Textarea
          value={bundleInput}
          onChange={(e) => setBundleInput(e.target.value)}
          placeholder='{"raw": {...}, "envelope": {...}, "recipientPrivHexByRid": {...}}'
          className="min-h-[220px]"
        />
      </Field>

      <div className="flex flex-wrap gap-2">
        <Button onClick={run}>Decrypt from bundle</Button>
        <Button
          variant="ghost"
          onClick={() => {
            runIdRef.current += 1;
            setBundleInput("");
            setOut({ ok: false, plaintext: "", info: "", error: "" });
            setSelectedRid("");
          }}
        >
          Clear
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
          <div className="text-sm font-medium">Plaintext</div>
          <div className="mt-3">
            {out.ok ? (
              <CodeBlock value={out.plaintext} />
            ) : (
              <div className="text-sm text-zinc-500">No plaintext yet.</div>
            )}
          </div>
        </div>

        <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
          <div className="text-sm font-medium">Details</div>
          <div className="mt-3">
            {out.info ? <CodeBlock value={out.info} /> : <div className="text-sm text-zinc-500">No details yet.</div>}
          </div>
        </div>
      </div>

      {out.error ? (
        <div className="rounded-2xl bg-rose-500/10 ring-1 ring-rose-500/20 p-4">
          <div className="text-sm font-medium text-rose-200">Error</div>
          <div className="mt-2 text-sm text-rose-200/80">{out.error}</div>
        </div>
      ) : null}
    </div>
  );
}

// --- WK1 tab panel ---
function WK1Panel({ bundleInput, onStatus }) {
  const [wrappedKey, setWrappedKey] = useState("");
  const [privHex, setPrivHex] = useState("");
  const [aadText, setAadText] = useState("app:pxp201-ui|v0.1");
  const [parsed, setParsed] = useState("");
  const [out, setOut] = useState({ dekHex: "", error: "" });

  // ✅ new states
  const [dekHexIn, setDekHexIn] = useState("");
  const [pubHex, setPubHex] = useState("");
  const [kid, setKid] = useState("did:pkh:eip155:1:0xDEMO_RECIPIENT");

  // ✅ multi-recipient: selected rid
  const [selectedRid, setSelectedRid] = useState("");

  // ✅ auto-sync selectedRid if empty (best effort)
  useEffect(() => {
    try {
      const b = JSON.parse(bundleInput || "{}");
      if (!selectedRid) {
        const recips = b?.envelope?.access?.recipients || [];
        if (recips?.[0]?.rid) setSelectedRid(recips[0].rid);
      }
    } catch {}
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bundleInput]);

  // ✅ Prefill supports multi-recipient bundle (and legacy fallback)
  const fillFromBundle = () => {
    try {
      const bundle = JSON.parse(bundleInput || "{}");

      if (typeof bundle?.aadText === "string") setAadText(bundle.aadText || "");

      // NEW multi-recipient bundle path
      const recips = bundle?.envelope?.access?.recipients || [];
      const privMap = bundle?.recipientPrivHexByRid;

      if (Array.isArray(recips) && recips.length > 0) {
        const ridToUse = selectedRid || recips[0]?.rid;
        const entry = recips.find((x) => x.rid === ridToUse) || recips[0];

        if (entry?.wrappedKey) setWrappedKey(entry.wrappedKey);
        if (entry?.rid) setKid(entry.rid);

        if (privMap && typeof privMap === "object" && entry?.rid && privMap[entry.rid]) {
          setPrivHex(privMap[entry.rid]);
        }

        // optional: if you also ship pub map
        const pubMap = bundle?.recipientPubHexByRid;
        if (pubMap && typeof pubMap === "object" && entry?.rid && pubMap[entry.rid]) {
          setPubHex(pubMap[entry.rid]);
        }

        // try parse immediately (best effort)
        try {
          if (entry?.wrappedKey) setParsed(JSON.stringify(parseWk1(entry.wrappedKey), null, 2));
        } catch {}

        return;
      }

      // legacy single-recipient bundle fallback
      if (bundle?.wrappedKey) setWrappedKey(bundle.wrappedKey);
      if (bundle?.recipient?.recipientPrivHex) setPrivHex(bundle.recipient.recipientPrivHex);
      if (bundle?.recipient?.recipientPubHex) setPubHex(bundle.recipient.recipientPubHex);
      if (bundle?.recipient?.rid) setKid(bundle.recipient.rid);

      if (typeof bundle?.dekHex === "string" && bundle.dekHex) setDekHexIn(bundle.dekHex);
      if (typeof bundle?.raw?.dekHex === "string" && bundle.raw.dekHex) setDekHexIn(bundle.raw.dekHex);
    } catch {}
  };

  const doParse = () => {
    try {
      const obj = parseWk1(wrappedKey);
      setParsed(JSON.stringify(obj, null, 2));
      setOut((p) => ({ ...p, error: "" }));
    } catch (e) {
      setParsed("");
      setOut({ dekHex: "", error: String(e?.message || e) });
    }
  };

  const doUnwrap = async () => {
    onStatus?.({ sdk: "running" });
    setOut({ dekHex: "", error: "" });

    try {
      if (!wrappedKey) throw new Error("wrappedKey required");
      if (!privHex) throw new Error("recipientPrivHex required");

      const obj = parseWk1(wrappedKey);
      setParsed(JSON.stringify(obj, null, 2));

      const dek = await unwrapDEK_secp256k1({
        wrappedKey,
        recipientPrivKeyHex: privHex,
        aadText: aadText || undefined,
      });

      setOut({ dekHex: u8ToHex(dek), error: "" });
      onStatus?.({ sdk: "ok" });
    } catch (e) {
      console.error(e);
      setOut({ dekHex: "", error: String(e?.message || e) });
      onStatus?.({ sdk: "error" });
    }
  };

  const doWrap = async () => {
    onStatus?.({ sdk: "running" });
    setOut({ dekHex: "", error: "" });

    try {
      if (!dekHexIn) throw new Error("dekHex required (0x.. 32 bytes)");
      if (!pubHex) throw new Error("recipientPubHex required");
      if (!kid) throw new Error("kid required");
      if (!privHex) throw new Error("recipientPrivHex required for auto-sanity unwrap (optional)");

      const dek = hexToU8(dekHexIn);
      if (dek.length !== 32) throw new Error("DEK must be 32 bytes (64 hex chars)");

      const wk = await wrapDEK_secp256k1({
        dek,
        recipientPubKeyHex: pubHex,
        kid,
        aadText: aadText || undefined,
      });

      setWrappedKey(wk);
      setParsed(JSON.stringify(parseWk1(wk), null, 2));

      const dek2 = await unwrapDEK_secp256k1({
        wrappedKey: wk,
        recipientPrivKeyHex: privHex,
        aadText: aadText || undefined,
      });
      setOut({ dekHex: u8ToHex(dek2), error: "" });

      onStatus?.({ sdk: "ok" });
    } catch (e) {
      console.error(e);
      setOut({ dekHex: "", error: String(e?.message || e) });
      onStatus?.({ sdk: "error" });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <Pill>wk1 parse</Pill>
        <Pill>secp256k1 wrap/unwrap</Pill>
        <Pill>AAD-bound</Pill>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button variant="ghost" onClick={fillFromBundle} disabled={!bundleInput}>
          Prefill from Bundle JSON
        </Button>
        <Button variant="ghost" onClick={doParse} disabled={!wrappedKey}>
          Parse wk1
        </Button>
        <Button onClick={doWrap}>Wrap ← DEK</Button>
        <Button onClick={doUnwrap}>Unwrap → DEK</Button>
      </div>

      <Field label="AAD (optional)" hint="Must match the AAD used at wrap time">
        <Input value={aadText} onChange={(e) => setAadText(e.target.value)} />
      </Field>

      <Field label="DEK hex (32 bytes)">
        <Input value={dekHexIn} onChange={(e) => setDekHexIn(e.target.value)} placeholder="0x..." />
      </Field>

      <Field label="recipientPubHex">
        <Input value={pubHex} onChange={(e) => setPubHex(e.target.value)} placeholder="0x..." />
      </Field>

      <Field label="kid">
        <Input value={kid} onChange={(e) => setKid(e.target.value)} />
      </Field>

      {/* ✅ multi-recipient rid dropdown */}
      <Field label="Recipient (rid)" hint="Select which recipient entry to use from the envelope">
        <select
          value={selectedRid}
          onChange={(e) => setSelectedRid(e.target.value)}
          className="w-full rounded-xl bg-zinc-900/50 px-3 py-2.5 text-sm text-zinc-100 ring-1 ring-zinc-800 focus:outline-none focus:ring-2 focus:ring-emerald-400/40"
        >
          <option value="">Auto (first recipient)</option>
          {(() => {
            try {
              const b = JSON.parse(bundleInput || "{}");
              const recips = b?.envelope?.access?.recipients || [];
              return recips.map((r, idx) => (
                <option key={idx} value={r.rid}>
                  {r.rid}
                </option>
              ));
            } catch {
              return null;
            }
          })()}
        </select>
      </Field>

      <Field label="wrappedKey (wk1)">
        <Textarea
          value={wrappedKey}
          onChange={(e) => setWrappedKey(e.target.value)}
          className="min-h-[140px]"
          placeholder="pxp201:wk1:..."
        />
      </Field>

      <Field label="recipientPrivHex">
        <Input value={privHex} onChange={(e) => setPrivHex(e.target.value)} placeholder="0x..." />
      </Field>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
          <div className="text-sm font-medium">WK1 payload (decoded)</div>
          <div className="mt-3">
            {parsed ? <CodeBlock value={parsed} /> : <div className="text-sm text-zinc-500">No parsed data yet.</div>}
          </div>
        </div>

        <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
          <div className="text-sm font-medium">Last unwrapped DEK</div>
          <div className="mt-3">
            {out.dekHex ? <CodeBlock value={out.dekHex} /> : <div className="text-sm text-zinc-500">No DEK yet.</div>}
          </div>
        </div>
      </div>

      {out.error ? (
        <div className="rounded-2xl bg-rose-500/10 ring-1 ring-rose-500/20 p-4">
          <div className="text-sm font-medium text-rose-200">Error</div>
          <div className="mt-2 text-sm text-rose-200/80">{out.error}</div>
        </div>
      ) : null}
    </div>
  );
}

// ✅ VectorsPanel (kept mono-recipient as requested)
function VectorsPanel({ bundleInput, setBundleInput, setTab, onStatus }) {
  const [res, setRes] = useState(null);

  const [includePriv, setIncludePriv] = useState(false);

  const [toast, setToast] = useState("");
  const flash = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(""), 1800);
  };

  const [importJson, setImportJson] = useState("");
  const [autoRunAfterImport, setAutoRunAfterImport] = useState(true);

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
  };

  const vectorToBundle = (v) => {
    if (!v || typeof v !== "object") throw new Error("Invalid vector JSON");
    if (!v.raw?.ciphertextB64url || !v.raw?.nonceB64url)
      throw new Error("Vector missing raw.ciphertextB64url/nonceB64url");
    if (!v.envelope) throw new Error("Vector missing envelope");
    if (!v.wrappedKey) throw new Error("Vector missing wrappedKey");
    if (!v.recipientPrivHex) {
      throw new Error("Vector missing recipientPrivHex. Re-export with 'include demo privkey' enabled.");
    }

    return {
      aadText: typeof v.aadText === "string" ? v.aadText : "",
      raw: {
        ciphertextB64url: v.raw.ciphertextB64url,
        nonceB64url: v.raw.nonceB64url,
        ciphertextHash: v.raw.ciphertextHash,
        ...(v.raw.aadHash ? { aadHash: v.raw.aadHash } : {}),
      },
      envelope: v.envelope,
      wrappedKey: v.wrappedKey,
      recipient: {
        rid: v.rid,
        recipientPubHex: v.recipientPubHex,
        recipientPrivHex: v.recipientPrivHex,
      },
    };
  };

  const importVectorFile = async (file) => {
    if (!file) return;
    const text = await file.text();

    try {
      const v = JSON.parse(text);
      const bundle = vectorToBundle(v);

      const bundleStr = JSON.stringify(bundle, null, 2);
      setImportJson(bundleStr);
      flash("Vector imported");

      setBundleInput?.(bundleStr);
      setTab?.("decrypt");

      if (autoRunAfterImport) return;

      onStatus?.({ sdk: "ok" });
    } catch (e) {
      console.error(e);
      flash("Import failed");
      setRes({ mode: "import", ok: false, error: String(e?.message || e) });
      onStatus?.({ sdk: "error" });
    }
  };

  // ✅ PATCH: multi-recipient compatible runFromBundle (and legacy fallback)
  const runFromBundle = async () => {
    onStatus?.({ sdk: "running" });
    setRes(null);

    try {
      const bundle = JSON.parse(bundleInput || "{}");
      const { raw, envelope } = bundle;

      const aadText = typeof bundle.aadText === "string" ? bundle.aadText : "";

      if (!raw?.ciphertextB64url || !raw?.nonceB64url) {
        throw new Error("bundle.raw missing ciphertextB64url/nonceB64url");
      }
      if (!envelope) throw new Error("bundle.envelope missing");

      // 1) validate envelope structure
      validateEnvelope(envelope);

      // --- Resolve (wrappedKey, privHex, rid) from either:
      // A) new multi-recipient bundle: envelope.access.recipients + recipientPrivHexByRid
      // B) legacy bundle: bundle.wrappedKey + bundle.recipient.recipientPrivHex

      let wrappedKey = bundle?.wrappedKey || "";
      let privHex = bundle?.recipient?.recipientPrivHex || "";
      let rid = bundle?.recipient?.rid || envelope?.access?.recipients?.[0]?.rid || "";

      // If multi-recipient bundle style:
      if (!wrappedKey) {
        const recips = envelope?.access?.recipients || [];
        if (!Array.isArray(recips) || recips.length === 0) {
          throw new Error("envelope.access.recipients missing/empty");
        }

        // choose first recipient (Vectors panel is mono-recipient UX)
        const entry = recips[0];
        if (!entry?.wrappedKey) throw new Error("No wrappedKey found in envelope.access.recipients[0]");
        wrappedKey = entry.wrappedKey;
        rid = entry.rid || rid;

        const privMap = bundle?.recipientPrivHexByRid;
        if (privMap && typeof privMap === "object") {
          privHex = privMap[entry.rid] || privHex;
        }
      }

      if (!wrappedKey)
        throw new Error(
          "No wrappedKey available in bundle (expected bundle.wrappedKey or envelope.access.recipients[0].wrappedKey)"
        );
      if (!privHex)
        throw new Error(
          "No recipient privkey available in bundle (expected bundle.recipient.recipientPrivHex or bundle.recipientPrivHexByRid[rid])"
        );

      // 2) unwrap
      const dek = await unwrapDEK_secp256k1({
        wrappedKey,
        recipientPrivKeyHex: privHex,
        aadText: aadText || undefined,
      });

      // 3) decrypt
      const plaintext = await decryptTextFromEnvelope({
        envelope,
        dek,
        ciphertextB64url: raw.ciphertextB64url,
        nonceB64url: raw.nonceB64url,
        aadText: aadText || undefined,
      });

      // 4) hash checks
      const hashMatch = raw.ciphertextHash === envelope.ciphertextHash;
      const aadMatch = !envelope.aadHash || raw.aadHash === envelope.aadHash;

      setRes({
        mode: "bundle",
        ok: true,
        plaintext,
        checks: {
          envelopeValid: true,
          wk1Parsed: true,
          hashMatch,
          aadMatch,
          decryptOk: true,
        },
        meta: {
          rid,
          createdAt: envelope.createdAt,
        },
      });

      onStatus?.({ sdk: "ok" });
    } catch (e) {
      console.error(e);
      setRes({ mode: "bundle", ok: false, error: String(e?.message || e) });
      onStatus?.({ sdk: "error" });
    }
  };

  const runGenerate = async () => {
    onStatus?.({ sdk: "running" });
    setRes(null);

    try {
      const plaintextIn = "vector: hello from PXP-201";
      const aadText = "app:pxp201-ui|vectors:v0.1";
      const rid = "did:pkh:eip155:1:0xDEMO_RECIPIENT";

      const priv = secp.utils.randomSecretKey();
      const pub = secp.getPublicKey(priv, true);
      const privHex = u8ToHex(priv);
      const pubHex = u8ToHex(pub);

      const raw = await encryptTextRaw({
        plaintext: plaintextIn,
        cipher: "AES-256-GCM",
        aadText,
      });

      const wk = await wrapDEK_secp256k1({
        dek: raw.dek,
        recipientPubKeyHex: pubHex,
        kid: rid,
        aadText,
      });

      const env = {
        v: "0.1",
        typ: "PXP201",
        cipher: "AES-256-GCM",
        kdf: "HKDF-SHA256",
        access: {
          mode: "RECIPIENTS",
          kem: "RECIPIENTS-SECP256K1-ECIES",
          recipients: [{ rid, wrappedKey: wk }],
        },
        uri: "ipfs://<your-ciphertext-uri>",
        ciphertextHash: raw.ciphertextHash,
        ...(raw.aadHash ? { aadHash: raw.aadHash } : {}),
        meta: { mime: "text/plain" },
        createdAt: nowUnix(),
      };

      validateEnvelope(env);

      const dek2 = await unwrapDEK_secp256k1({
        wrappedKey: wk,
        recipientPrivKeyHex: privHex,
        aadText,
      });

      const plaintextOut = await decryptTextFromEnvelope({
        envelope: env,
        dek: dek2,
        ciphertextB64url: raw.ciphertextB64url,
        nonceB64url: raw.nonceB64url,
        aadText,
      });

      const decryptOk = plaintextOut === plaintextIn;
      const hashMatch = raw.ciphertextHash === env.ciphertextHash;
      const aadMatch = !env.aadHash || raw.aadHash === env.aadHash;

      setRes({
        mode: "generate",
        ok: decryptOk && hashMatch && aadMatch,
        plaintext: plaintextOut,
        checks: {
          envelopeValid: true,
          wk1Parsed: true,
          hashMatch,
          aadMatch,
          decryptOk,
        },
        generated: {
          aadText,
          rid,
          recipientPubHex: pubHex,
          recipientPrivHex: privHex,
          wrappedKey: wk,
          raw: {
            nonceB64url: raw.nonceB64url,
            ciphertextB64url: raw.ciphertextB64url,
            ciphertextHash: raw.ciphertextHash,
            ...(raw.aadHash ? { aadHash: raw.aadHash } : {}),
          },
          envelope: env,
        },
      });

      onStatus?.({ sdk: "ok" });
    } catch (e) {
      console.error(e);
      setRes({ mode: "generate", ok: false, error: String(e?.message || e) });
      onStatus?.({ sdk: "error" });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        <Pill>self-test</Pill>
        <Pill>bundle replay</Pill>
        <Pill>hash checks</Pill>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button onClick={runGenerate}>Run self-test (generate)</Button>
        <Button variant="ghost" onClick={runFromBundle} disabled={!bundleInput}>
          Run from Bundle JSON
        </Button>

        <div className="mx-1 h-6 w-px bg-zinc-800" />

        <Button
          variant="ghost"
          onClick={() => {
            if (!res?.generated) return;
            const v = {
              ...res.generated,
              recipientPrivHex: includePriv ? res.generated.recipientPrivHex : undefined,
            };
            if (!includePriv) delete v.recipientPrivHex;

            downloadText("pxp201-vector.json", JSON.stringify(v, null, 2));
          }}
          disabled={!res?.generated}
        >
          Download vector JSON
        </Button>

        <Button
          variant="ghost"
          onClick={async () => {
            if (!res?.generated) return;
            const v = {
              ...res.generated,
              recipientPrivHex: includePriv ? res.generated.recipientPrivHex : undefined,
            };
            if (!includePriv) delete v.recipientPrivHex;

            await copyToClipboard(JSON.stringify(v, null, 2));
            flash("Copied to clipboard");
          }}
          disabled={!res?.generated}
        >
          Copy vector JSON
        </Button>

        <label className="ml-2 inline-flex items-center gap-2 text-xs text-zinc-400 select-none">
          <input
            type="checkbox"
            checked={includePriv}
            onChange={(e) => setIncludePriv(e.target.checked)}
            className="h-4 w-4 rounded border-zinc-700 bg-zinc-900"
          />
          include demo privkey
        </label>

        <div className="mx-1 h-6 w-px bg-zinc-800" />

        <label className="inline-flex items-center gap-2 text-xs text-zinc-400 select-none">
          <input
            type="checkbox"
            checked={autoRunAfterImport}
            onChange={(e) => setAutoRunAfterImport(e.target.checked)}
            className="h-4 w-4 rounded border-zinc-700 bg-zinc-900"
          />
          auto-run after import
        </label>

        <label className="inline-flex items-center gap-2 text-xs text-zinc-400 select-none cursor-pointer">
          <input
            type="file"
            accept="application/json"
            className="hidden"
            onChange={(e) => importVectorFile(e.target.files?.[0])}
          />
          <span className="inline-flex items-center rounded-xl px-3 py-2 ring-1 ring-zinc-800 bg-zinc-950 hover:bg-zinc-900/40">
            Import vector JSON
          </span>
        </label>
      </div>

      {toast ? <div className="text-xs text-emerald-300">{toast}</div> : null}

      {importJson ? (
        <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
          <div className="text-sm font-medium">Imported bundle (ready for Decrypt tab)</div>
          <div className="mt-3">
            <CodeBlock value={importJson} />
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button
              variant="ghost"
              onClick={async () => {
                await copyToClipboard(importJson);
                flash("Bundle copied");
              }}
            >
              Copy bundle JSON
            </Button>
            <Button variant="ghost" onClick={() => downloadText("pxp201-bundle.imported.json", importJson)}>
              Download bundle JSON
            </Button>
          </div>
        </div>
      ) : null}

      {res ? (
        res.ok ? (
          <div className="rounded-2xl bg-emerald-400/10 ring-1 ring-emerald-400/20 p-4">
            <div className="text-sm font-medium text-emerald-200">All checks OK</div>
            <div className="mt-2 text-sm text-emerald-200/80">Plaintext: {res.plaintext}</div>
          </div>
        ) : (
          <div className="rounded-2xl bg-rose-500/10 ring-1 ring-rose-500/20 p-4">
            <div className="text-sm font-medium text-rose-200">Test failed</div>
            <div className="mt-2 text-sm text-rose-200/80">{res.error || "Unknown error"}</div>
          </div>
        )
      ) : (
        <div className="text-sm text-zinc-500">Run a test to see PASS/FAIL checks.</div>
      )}

      {res?.checks ? (
        <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
          <div className="text-sm font-medium">Checks</div>
          <div className="mt-3 space-y-2 text-sm text-zinc-300">
            <div className="flex items-center justify-between">
              <span className="text-zinc-400">Envelope valid</span>
              <span>{okBadge(res.checks.envelopeValid)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zinc-400">WK1 parsed</span>
              <span>{okBadge(res.checks.wk1Parsed)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zinc-400">ciphertextHash match</span>
              <span>{okBadge(res.checks.hashMatch)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zinc-400">aadHash match</span>
              <span>{okBadge(res.checks.aadMatch)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zinc-400">Decrypt OK</span>
              <span>{okBadge(res.checks.decryptOk)}</span>
            </div>
          </div>
        </div>
      ) : null}

      {res?.generated ? (
        <div className="rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
          <div className="text-sm font-medium">Generated vector (debug)</div>
          <div className="mt-3">
            <CodeBlock
              value={JSON.stringify(
                includePriv
                  ? res.generated
                  : { ...res.generated, recipientPrivHex: "<hidden (toggle include demo privkey)>" },
                null,
                2
              )}
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState("encrypt");
  const [status, setStatus] = useState({ tailwind: "ok", sdk: "not wired", vectors: "idle" });

  const [bundleInput, setBundleInput] = useState("");

  const title = useMemo(() => tabs.find((x) => x.id === tab)?.label ?? "PXP-201 UI", [tab]);

  const sdkStatusPill =
    status.sdk === "ok" ? "text-emerald-300" : status.sdk === "error" ? "text-rose-300" : "text-zinc-500";

  const vectorsStatusPill =
    status.vectors === "ok" ? "text-emerald-300" : status.vectors === "error" ? "text-rose-300" : "text-zinc-500";

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-10 border-b border-zinc-800/70 bg-zinc-950/70 backdrop-blur">
        <div className="mx-auto max-w-6xl px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-zinc-950 ring-1 ring-zinc-800 flex items-center justify-center overflow-hidden">
              <img
                src="/logo-prvx-copy.png"
                alt="PrivacyX"
                className="h-6 w-6 object-contain"
              />
            </div>
            <div>
              <div className="font-semibold leading-tight">PXP-201</div>
              <div className="text-xs text-zinc-400">Encryption Playground</div>
            </div>
          </div>

          <a
            className="text-xs text-zinc-400 hover:text-zinc-200 transition"
            href="https://www.npmjs.com/package/@privacyx/pxp201"
            target="_blank"
            rel="noreferrer"
          >
            @privacyx/pxp201
          </a>
        </div>

        <div className="mx-auto max-w-6xl px-4 pb-3">
          <nav className="flex flex-wrap gap-2">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={classNames(
                  "rounded-xl px-3 py-2 text-sm ring-1 transition",
                  tab === t.id
                    ? "bg-zinc-900 ring-emerald-400/40 text-zinc-100"
                    : "bg-zinc-950 ring-zinc-800 text-zinc-300 hover:bg-zinc-900/40"
                )}
              >
                {t.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold">{title}</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Developer-friendly playground for encrypt → wrap → envelope → decrypt, plus reproducible test vectors.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-12">
          <section className="md:col-span-8 rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
            {tab === "encrypt" ? (
              <EncryptPanel
                onStatus={(s) =>
                  setStatus((prev) => ({
                    ...prev,
                    sdk: s.sdk ?? prev.sdk,
                  }))
                }
              />
            ) : tab === "decrypt" ? (
              <DecryptPanel
                bundleInput={bundleInput}
                setBundleInput={setBundleInput}
                onStatus={(s) =>
                  setStatus((prev) => ({
                    ...prev,
                    sdk: s.sdk ?? prev.sdk,
                  }))
                }
              />
            ) : tab === "wk1" ? (
              <WK1Panel
                bundleInput={bundleInput}
                onStatus={(s) =>
                  setStatus((prev) => ({
                    ...prev,
                    sdk: s.sdk ?? prev.sdk,
                  }))
                }
              />
            ) : tab === "vectors" ? (
              <VectorsPanel
                bundleInput={bundleInput}
                setBundleInput={setBundleInput}
                setTab={setTab}
                onStatus={(s) =>
                  setStatus((prev) => ({
                    ...prev,
                    sdk: s.sdk ?? prev.sdk,
                    vectors: s.sdk ?? prev.vectors,
                  }))
                }
              />
            ) : (
              <div className="text-sm text-zinc-400">
                Coming next. Current tab: <span className="text-zinc-200">{tab}</span>
              </div>
            )}
          </section>

          <aside className="md:col-span-4 rounded-2xl bg-zinc-950 ring-1 ring-zinc-800 p-4">
            <div className="text-sm font-medium">Status</div>
            <ul className="mt-3 space-y-2 text-sm text-zinc-300">
              <li className="flex items-center justify-between">
                <span className="text-zinc-400">Tailwind</span>
                <span className="text-emerald-300">OK</span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-zinc-400">SDK</span>
                <span className={sdkStatusPill}>{status.sdk}</span>
              </li>
              <li className="flex items-center justify-between">
                <span className="text-zinc-400">Vectors</span>
                <span className={vectorsStatusPill}>{status.vectors}</span>
              </li>
            </ul>

            <div className="mt-6 rounded-xl bg-zinc-900/40 ring-1 ring-zinc-800 p-4">
              <div className="text-xs text-zinc-400">
                Tip: AAD binds context (app/chain/epoch). Use it to prevent replay across contexts.
              </div>
            </div>

            <div className="mt-4 rounded-xl bg-zinc-900/40 ring-1 ring-zinc-800 p-4">
              <div className="text-xs text-zinc-400">
                Next: add multi-recipient envelopes / export wk1-only bundle / IPFS storage hook
              </div>
            </div>
          </aside>
        </div>
      </main>

      <footer className="mx-auto max-w-6xl px-4 pb-10 text-xs text-zinc-500">
        © {new Date().getFullYear()} Privacyx • PXP-201
      </footer>
    </div>
  );
}

