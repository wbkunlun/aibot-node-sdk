import { describe, it, expect } from "vitest";
import { WecomCrypto } from "../src/wecom-crypto/index";

describe("WecomCrypto", () => {
  const encodingAESKey = "<your encodingAESKey>";
  const token = "<your token>";
  const crypto = new WecomCrypto(token, encodingAESKey, "");

  it("round-trips plaintext", () => {
    const plaintext = JSON.stringify({ hello: "world" });
    const { encrypt, signature } = crypto.encrypt(plaintext, "123", "456");
    expect(crypto.verifySignature(signature, "123", "456", encrypt)).toBe(true);
    const decrypted = crypto.decrypt(encrypt);
    expect(decrypted).toBe(plaintext);
  });

  it("pads correctly when raw length is a multiple of 32", () => {
    const plaintext = "x".repeat(12);
    const { encrypt } = crypto.encrypt(plaintext, "123", "456");
    const decrypted = crypto.decrypt(encrypt);
    expect(decrypted).toBe(plaintext);
  });

  it("computes sha1 msg signature", () => {
    const sig = crypto.computeSignature("123", "456", "ENCRYPT");
    expect(sig).toMatch(/^[a-f0-9]{40}$/);
  });
});
