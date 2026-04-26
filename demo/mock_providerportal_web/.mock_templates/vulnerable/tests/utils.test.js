"use strict";

const {
  classifyProviderTier,
  buildHealthPayload,
  maskMemberId,
  summarizeClaim,
} = require("../src/utils");

describe("classifyProviderTier", () => {
  test("returns platinum for top scores", () => {
    expect(classifyProviderTier(95)).toBe("platinum");
  });

  test("returns gold for high scores", () => {
    expect(classifyProviderTier(80)).toBe("gold");
  });

  test("returns silver for mid-range scores", () => {
    expect(classifyProviderTier(60)).toBe("silver");
  });

  test("rejects non-numeric input", () => {
    expect(() => classifyProviderTier("not-a-number")).toThrow(TypeError);
  });
});

describe("buildHealthPayload", () => {
  test("returns expected shape with versions", () => {
    expect(buildHealthPayload({ axiosVersion: "1.2.3", lodashVersion: "4.17.21" })).toEqual({
      ok: true,
      dependency: "1.2.3",
      utility: "4.17.21",
    });
  });

  test("falls back to safe defaults when versions are missing", () => {
    expect(buildHealthPayload()).toEqual({
      ok: true,
      dependency: "0.0.0",
      utility: "0.0.0",
    });
  });
});

describe("summarizeClaim", () => {
  test("approves a normal claim", () => {
    expect(summarizeClaim({ amount: 125.5, status: "open" })).toEqual({
      ok: true,
      decision: "approved",
      payable: 125.5,
    });
  });

  test("flags missing claim", () => {
    expect(summarizeClaim(null)).toEqual({ ok: false, reason: "missing_claim" });
  });

  test("flags negative amount", () => {
    expect(summarizeClaim({ amount: -10, status: "open" })).toEqual({
      ok: false,
      reason: "invalid_amount",
    });
  });
});

// Note: `classifyProviderTier` bronze/watchlist branches and the `maskMemberId`
// helper are intentionally left without dedicated tests so SonarQube has a
// concrete coverage gap to surface during the demo.
void maskMemberId;
