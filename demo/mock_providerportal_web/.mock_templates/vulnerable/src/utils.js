"use strict";

/**
 * Minimal utility helpers used by the mock provider portal demo.
 * Exposes a handful of small functions with simple branches so the
 * demo project can be exercised by a Jest test suite and a SonarQube
 * coverage scan.
 */

function classifyProviderTier(score) {
  if (typeof score !== "number" || Number.isNaN(score)) {
    throw new TypeError("score must be a finite number");
  }
  if (score < 0 || score > 100) {
    throw new RangeError("score must be between 0 and 100");
  }
  if (score >= 90) {
    return "platinum";
  }
  if (score >= 75) {
    return "gold";
  }
  if (score >= 50) {
    return "silver";
  }
  if (score >= 25) {
    return "bronze";
  }
  return "watchlist";
}

function buildHealthPayload({ axiosVersion, lodashVersion } = {}) {
  return {
    ok: true,
    dependency: axiosVersion || "0.0.0",
    utility: lodashVersion || "0.0.0",
  };
}

function maskMemberId(memberId) {
  const value = String(memberId || "");
  if (value.length <= 4) {
    return "****";
  }
  return `****${value.slice(-4)}`;
}

function summarizeClaim(claim) {
  if (!claim || typeof claim !== "object") {
    return { ok: false, reason: "missing_claim" };
  }
  const amount = Number(claim.amount);
  if (!Number.isFinite(amount) || amount < 0) {
    return { ok: false, reason: "invalid_amount" };
  }
  const status = (claim.status || "").toString().toLowerCase();
  if (status === "denied") {
    return { ok: true, decision: "denied", payable: 0 };
  }
  if (status === "pending") {
    return { ok: true, decision: "pending", payable: 0 };
  }
  return { ok: true, decision: "approved", payable: Math.round(amount * 100) / 100 };
}

module.exports = {
  classifyProviderTier,
  buildHealthPayload,
  maskMemberId,
  summarizeClaim,
};
