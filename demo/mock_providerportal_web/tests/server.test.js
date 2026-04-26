"use strict";

const { buildHealthPayload } = require("../src/utils");

describe("/health response shape", () => {
  test("uses buildHealthPayload to expose dependency versions", () => {
    const payload = buildHealthPayload({ axiosVersion: "0.16.2", lodashVersion: "4.17.15" });
    expect(payload.ok).toBe(true);
    expect(payload.dependency).toBe("0.16.2");
    expect(payload.utility).toBe("4.17.15");
  });
});
