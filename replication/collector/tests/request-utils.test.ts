import { describe, expect, it } from "vitest";
import {
  clampLimit,
  isReservedRootSegment,
  mapSearchParams,
  parseRequestBody,
  sanitizeHeaders
} from "@/lib/request-utils";

describe("request utils", () => {
  it("flags reserved root segments", () => {
    expect(isReservedRootSegment("api")).toBe(true);
    expect(isReservedRootSegment("console")).toBe(true);
    expect(isReservedRootSegment("mybin")).toBe(false);
  });

  it("maps duplicate query params into arrays", () => {
    const params = new URLSearchParams("a=1&a=2&b=3");
    expect(mapSearchParams(params)).toEqual({ a: ["1", "2"], b: "3" });
  });

  it("parses textual request bodies", async () => {
    const request = new Request("https://example.com", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hello: "world" })
    });

    const parsed = await parseRequestBody(request);
    expect(parsed.bodyText).toContain("hello");
    expect(parsed.bodyBase64).toBeNull();
    expect(parsed.truncated).toBe(false);
  });

  it("parses binary request bodies", async () => {
    const request = new Request("https://example.com", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    });

    const parsed = await parseRequestBody(request);
    expect(parsed.bodyText).toBeNull();
    expect(parsed.bodyBase64).toBe("3q2+7w==");
  });

  it("clamps api limits", () => {
    expect(clampLimit("500", 100, 200)).toBe(200);
    expect(clampLimit("-2", 100, 200)).toBe(1);
    expect(clampLimit(null, 100, 200)).toBe(100);
  });

  it("removes platform and forwarding headers", () => {
    const headers = new Headers({
      "content-type": "application/json",
      forwarded: "for=1.2.3.4",
      "x-forwarded-for": "1.2.3.4",
      "x-real-ip": "1.2.3.4",
      "x-vercel-oidc-token": "secret",
      "x-vercel-proxy-signature": "secret2"
    });

    expect(sanitizeHeaders(headers)).toEqual({
      "content-type": "application/json"
    });
  });
});
