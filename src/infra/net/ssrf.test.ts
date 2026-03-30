import { describe, expect, it } from "vitest";
import { blockedIpv6MulticastLiterals } from "../../shared/net/ip-test-fixtures.js";
import { isBlockedHostnameOrIp, isPrivateIpAddress } from "./ssrf.js";

const privateIpCases = [
  "198.18.0.1",
  "198.19.255.254",
  "198.51.100.42",
  "203.0.113.10",
  "192.0.0.8",
  "192.0.2.1",
  "192.88.99.1",
  "224.0.0.1",
  "239.255.255.255",
  "240.0.0.1",
  "255.255.255.255",
  "::ffff:127.0.0.1",
  "::ffff:198.18.0.1",
  "64:ff9b::198.51.100.42",
  "0:0:0:0:0:ffff:7f00:1",
  "0000:0000:0000:0000:0000:ffff:7f00:0001",
  "::127.0.0.1",
  "0:0:0:0:0:0:7f00:1",
  "[0:0:0:0:0:ffff:7f00:1]",
  "::ffff:169.254.169.254",
  "0:0:0:0:0:ffff:a9fe:a9fe",
  "64:ff9b::127.0.0.1",
  "64:ff9b::169.254.169.254",
  "64:ff9b:1::192.168.1.1",
  "64:ff9b:1::10.0.0.1",
  "2002:7f00:0001::",
  "2002:a9fe:a9fe::",
  "2001:0000:0:0:0:0:80ff:fefe",
  "2001:0000:0:0:0:0:3f57:fefe",
  "2002:c612:0001::",
  "::",
  "::1",
  "fe80::1%lo0",
  "fd00::1",
  "fec0::1",
  "100::1",
  ...blockedIpv6MulticastLiterals,
  "2001:2::1",
  "2001:20::1",
  "2001:db8::1",
  "2001:db8:1234::5efe:127.0.0.1",
  "2001:db8:1234:1:200:5efe:7f00:1",
];

const publicIpCases = [
  "93.184.216.34",
  "198.17.255.255",
  "198.20.0.1",
  "198.51.99.1",
  "198.51.101.1",
  "203.0.112.1",
  "203.0.114.1",
  "223.255.255.255",
  "2606:4700:4700::1111",
  "64:ff9b::8.8.8.8",
  "64:ff9b:1::8.8.8.8",
  "2002:0808:0808::",
  "2001:0000:0:0:0:0:f7f7:f7f7",
  "2001:4860:1234::5efe:8.8.8.8",
  "2001:4860:1234:1:1111:5efe:7f00:1",
];

const malformedIpv6Cases = ["::::", "2001:db8::gggg"];
const unsupportedLegacyIpv4Cases = [
  "0177.0.0.1",
  "0x7f.0.0.1",
  "127.1",
  "2130706433",
  "0x7f000001",
  "017700000001",
  "8.8.2056",
  "0x08080808",
  "08.0.0.1",
  "0x7g.0.0.1",
  "127..0.1",
  "999.1.1.1",
];

const nonIpHostnameCases = ["example.com", "abc.123.example", "1password.com", "0x.example.com"];

function expectIpPrivacyCases(cases: string[], expected: boolean) {
  for (const address of cases) {
    expect(isPrivateIpAddress(address)).toBe(expected);
  }
}

describe("ssrf ip classification", () => {
  it("classifies blocked ip literals as private", () => {
    expectIpPrivacyCases(
      [...privateIpCases, ...malformedIpv6Cases, ...unsupportedLegacyIpv4Cases],
      true,
    );
  });

  it("classifies public ip literals as non-private", () => {
    expectIpPrivacyCases(publicIpCases, false);
  });

  it("does not treat hostnames as ip literals", () => {
    expectIpPrivacyCases(nonIpHostnameCases, false);
  });
});

describe("ipAllowlist policy", () => {
  it("allows private IPs when in ipAllowlist", () => {
    const policy = { ipAllowlist: ["10.0.0.1", "192.168.1.0/24", "172.16.0.0/16"] };

    // Exact match
    expect(isPrivateIpAddress("10.0.0.1", policy)).toBe(false);

    // CIDR match /24
    expect(isPrivateIpAddress("192.168.1.5", policy)).toBe(false);
    expect(isPrivateIpAddress("192.168.1.255", policy)).toBe(false);

    // CIDR match /16
    expect(isPrivateIpAddress("172.16.0.1", policy)).toBe(false);
    expect(isPrivateIpAddress("172.16.255.255", policy)).toBe(false);

    // Outside CIDR range - should be blocked
    expect(isPrivateIpAddress("192.168.2.1", policy)).toBe(true);
    expect(isPrivateIpAddress("172.17.0.1", policy)).toBe(true);
    expect(isPrivateIpAddress("10.0.0.2", policy)).toBe(true);
  });

  it("allows IPv6 addresses when in ipAllowlist", () => {
    const policy = { ipAllowlist: ["fd00::1", "fe80::/64"] };

    // Exact match
    expect(isPrivateIpAddress("fd00::1", policy)).toBe(false);

    // CIDR match
    expect(isPrivateIpAddress("fe80::1", policy)).toBe(false);
    expect(isPrivateIpAddress("fe80::ffff", policy)).toBe(false);

    // Outside CIDR range - should be blocked
    expect(isPrivateIpAddress("fd00::2", policy)).toBe(true);
    expect(isPrivateIpAddress("fe81::1", policy)).toBe(true);
  });

  it("handles bracketed IPv6 addresses in ipAllowlist", () => {
    const policy = { ipAllowlist: ["fd00::1"] };

    expect(isPrivateIpAddress("[fd00::1]", policy)).toBe(false);
  });

  it("combines ipAllowlist with other policies", () => {
    const policy = {
      ipAllowlist: ["10.0.0.0/24"],
      allowPrivateNetwork: false,
    };

    // IP in allowlist should be allowed even with allowPrivateNetwork=false
    expect(isPrivateIpAddress("10.0.0.5", policy)).toBe(false);

    // IP not in allowlist should still be blocked
    expect(isPrivateIpAddress("10.0.1.5", policy)).toBe(true);
  });

  it("allows localhost in ipAllowlist", () => {
    const policy = { ipAllowlist: ["127.0.0.1", "::1"] };

    expect(isPrivateIpAddress("127.0.0.1", policy)).toBe(false);
    expect(isPrivateIpAddress("::1", policy)).toBe(false);
  });

  it("works with isBlockedHostnameOrIp", () => {
    const policy = { ipAllowlist: ["10.0.0.1", "192.168.1.0/24"] };

    expect(isBlockedHostnameOrIp("10.0.0.1", policy)).toBe(false);
    expect(isBlockedHostnameOrIp("192.168.1.100", policy)).toBe(false);
    expect(isBlockedHostnameOrIp("10.0.0.2", policy)).toBe(true);
  });

  it("handles empty ipAllowlist", () => {
    const policy = { ipAllowlist: [] };

    expect(isPrivateIpAddress("10.0.0.1", policy)).toBe(true);
  });

  it("handles undefined ipAllowlist", () => {
    const policy = {};

    expect(isPrivateIpAddress("10.0.0.1", policy)).toBe(true);
  });

  it("ignores invalid CIDR entries", () => {
    const policy = { ipAllowlist: ["10.0.0.0/24", "invalid-ip", "not.a.cidr"] };

    // Valid entry works
    expect(isPrivateIpAddress("10.0.0.1", policy)).toBe(false);

    // Invalid entries don't cause errors, IP is still checked normally
    expect(isPrivateIpAddress("192.168.1.1", policy)).toBe(true);
  });
});

describe("isBlockedHostnameOrIp", () => {
  it.each([
    "localhost.localdomain",
    "metadata.google.internal",
    "api.localhost",
    "svc.local",
    "db.internal",
  ])("blocks reserved hostname %s", (hostname) => {
    expect(isBlockedHostnameOrIp(hostname)).toBe(true);
  });

  it.each([
    ["2001:db8:1234::5efe:127.0.0.1", true],
    ["100::1", true],
    ["2001:2::1", true],
    ["2001:20::1", true],
    ["2001:db8::1", true],
    ["198.18.0.1", true],
    ["198.20.0.1", false],
  ])("returns %s => %s", (value, expected) => {
    expect(isBlockedHostnameOrIp(value)).toBe(expected);
  });

  it.each([
    ["198.18.0.1", undefined, true],
    ["198.18.0.1", { allowRfc2544BenchmarkRange: true }, false],
    ["::ffff:198.18.0.1", { allowRfc2544BenchmarkRange: true }, false],
    ["198.51.100.1", { allowRfc2544BenchmarkRange: true }, true],
  ] as const)("applies RFC2544 benchmark policy for %s", (value, policy, expected) => {
    expect(isBlockedHostnameOrIp(value, policy)).toBe(expected);
  });

  it.each(["0177.0.0.1", "8.8.2056", "127.1", "2130706433"])(
    "blocks legacy IPv4 literal %s",
    (address) => {
      expect(isBlockedHostnameOrIp(address)).toBe(true);
    },
  );

  it.each(["example.com", "api.example.net"])("does not block ordinary hostname %s", (value) => {
    expect(isBlockedHostnameOrIp(value)).toBe(false);
  });
});
