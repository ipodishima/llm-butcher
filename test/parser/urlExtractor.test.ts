import { describe, it, expect } from "vitest";
import { extractUrls } from "../../src/parser/urlExtractor.js";

describe("urlExtractor", () => {
  it("extracts simple HTTPS URLs", () => {
    const urls = extractUrls("curl https://example.com/install.sh");
    expect(urls).toHaveLength(1);
    expect(urls[0].hostname).toBe("example.com");
    expect(urls[0].protocol).toBe("https:");
  });

  it("extracts HTTP URLs", () => {
    const urls = extractUrls("wget http://example.com/file.tar.gz");
    expect(urls).toHaveLength(1);
    expect(urls[0].protocol).toBe("http:");
  });

  it("extracts URLs with paths and query strings", () => {
    const urls = extractUrls(
      "curl https://example.com/path/to/file?key=value&foo=bar"
    );
    expect(urls).toHaveLength(1);
    expect(urls[0].hostname).toBe("example.com");
  });

  it("extracts multiple URLs from one command", () => {
    const urls = extractUrls(
      "curl https://a.com/1 && curl https://b.com/2"
    );
    expect(urls).toHaveLength(2);
    expect(urls[0].hostname).toBe("a.com");
    expect(urls[1].hostname).toBe("b.com");
  });

  it("returns empty array for commands without URLs", () => {
    const urls = extractUrls("npm install lodash");
    expect(urls).toHaveLength(0);
  });

  it("handles URLs with port numbers", () => {
    const urls = extractUrls("curl https://localhost:3000/api");
    expect(urls).toHaveLength(1);
    expect(urls[0].hostname).toBe("localhost");
  });

  it("handles subdomains", () => {
    const urls = extractUrls("curl https://cdn.example.co.uk/file");
    expect(urls).toHaveLength(1);
    expect(urls[0].hostname).toBe("cdn.example.co.uk");
  });
});
