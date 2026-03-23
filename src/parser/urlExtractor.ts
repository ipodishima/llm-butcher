import type { ExtractedUrl } from "../checks/types.js";

const URL_REGEX =
  /https?:\/\/[^\s"'<>|;)}\]]+/gi;

export function extractUrls(command: string): ExtractedUrl[] {
  const matches = command.match(URL_REGEX);
  if (!matches) return [];

  return matches.map((raw) => {
    try {
      const url = new URL(raw);
      return {
        raw,
        hostname: url.hostname,
        protocol: url.protocol,
      };
    } catch {
      // Fallback for malformed URLs
      const hostnameMatch = raw.match(/https?:\/\/([^/:\s]+)/);
      return {
        raw,
        hostname: hostnameMatch?.[1] ?? "",
        protocol: raw.startsWith("https") ? "https:" : "http:",
      };
    }
  });
}
