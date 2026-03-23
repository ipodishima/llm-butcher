import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { Severity, type CheckResult, type ExtractedUrl } from "./types.js";
import type { ButcherConfig } from "../config/defaults.js";

const URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/";
const CACHE_DIR = join(homedir(), ".llm-butcher", "cache");
const BLOCKLIST_PATH = join(CACHE_DIR, "urlhaus.txt");

async function isCacheStale(
  filePath: string,
  maxAgeSeconds: number
): Promise<boolean> {
  try {
    const stats = await stat(filePath);
    const ageMs = Date.now() - stats.mtimeMs;
    return ageMs > maxAgeSeconds * 1000;
  } catch {
    return true;
  }
}

async function loadBlocklist(
  updateInterval: number
): Promise<Set<string>> {
  const stale = await isCacheStale(BLOCKLIST_PATH, updateInterval);

  if (!stale) {
    try {
      const content = await readFile(BLOCKLIST_PATH, "utf-8");
      const domains = new Set<string>();
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          try {
            const url = new URL(trimmed);
            domains.add(url.hostname);
          } catch {
            // Not a valid URL, try as domain
            if (trimmed.includes(".")) {
              domains.add(trimmed);
            }
          }
        }
      }
      return domains;
    } catch {
      // Cache read failed, will try to refresh
    }
  }

  // Try to download fresh blocklist
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const response = await fetch(URLHAUS_URL, {
      signal: controller.signal,
      headers: { "User-Agent": "LLM-Butcher/0.1.0" },
    });
    clearTimeout(timeout);

    if (response.ok) {
      const content = await response.text();
      await mkdir(CACHE_DIR, { recursive: true });
      await writeFile(BLOCKLIST_PATH, content, "utf-8");

      const domains = new Set<string>();
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          try {
            const url = new URL(trimmed);
            domains.add(url.hostname);
          } catch {
            if (trimmed.includes(".")) {
              domains.add(trimmed);
            }
          }
        }
      }
      return domains;
    }
  } catch {
    // Blocklist fetch failed, continue without it
  }

  return new Set();
}

async function checkDomainAge(
  hostname: string,
  config: ButcherConfig
): Promise<CheckResult | null> {
  try {
    // Dynamic import since whois-json is CJS
    const whois = await import("whois-json");
    const whoisLookup = whois.default || whois;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);

    const result = await Promise.race([
      whoisLookup(hostname),
      new Promise<null>((_, reject) =>
        setTimeout(() => reject(new Error("WHOIS timeout")), 1500)
      ),
    ]);
    clearTimeout(timeoutId);

    if (!result) return null;

    const whoisData = Array.isArray(result) ? result[0] : result;
    const creationDate =
      whoisData?.creationDate ||
      whoisData?.createdDate ||
      whoisData?.domainCreatedDate;

    if (!creationDate) return null;

    const created = new Date(creationDate);
    if (isNaN(created.getTime())) return null;

    const ageDays = Math.floor(
      (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24)
    );

    if (ageDays < config.domainAge.blockDays) {
      return {
        check: "domain-reputation",
        severity: Severity.HIGH,
        title: `Domain registered ${ageDays} day(s) ago (${hostname})`,
        details: `WHOIS creation date: ${created.toISOString().split("T")[0]}. Domains younger than ${config.domainAge.blockDays} days are highly suspicious.`,
        recommendation:
          "Do NOT run commands targeting this domain. Verify it is legitimate before proceeding.",
      };
    }

    if (ageDays < config.domainAge.warnDays) {
      return {
        check: "domain-reputation",
        severity: Severity.MEDIUM,
        title: `Domain registered ${ageDays} days ago (${hostname})`,
        details: `WHOIS creation date: ${created.toISOString().split("T")[0]}. This domain is less than ${config.domainAge.warnDays} days old.`,
        recommendation:
          "Verify this is the official domain for the tool you're installing.",
      };
    }

    return null;
  } catch {
    // WHOIS failed — don't block based on inability to verify
    return null;
  }
}

export async function checkDomainReputation(
  urls: ExtractedUrl[],
  config: ButcherConfig
): Promise<CheckResult[]> {
  if (!config.domainAge.enabled && !config.blocklist.enabled) return [];

  const results: CheckResult[] = [];
  const checkedDomains = new Set<string>();

  // Load blocklist
  const blocklist = config.blocklist.enabled
    ? await loadBlocklist(config.blocklist.updateIntervalSeconds)
    : new Set<string>();

  for (const url of urls) {
    const hostname = url.hostname;
    if (checkedDomains.has(hostname)) continue;
    checkedDomains.add(hostname);

    // Skip allowlisted domains
    if (
      config.allowlist.domains.some(
        (allowed) =>
          hostname === allowed || hostname.endsWith(`.${allowed}`)
      )
    ) {
      continue;
    }

    // Check blocklist
    if (blocklist.has(hostname)) {
      results.push({
        check: "domain-reputation",
        severity: Severity.CRITICAL,
        title: `Domain is on URLhaus blocklist (${hostname})`,
        details: `${hostname} appears in the URLhaus malware URL database.`,
        recommendation:
          "Do NOT run this command. This domain is known to distribute malware.",
      });
      continue;
    }

    // Check domain age
    if (config.domainAge.enabled) {
      const ageResult = await checkDomainAge(hostname, config);
      if (ageResult) {
        results.push(ageResult);
      }
    }
  }

  return results;
}
