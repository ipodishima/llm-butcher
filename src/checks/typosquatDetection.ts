import { distance } from "fastest-levenshtein";
import { Severity, type CheckResult, type PackageInstall } from "./types.js";
import type { ButcherConfig } from "../config/defaults.js";
import topNpmPackages from "../data/topNpmPackages.json";
import topPypiPackages from "../data/topPypiPackages.json";

const PACKAGE_LISTS: Record<string, string[]> = {
  npm: topNpmPackages,
  pip: topPypiPackages,
};

function mapManagerToEcosystem(
  manager: PackageInstall["manager"]
): string {
  switch (manager) {
    case "npm":
    case "yarn":
    case "pnpm":
      return "npm";
    case "pip":
      return "pip";
    case "brew":
      return "brew";
  }
}

async function checkRegistryExists(
  pkg: PackageInstall
): Promise<CheckResult | null> {
  const ecosystem = mapManagerToEcosystem(pkg.manager);
  let registryUrl: string;

  switch (ecosystem) {
    case "npm":
      registryUrl = `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}`;
      break;
    case "pip":
      registryUrl = `https://pypi.org/pypi/${encodeURIComponent(pkg.name)}/json`;
      break;
    default:
      return null;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(registryUrl, {
      method: "HEAD",
      signal: controller.signal,
      headers: { "User-Agent": "LLM-Butcher/0.1.0" },
    });
    clearTimeout(timeout);

    if (response.status === 404) {
      return {
        check: "typosquat",
        severity: Severity.CRITICAL,
        title: `Package "${pkg.name}" does not exist in ${ecosystem} registry`,
        details: `No package named "${pkg.name}" was found at ${registryUrl}. This may indicate a typo or a malicious package name.`,
        recommendation: `Verify the package name is correct. Check the official documentation for the right package name.`,
      };
    }
  } catch {
    // Network error — don't block
  }

  return null;
}

export async function checkTyposquat(
  packages: PackageInstall[],
  config: ButcherConfig
): Promise<CheckResult[]> {
  if (!config.typosquat.enabled) return [];

  const results: CheckResult[] = [];

  for (const pkg of packages) {
    const ecosystem = mapManagerToEcosystem(pkg.manager);

    // Skip allowlisted packages
    const allowedPackages = config.allowlist.packages[ecosystem] ?? [];
    if (allowedPackages.includes(pkg.name)) continue;

    // Load top packages for this ecosystem
    const topPackages = PACKAGE_LISTS[ecosystem] ?? [];

    // If the exact package is in the top list, it's fine
    if (topPackages.includes(pkg.name)) continue;

    // Check Levenshtein distance against top packages
    let closestMatch: string | null = null;
    let closestDistance = Infinity;

    for (const topPkg of topPackages) {
      // Skip if length difference is too large (optimization)
      if (
        Math.abs(topPkg.length - pkg.name.length) >
        config.typosquat.maxLevenshteinDistance
      ) {
        continue;
      }

      const d = distance(pkg.name, topPkg);
      if (d < closestDistance) {
        closestDistance = d;
        closestMatch = topPkg;
      }
      if (d === 1) break;
    }

    if (
      closestMatch &&
      closestDistance <= config.typosquat.maxLevenshteinDistance
    ) {
      const severity =
        closestDistance === 1 ? Severity.HIGH : Severity.MEDIUM;
      results.push({
        check: "typosquat",
        severity,
        title: `Possible typosquat: "${pkg.name}" is similar to "${closestMatch}"`,
        details: `The package "${pkg.name}" is ${closestDistance} character(s) away from the popular package "${closestMatch}". This could be a typosquatting attack.`,
        recommendation: `Did you mean "${closestMatch}"? Verify the package name before installing.`,
      });
    }

    // Check if package exists in registry
    const registryResult = await checkRegistryExists(pkg);
    if (registryResult) {
      results.push(registryResult);
    }
  }

  return results;
}
