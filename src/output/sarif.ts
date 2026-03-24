import { Severity, type CheckResult } from "../checks/types.js";

// SARIF v2.1.0 types (subset)
export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: SarifLocation[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
    };
    region?: {
      startLine: number;
      snippet?: { text: string };
    };
  };
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function severityToLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case Severity.CRITICAL:
    case Severity.HIGH:
      return "error";
    case Severity.MEDIUM:
      return "warning";
    case Severity.LOW:
      return "note";
  }
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
    case Severity.HIGH:
      return "error";
    case Severity.MEDIUM:
      return "warning";
    case Severity.LOW:
      return "note";
  }
}

export function toSarif(
  results: CheckResult[],
  command: string
): SarifLog {
  // Build unique rules
  const ruleMap = new Map<string, SarifRule>();
  for (const result of results) {
    const ruleId = `${result.check}/${slugify(result.title)}`;
    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, {
        id: ruleId,
        shortDescription: { text: result.title },
        fullDescription: { text: result.recommendation },
        defaultConfiguration: {
          level: severityToSarifLevel(result.severity),
        },
      });
    }
  }

  // Build results
  const sarifResults: SarifResult[] = results.map((result) => ({
    ruleId: `${result.check}/${slugify(result.title)}`,
    level: severityToLevel(result.severity),
    message: {
      text: `${result.title}\n\n${result.details}\n\nRecommendation: ${result.recommendation}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: "stdin",
          },
          region: {
            startLine: 1,
            snippet: { text: command },
          },
        },
      },
    ],
  }));

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "LLM-Butcher",
            version: "0.2.0",
            informationUri: "https://github.com/user/llm-butcher",
            rules: Array.from(ruleMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };
}

export function toJson(
  results: CheckResult[],
  exitCode: number
): string {
  return JSON.stringify({ exitCode, results }, null, 2);
}
