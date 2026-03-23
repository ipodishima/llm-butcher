export enum Severity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export interface CheckResult {
  check: "domain-reputation" | "script-analysis" | "typosquat";
  severity: Severity;
  title: string;
  details: string;
  recommendation: string;
}

export interface ExtractedUrl {
  raw: string;
  hostname: string;
  protocol: string;
}

export interface PackageInstall {
  manager: "npm" | "pip" | "brew" | "yarn" | "pnpm";
  name: string;
}

export interface CommandClassification {
  urls: ExtractedUrl[];
  pipesToShell: boolean;
  packageInstalls: PackageInstall[];
  pipeToShellUrl: string | null;
}
