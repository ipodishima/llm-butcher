export interface ButcherConfig {
  domainAge: {
    enabled: boolean;
    warnDays: number;
    blockDays: number;
  };
  blocklist: {
    enabled: boolean;
    updateIntervalSeconds: number;
  };
  scriptAnalysis: {
    enabled: boolean;
    maxScriptSizeKB: number;
  };
  typosquat: {
    enabled: boolean;
    maxLevenshteinDistance: number;
    ecosystems: string[];
  };
  allowlist: {
    domains: string[];
    packages: Record<string, string[]>;
  };
  severity: {
    blockThreshold: "medium" | "high" | "critical";
  };
  rules?: {
    disabledPacks?: string[];
    disabledRules?: string[];
  };
}

export const DEFAULT_CONFIG: ButcherConfig = {
  domainAge: {
    enabled: true,
    warnDays: 30,
    blockDays: 7,
  },
  blocklist: {
    enabled: true,
    updateIntervalSeconds: 86400,
  },
  scriptAnalysis: {
    enabled: true,
    maxScriptSizeKB: 512,
  },
  typosquat: {
    enabled: true,
    maxLevenshteinDistance: 2,
    ecosystems: ["npm", "pip", "brew"],
  },
  allowlist: {
    domains: [
      "github.com",
      "raw.githubusercontent.com",
      "objects.githubusercontent.com",
      "nodejs.org",
      "npmjs.com",
      "registry.npmjs.org",
      "npmjs.org",
      "pypi.org",
      "files.pythonhosted.org",
      "brew.sh",
      "formulae.brew.sh",
      "dl.google.com",
      "packages.microsoft.com",
      "deb.nodesource.com",
      "apt.releases.hashicorp.com",
      "download.docker.com",
      "get.docker.com",
      "rust-lang.org",
      "sh.rustup.rs",
      "rubygems.org",
      "repo.maven.apache.org",
      "releases.hashicorp.com",
    ],
    packages: {
      npm: [],
      pip: [],
      brew: [],
    },
  },
  severity: {
    blockThreshold: "high",
  },
};
