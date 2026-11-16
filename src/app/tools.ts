import {
  FileBadge,
  Globe,
  KeyRound,
  Link,
  LockOpen,
  MailExclamationPoint,
  MailSearch,
  MonitorCheck,
  Network,
  type LucideIcon,
} from "lucide-react";

/* =========================
   Tool Registry
   ========================= */

/* The sidebar, home page and shortcuts are all built from this list. */
export interface Tool {
  id: string;
  label: string;
  icon: LucideIcon;
  summary: string;
  /* What the tool will check, shown until it is built. */
  plan: string[];
  /* What leaves the device when the tool runs. */
  privacy: string;
  ready: boolean;
}

export interface ToolGroup {
  id: string;
  label: string;
  tools: Tool[];
}

export const TOOL_GROUPS: ToolGroup[] = [
  {
    id: "password",
    label: "Password Security",
    tools: [
      {
        id: "password-strength",
        label: "Password Strength",
        icon: KeyRound,
        summary: "Estimate how well a password resists guessing.",
        plan: [
          "Length, character variety and common patterns",
          "Matches against known weak passwords",
          "Why each weakness makes guessing easier",
        ],
        privacy: "Runs entirely on this device. The password is never stored or sent.",
        ready: false,
      },
      {
        id: "password-breach",
        label: "Breached Passwords",
        icon: LockOpen,
        summary: "Check whether a password appears in known data breaches.",
        plan: [
          "Hash the password locally",
          "Look up only the first 5 characters of the hash",
          "Compare the returned matches on this device",
        ],
        privacy: "Only a 5-character hash prefix is sent. The password never leaves this device.",
        ready: false,
      },
    ],
  },
  {
    id: "phishing",
    label: "Scam & Phishing",
    tools: [
      {
        id: "url-check",
        label: "URL Checker",
        icon: Link,
        summary: "Inspect a link for signs of phishing before opening it.",
        plan: [
          "Lookalike domains and misleading subdomains",
          "Redirects, shorteners and unusual encoding",
          "Reputation from an external service, if enabled",
        ],
        privacy: "Structure checks run locally. Reputation lookups send the URL to a third party.",
        ready: false,
      },
      {
        id: "email-scam",
        label: "Email Scam Checker",
        icon: MailExclamationPoint,
        summary: "Review an email's text for common scam indicators.",
        plan: [
          "Urgency, threats and requests for payment or credentials",
          "Mismatched sender names and link targets",
          "Why each indicator is used by scammers",
        ],
        privacy: "Runs entirely on this device.",
        ready: false,
      },
      {
        id: "email-headers",
        label: "Email Headers",
        icon: MailSearch,
        summary: "Read SPF, DKIM, DMARC and routing from raw headers.",
        plan: [
          "SPF, DKIM and DMARC results",
          "The path the message took between servers",
          "Mismatches between sender fields",
        ],
        privacy: "Runs entirely on this device.",
        ready: false,
      },
    ],
  },
  {
    id: "network",
    label: "Network Tools",
    tools: [
      {
        id: "dns-lookup",
        label: "DNS Lookup",
        icon: Globe,
        summary: "Query DNS records for a domain.",
        plan: ["A, AAAA, MX, TXT, NS and CNAME records", "Mail security records such as SPF and DMARC"],
        privacy: "Sends the domain name to a DNS resolver.",
        ready: false,
      },
      {
        id: "ip-info",
        label: "IP Information",
        icon: Network,
        summary: "Look up ownership, location and reputation for an IP address.",
        plan: ["Network owner and approximate location", "Reputation from an external service, if enabled"],
        privacy: "Sends the IP address to a third-party lookup service.",
        ready: false,
      },
      {
        id: "tls-check",
        label: "TLS Certificate",
        icon: FileBadge,
        summary: "Inspect a site's certificate and TLS configuration.",
        plan: ["Certificate validity, issuer and expiry", "Supported protocol versions"],
        privacy: "Connects directly to the site you enter.",
        ready: false,
      },
    ],
  },
  {
    id: "device",
    label: "Device Security",
    tools: [
      {
        id: "windows-security",
        label: "Windows Security",
        icon: MonitorCheck,
        summary: "Review antivirus, firewall and update settings on this PC.",
        plan: [],
        privacy: "Reads settings on this device only. Nothing is changed or sent.",
        ready: true,
      },
    ],
  },
];

export const ALL_TOOLS = TOOL_GROUPS.flatMap((group) => group.tools);
