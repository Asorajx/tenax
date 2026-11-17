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

/* The navigation, home page and shortcuts are all built from this list. */
export interface Tool {
  id: string;
  label: string;
  icon: LucideIcon;
  summary: string;
  /* What leaves the device when the tool runs. */
  privacy: string;
  /* What the tool cannot tell you, shown under About Tenax in Settings. */
  limits: string;
  /* Whether the tool needs the network, or only uses it when asked. Left out for offline tools. */
  network?: "required" | "optional";
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
        summary: "See how difficult your password is to guess and how to make it stronger.",
        privacy: "Runs entirely on this device. The password is never stored or sent.",
        limits: "Estimates password strength based on detectable patterns but cannot guarantee resistance to compromise.",
        ready: true,
      },
      {
        id: "password-breach",
        label: "Breached Passwords",
        icon: LockOpen,
        summary: "Check whether a password appears in known data breaches.",
        privacy: "Checks for known breaches by sharing only a small part of your password's digital fingerprint.",
        limits: "Checks against the Have I Been Pwned breach database, which may not contain every compromised password.",
        network: "required",
        ready: true,
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
        privacy: "Runs entirely on this device. The address is never opened, followed or sent anywhere.",
        limits: "Examines link addresses for suspicious patterns without visiting the website or checking its reputation, so it cannot verify where a link finally leads.",
        ready: true,
      },
      {
        id: "email-scam",
        label: "Email Scam Checker",
        icon: MailExclamationPoint,
        summary: "Review an email's text for common scam indicators.",
        privacy: "Runs entirely on this device. The email is never stored or sent.",
        limits: "Looks for common scam signs in pasted text but cannot verify the sender.",
        ready: true,
      },
      {
        id: "email-headers",
        label: "Email Headers",
        icon: MailSearch,
        summary: "Read SPF, DKIM, DMARC and routing from raw headers.",
        privacy: "Runs entirely on this device. The headers are never stored or sent.",
        limits: "Reads authentication and routing information from email headers without independently verifying it.",
        ready: true,
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
        privacy: "Sends the domain name to the DNS server this PC already uses, which may pass it on, as it does for any website you visit. Nothing else leaves this PC. It needs network access to be on, but not necessarily an internet connection, since a DNS server on your own network can answer some names.",
        limits: "Displays DNS records returned by your server, which do not establish whether a domain is trustworthy.",
        network: "required",
        ready: true,
      },
      {
        id: "ip-info",
        label: "IP Information",
        icon: Network,
        summary: "See what kind of address an IP address is, and optionally who runs it.",
        privacy: "The address type is worked out on this PC. Reverse DNS sends the address to the DNS server this PC already uses. The owner and location lookup sends the address to ipinfo.io, an outside service, and only after you confirm it.",
        limits: "Identifies IP address types. Ownership and location from the outside service may be approximate, and a reverse DNS name does not prove who owns an address.",
        network: "optional",
        ready: true,
      },
      {
        id: "tls-check",
        label: "TLS Certificate",
        icon: FileBadge,
        summary: "Check a site's certificate and see what is wrong with it, if anything.",
        privacy: "Connects to the site you enter, on port 443, and only makes a secure handshake. It sends no web request, downloads nothing and follows no redirects. The server name is looked up through this PC's DNS server, and the site can see this PC's internet address, as any website can. No other service is contacted.",
        limits: "Examines the server certificate and Windows trust evaluation. It does not check certificate revocation, and a trusted certificate does not establish website safety.",
        network: "required",
        ready: true,
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
        privacy: "Reads settings on this device only. Nothing is changed or sent.",
        limits: "Checks antivirus, firewall and Windows Update status only. Healthy settings do not guarantee device security.",
        ready: true,
      },
    ],
  },
];

export const ALL_TOOLS = TOOL_GROUPS.flatMap((group) => group.tools);
