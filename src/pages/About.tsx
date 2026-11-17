import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { isTauri } from "@tauri-apps/api/core";
import { WORKSPACES } from "../app/workspaces";

/* =========================
   About
   ========================= */

/* Where data goes, in the same order for every tool. Each statement is checked against the code. */
const PRIVACY = [
  {
    title: "On this device",
    text: "Password Strength, URL Checker, Email Scam Checker, Email Headers and Windows Security do not send what you give them over the network. The URL Checker never opens the address.",
  },
  {
    title: "DNS queries",
    text: "DNS Lookup, IP Information (reverse DNS) and TLS Certificate (to find the server) send a name or address to the DNS server this PC is set to use. That server may forward the query, and Windows may cache the answer.",
  },
  {
    title: "Direct server connections",
    text: "TLS Certificate connects to the server you enter to read its certificate. The server can see this PC's public IP address.",
  },
  {
    title: "External services",
    text: "Breached Passwords sends only the first 5 characters of the password's hash to Have I Been Pwned, never the password. IP Information sends a public address to ipinfo.io, only after you confirm. Both services can see this PC's public IP address and may log requests.",
  },
  {
    title: "Network access",
    text: "Tools that connect need the Network access switch, which turns off every time Tenax starts.",
  },
  {
    title: "Data storage",
    text: "Tenax saves only your theme and log tab choices. What you enter, results and recent activity stay in memory until the app is closed.",
  },
];

export default function About() {
  /* The version comes from the app itself, so it is only shown when there is an app to ask. */
  const [version, setVersion] = useState("");
  useEffect(() => {
    if (isTauri()) getVersion().then(setVersion).catch(() => {});
  }, []);

  return (
    <div className="about">
      <section>
        <h2>About the results</h2>
        <p>
          Tenax helps identify potential security risks using available information. Its checks have limitations and
          cannot guarantee safety.
        </p>
      </section>

      <section>
        <h2>Known limitations</h2>
        {WORKSPACES.map((workspace) => (
          <div key={workspace.id} className="about-group">
            <h3>{workspace.label}</h3>
            <dl>
              {workspace.tools
                .filter((tool) => tool.ready)
                .map((tool) => (
                  <div key={tool.id}>
                    <dt>{tool.label}</dt>
                    <dd>{tool.limits}</dd>
                  </div>
                ))}
            </dl>
          </div>
        ))}
      </section>

      <section>
        <h2>Privacy &amp; data handling</h2>
        <dl>
          {PRIVACY.map((item) => (
            <div key={item.title}>
              <dt>{item.title}</dt>
              <dd>{item.text}</dd>
            </div>
          ))}
        </dl>
      </section>

      {version && (
        <section>
          <h2>Application</h2>
          <p>Tenax {version}</p>
        </section>
      )}
    </div>
  );
}
