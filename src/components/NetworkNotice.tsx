import { useNetwork } from "../app/network";

/* =========================
   Network Notice
   ========================= */

/* Shown on a tool that needs the network while the sidebar switch is off. */
export default function NetworkNotice() {
  const { enabled } = useNetwork();
  if (enabled) return null;

  return (
    <div className="notice" role="status">
      <strong>Network access is off.</strong> Turn it on in the sidebar to use this tool's connected analysis.
    </div>
  );
}
