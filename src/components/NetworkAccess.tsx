import { Globe } from "lucide-react";
import { useNetwork } from "../app/network";

/* =========================
   Network Access Switch
   ========================= */

/* The sidebar switch for connected analysis. Off, every tool stays offline. */
export default function NetworkAccess() {
  const { enabled, setEnabled } = useNetwork();

  return (
    <div className="network-toggle">
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        onClick={() => setEnabled(!enabled)}
      >
        <Globe className="nav-icon" size={18} strokeWidth={1.75} aria-hidden="true" />
        Network access
        <span className="switch" aria-hidden="true" />
      </button>
    </div>
  );
}
