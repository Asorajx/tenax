import { useNetwork } from "../app/network";

/* =========================
   Network Notice
   ========================= */

/* Shown on a tool that needs the network while the sidebar switch is off. */
export default function NetworkNotice() {
  const { enabled, setEnabled } = useNetwork();
  if (enabled) return null;

  return (
    <div className="notice" role="status" data-action="true">
      <strong>Network access is off.</strong>
      <button type="button" className="button button-small" onClick={() => setEnabled(true)}>
        Turn on
      </button>
    </div>
  );
}
