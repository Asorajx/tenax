import type { ReactNode } from "react";
import { Info } from "lucide-react";
import type { Tool } from "../app/tools";

/* =========================
   Tool Page
   ========================= */

interface ToolPageProps {
  tool: Tool;
  /* Fine print shown in a popover behind an info button, in place of the privacy note. */
  info?: ReactNode;
  /* A control shown at the top right, such as Run again. */
  action?: ReactNode;
  children: ReactNode;
}

/* Shared frame for every tool: header, privacy note or info button, then the tool's content. */
export default function ToolPage({ tool, info, action, children }: ToolPageProps) {
  return (
    <>
      <header className="page-header page-header-row">
        <div className="page-header">
          <div className="page-title">
            <h1>{tool.label}</h1>
            {info && (
              <>
                {/* The id includes the tool, because several tool pages can be loaded at once. */}
                <button
                  type="button"
                  className="icon-button"
                  popoverTarget={`${tool.id}-info`}
                  aria-label="About this check"
                >
                  <Info size={16} strokeWidth={1.75} aria-hidden="true" />
                </button>
                <div id={`${tool.id}-info`} popover="auto" className="info-popover">
                  {info}
                </div>
              </>
            )}
          </div>
          <p>{tool.summary}</p>
        </div>
        {action}
      </header>

      {!info && <p className="notice">{tool.privacy}</p>}

      {children}
    </>
  );
}
