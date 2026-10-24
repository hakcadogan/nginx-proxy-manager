type Props = {
  text: string;
  /** Optional short label for screen readers; defaults to text */
  label?: string;
  /** Prefer "below" near the top of the viewport (e.g. sticky topbar). */
  placement?: "above" | "below";
};

/** Inline info icon with hover/focus tooltip for section titles. */
export default function HelpTip({ text, label, placement = "above" }: Props) {
  if (!text?.trim()) return null;
  return (
    <span
      className={`help-tip${placement === "below" ? " help-tip--below" : ""}`}
      tabIndex={0}
      aria-label={label || text}
    >
      <svg
        className="help-tip-icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <circle cx="12" cy="12" r="10" />
        <path d="M12 16v-4" />
        <path d="M12 8h.01" />
      </svg>
      <span className="help-tip-bubble" role="tooltip">
        {text}
      </span>
    </span>
  );
}
