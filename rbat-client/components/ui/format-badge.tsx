import { cn } from "@/lib/utils";

interface FormatBadgeProps {
  label: string;
  shortLabel: string;
  className?: string;
}

export function FormatBadge({
  label,
  shortLabel,
  className,
}: FormatBadgeProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center rounded-md border border-rbat-border bg-rbat-card px-4 py-1.5 text-center",
        className,
      )}
    >
      <span className="text-xs font-semibold tracking-wider text-rbat-accent">
        {label}
      </span>
      <span className="text-[10px] font-medium text-rbat-muted">
        {shortLabel}
      </span>
    </div>
  );
}
