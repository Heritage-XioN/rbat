import { cn } from "@/lib/utils";

interface DataRowProps {
  label: string;
  value?: string;
  className?: string;
  mono?: boolean;
}

export function DataRow({
  label,
  value,
  className,
  mono = false,
}: DataRowProps) {
  return (
    <div
      className={cn(
        "flex items-baseline justify-between gap-4 py-2",
        className,
      )}
    >
      <span className="text-[11px] font-semibold uppercase tracking-wider text-rbat-muted">
        {label}
      </span>
      <span
        className={cn(
          "text-sm text-rbat-text text-right",
          mono && "font-mono text-xs",
        )}
      >
        {value}
      </span>
    </div>
  );
}
