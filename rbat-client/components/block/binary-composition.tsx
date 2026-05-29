interface Section {
  name: string;
  label: string;
  percentage: number;
}

interface BinaryCompositionProps {
  sections?: Section[];
}

export function BinaryComposition({ sections }: BinaryCompositionProps) {
  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5">
      {/* Header */}
      <h3 className="mb-4 text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
        Binary Composition
      </h3>

      {/* Progress bars */}
      <div className="space-y-4">
        {sections?.map((section) => (
          <div key={section.name} className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-rbat-text">
                {section.label}{" "}
                <span className="text-rbat-muted">({section.name})</span>
              </span>
              <span className="text-xs font-semibold text-rbat-text-secondary">
                {section.percentage}%
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-rbat-border">
              <div
                className="h-full rounded-full bg-gradient-to-r from-rbat-accent to-pink-400 transition-all duration-700"
                style={{ width: `${section.percentage}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
