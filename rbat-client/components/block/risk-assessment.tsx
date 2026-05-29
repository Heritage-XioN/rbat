import { RiskGauge } from "@/components/ui/risk-gauge";

interface RiskAssessmentProps {
  score?: number;
  severity?: string;
  threatLevel?: string;
  description?: string;
}

export function RiskAssessment({
  score,
  severity,
  threatLevel,
  description,
}: RiskAssessmentProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-rbat-border bg-rbat-card p-5">
      {/* Header */}
      <h3 className="mb-6 self-start text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
        Risk Assessment
      </h3>

      {/* Gauge */}
      <RiskGauge score={score} label={severity} />

      {/* Threat Level */}
      <div className="mt-6 flex items-center gap-2 self-start">
        <div className="h-6 w-1 rounded-full bg-rbat-accent" />
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-widest text-rbat-muted">
            Threat Level
          </p>
          <p className="text-lg font-bold text-rbat-text">{threatLevel}</p>
        </div>
      </div>

      {/* Description */}
      <p className="mt-4 self-start text-xs leading-relaxed text-rbat-text-secondary">
        {description}
      </p>
    </div>
  );
}
