import { cn } from "@/lib/utils";

interface RiskGaugeProps {
  score?: number;
  label?: string;
  className?: string;
}

export function RiskGauge({ score = 0, label, className }: RiskGaugeProps) {
  const radius = 70;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const dashOffset = circumference - progress;

  return (
    <div className={cn("flex flex-col items-center", className)}>
      <svg
        width="180"
        height="180"
        viewBox="0 0 180 180"
        className="drop-shadow-[0_0_15px_rgba(192,132,252,0.2)]"
      >
        <title>Risk Score Gauge</title>
        {/* Background track */}
        <circle
          cx="90"
          cy="90"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-rbat-border"
        />
        {/* Progress arc */}
        <circle
          cx="90"
          cy="90"
          r={radius}
          fill="none"
          stroke="url(#gaugeGradient)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 90 90)"
          className="transition-all duration-1000 ease-out"
        />
        {/* Gradient definition */}
        <defs>
          <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#c084fc" />
            <stop offset="100%" stopColor="#e879a8" />
          </linearGradient>
        </defs>
        {/* Score text */}
        <text
          x="90"
          y="85"
          textAnchor="middle"
          className="fill-rbat-text text-4xl font-bold"
          fontSize="42"
          fontWeight="700"
        >
          {score}
        </text>
        {/* Label text */}
        {label && (
          <text
            x="90"
            y="108"
            textAnchor="middle"
            className="fill-rbat-muted uppercase tracking-widest"
            fontSize="10"
            fontWeight="600"
            letterSpacing="0.15em"
          >
            {label}
          </text>
        )}
      </svg>
    </div>
  );
}
