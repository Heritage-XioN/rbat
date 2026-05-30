"use client";

import { useAnalysisStore } from "@/lib/store/analysis-store";
import { useCompletion } from "@ai-sdk/react";
import { useEffect, useRef } from "react";
import { ArrowRight, Loader2 } from "lucide-react";

export function AiInsight() {
  // Subscribe to the analysis data from our global Zustand store
  const { analysisData } = useAnalysisStore();

  const { completion, complete, isLoading } = useCompletion({
    api: "/api/ai/insight",
  });

  const hasCalled = useRef(false);

  useEffect(() => {
    if (analysisData) {
      // Prevents duplicate stream calls in React StrictMode development builds
      if (!hasCalled.current) {
        hasCalled.current = true;
        complete(JSON.stringify(analysisData));
      }
    } else {
      hasCalled.current = false;
    }
  }, [analysisData, complete]);

  // Dynamically split streamed completion based on our ---RECOMMENDATION--- delimiter
  const parts = completion.split("---RECOMMENDATION---");
  const analysis = parts[0]?.trim();
  const recommendation = parts[1]?.trim();

  // If no analysis runs yet, hide the card
  if (!analysisData && !isLoading) {
    return null;
  }

  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
          <span
            className={`inline-block size-1.5 rounded-full bg-rbat-accent ${
              isLoading ? "animate-pulse" : ""
            }`}
          />
          AI Insight
        </h3>
        <span className="rounded-md border border-rbat-accent/30 bg-rbat-accent/10 px-3 py-1 text-[10px] font-bold uppercase tracking-widest text-rbat-accent">
          {isLoading ? "Synthesizing Summary..." : "Real-Time Analysis"}
        </span>
      </div>

      {/* Loading indicator prior to stream start */}
      {isLoading && !analysis && (
        <div className="flex items-center gap-2 py-4 text-xs font-mono text-rbat-muted">
          <Loader2 className="size-4 animate-spin text-rbat-accent" />
          Synthesizing binary report...
        </div>
      )}

      {/* Streamed Analysis Content */}
      {analysis && (
        <p className="mb-4 text-sm leading-relaxed text-rbat-text-secondary whitespace-pre-wrap">
          {analysis}
        </p>
      )}

      {/* Actionable Recommendation Blockquote */}
      {recommendation && (
        <blockquote className="mb-4 border-l-2 border-rbat-accent pl-4 text-sm italic leading-relaxed text-rbat-text-secondary">
          &ldquo;{recommendation}&rdquo;
        </blockquote>
      )}

      {/* Generate report link */}
      {/* <div className="flex justify-end">
        <button
          type="button"
          className="group flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-rbat-muted transition-colors hover:text-rbat-accent"
        >
          Generate Full AI Report
          <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
        </button>
      </div> */}
    </div>
  );
}
