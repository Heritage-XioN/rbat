"use client";

import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  TerminalSquare,
} from "lucide-react";
import { type ChangeEvent, type DragEvent, useRef, useState } from "react";
import { FormatBadge } from "@/components/ui/format-badge";
import { useAnalysisStore } from "@/lib/store/analysis-store";

export function UploadZone() {
  const {
    status,
    fileName,
    errorMessage,
    setStatus,
    setFileName,
    setFileInfo,
    setAnalysisData,
    setErrorMessage,
    reset,
  } = useAnalysisStore();

  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const startUpload = async (file: File) => {
    reset(); // Clear previous reports
    setStatus("uploading");
    setFileName(file.name);

    try {
      const formData = new FormData();
      formData.append("file", file);

      // Upload to API route
      const uploadRes = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      if (!uploadRes.ok) {
        const errData = await uploadRes.json();
        throw new Error(errData.error || "Failed to upload file");
      }

      const { fileId, md5Hash, size } = await uploadRes.json();
      setFileInfo(md5Hash, size);
      setStatus("analyzing");

      // Connect to Server-Sent Events (SSE) stream to listen for analysis completion
      const eventSource = new EventSource(`/api/events?fileId=${fileId}`);

      eventSource.addEventListener("complete", (event) => {
        const payloadData = JSON.parse(event.data);
        setAnalysisData(payloadData);
        setStatus("completed");
        eventSource.close();
      });

      eventSource.addEventListener("failed", (event) => {
        const payloadData = JSON.parse(event.data);
        const errObj =
          Object.values(payloadData.error)[0] || "Heuristic analysis failed";
        const errStr = Object.values(errObj)[0];
        setErrorMessage(errStr);
        setStatus("failed");
        eventSource.close();
      });

      eventSource.onerror = (err) => {
        console.error("SSE stream connection error:", err);
        const errStr = "Lost connection to the analysis event stream";
        setErrorMessage(errStr);
        setStatus("failed");
        eventSource.close();
      };
    } catch (err: any) {
      console.error("Upload error:", err);
      const uploadErr = err.message || "Upload failed";
      setErrorMessage(uploadErr);
      setStatus("failed");
    }
  };

  const handleDrag = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setIsDragActive(true);
    } else if (e.type === "dragleave") {
      setIsDragActive(false);
    }
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    if (status !== "idle" && status !== "completed" && status !== "failed") {
      return;
    }

    if (e.dataTransfer.files?.[0]) {
      startUpload(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files?.[0]) {
      startUpload(e.target.files[0]);
    }
  };

  const onButtonClick = () => {
    fileInputRef.current?.click();
  };

  const resetZone = (e: React.MouseEvent) => {
    e.stopPropagation();
    reset();
  };

  return (
    <section className="mx-auto w-full max-w-7xl px-6 py-8">
      {/* biome-ignore lint/a11y/useSemanticElements: Using div instead of button to allow nested hidden input for drag and drop */}
      <div
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
        onClick={
          status === "idle" || status === "completed" || status === "failed"
            ? onButtonClick
            : undefined
        }
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            if (
              status === "idle" ||
              status === "completed" ||
              status === "failed"
            )
              onButtonClick();
          }
        }}
        tabIndex={
          status === "idle" || status === "completed" || status === "failed"
            ? 0
            : -1
        }
        role="button"
        aria-label="Upload binary for analysis"
        id="binary-upload-dropzone"
        className={`flex flex-col items-center justify-center rounded-xl border border-dashed px-6 py-12 text-center transition-all focus:outline-none focus:ring-1 focus:ring-rbat-accent ${
          status === "idle" || status === "completed" || status === "failed"
            ? "cursor-pointer"
            : "cursor-default"
        } ${
          isDragActive
            ? "border-rbat-accent bg-rbat-accent/5"
            : "border-rbat-border bg-rbat-card/50 hover:border-rbat-accent/30 hover:bg-rbat-card/70"
        }`}
      >
        <input
          ref={fileInputRef}
          id="binary-file-input"
          name="binary-file-input"
          type="file"
          className="hidden"
          onChange={handleChange}
          disabled={
            status !== "idle" && status !== "completed" && status !== "failed"
          }
        />

        {/* Icon */}
        <div className="mb-4 flex size-16 items-center justify-center rounded-xl border border-rbat-border bg-rbat-card">
          {status === "uploading" || status === "analyzing" ? (
            <Loader2 className="size-8 text-rbat-accent animate-spin" />
          ) : status === "completed" ? (
            <CheckCircle2 className="size-8 text-green-500" />
          ) : status === "failed" ? (
            <AlertTriangle className="size-8 text-red-500" />
          ) : (
            <TerminalSquare className="size-8 text-rbat-accent" />
          )}
        </div>

        {/* Title */}
        <h2 className="mb-2 text-lg font-semibold text-rbat-text">
          {status === "uploading" && "Uploading Binary..."}
          {status === "analyzing" && "Analyzing Static Heuristics..."}
          {status === "completed" && "Analysis Completed"}
          {status === "failed" && "Analysis Failed"}
          {status === "idle" && "Initialize New Analysis"}
        </h2>

        {/* Description / Prompt */}
        <p className="mb-6 font-mono text-sm text-rbat-muted">
          {status === "idle" && "drag and drop binary here, or click to browse"}
          {(status === "uploading" ||
            status === "analyzing" ||
            status === "completed" ||
            status === "failed") &&
            fileName}
        </p>

        {/* Format badges or status description */}
        {status === "idle" ? (
          <div className="flex items-center gap-3">
            <FormatBadge label="ELF" shortLabel="E" />
            <FormatBadge label="PE" shortLabel="P" />
            <FormatBadge label="MACH-O" shortLabel="M" />
          </div>
        ) : (
          <div className="text-xs text-rbat-muted font-mono flex flex-col items-center gap-2">
            {status === "uploading" && (
              <span>Streaming to secure object storage...</span>
            )}
            {status === "analyzing" && (
              <span>Running YARA, Code Caves & API Hooking engines...</span>
            )}
            {status === "completed" && (
              <div className="flex flex-col items-center gap-2">
                <span>Review findings below.</span>
                <button
                  type="button"
                  onClick={resetZone}
                  className="mt-2 rounded-md border border-rbat-accent/30 bg-rbat-accent/10 px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest text-rbat-accent hover:bg-rbat-accent/20 transition-colors"
                >
                  Analyze Another File
                </button>
              </div>
            )}
            {status === "failed" && (
              <div className="flex flex-col items-center gap-2">
                <span className="text-red-400 font-semibold">
                  {errorMessage}
                </span>
                <button
                  type="button"
                  onClick={resetZone}
                  className="mt-2 rounded-md border border-rbat-accent/30 bg-rbat-accent/10 px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest text-rbat-accent hover:bg-rbat-accent/20 transition-colors"
                >
                  Try Again
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
