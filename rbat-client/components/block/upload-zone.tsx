"use client";

import { useState, useRef, type DragEvent, type ChangeEvent } from "react";
import {
  TerminalSquare,
  Loader2,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { FormatBadge } from "@/components/ui/format-badge";


export function UploadZone() {
  const [status, setStatus] = useState<
    "idle" | "uploading" | "analyzing" | "completed" | "failed"
  >("idle");
  const [fileName, setFileName] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const startUpload = async (file: File) => {
    setStatus("uploading");
    setFileName(file.name);
    setErrorMessage("");

    try {
      const formData = new FormData();
      formData.append("file", file);

     
      setStatus("analyzing");

    } catch (err: any) {
      console.error("Upload error:", err);
      setStatus("failed");
      const uploadErr = err.message || "Upload failed";
      setErrorMessage(uploadErr);
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

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      startUpload(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      startUpload(e.target.files[0]);
    }
  };

  const onButtonClick = () => {
    fileInputRef.current?.click();
  };

  const resetZone = (e: React.MouseEvent) => {
    e.stopPropagation();
    setStatus("idle");
    setFileName("");
    setErrorMessage("");
  };

  return (
    <section className="mx-auto w-full max-w-7xl px-6 py-8">
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
        id="binary-upload-dropzone"
        role="button"
        aria-label="Upload binary for analysis"
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
          {status === "analyzing" && "Performing static binary analysis..."}
          {status === "completed" && "Analysis Completed"}
          {status === "failed" && "Analysis Failed"}
          {status === "idle" && "Start New Analysis"}
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
