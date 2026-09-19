"use client";

import { useState, useMemo } from "react";
import JSZip from "jszip";
import {
  Globe,
  Code2,
  Binary,
  Radio as NetworkIcon,
  GitBranch,
  Play,
  Lock,
  FolderGit2,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Upload,
  FileCode,
  Folder,
  Archive,
} from "lucide-react";

export interface ScanStudioProps {
  projectId: string;
  onJobCreated?: (jobId?: string) => void;
  onNavigateToJobs?: () => void;
}

export function ScanStudio({
  projectId,
  onJobCreated,
  onNavigateToJobs,
}: ScanStudioProps) {
  const [scanType, setScanType] = useState<"network" | "code" | "binary" | "pcap" | "github">("code");

  // Network State
  const [targetHost, setTargetHost] = useState("example.com");
  const [targetPort, setTargetPort] = useState(443);

  // Source Code State
  const [sourceMode, setSourceMode] = useState<"snippet" | "file" | "folder" | "archive">("snippet");
  const [sourceCode, setSourceCode] = useState(
    'import hashlib\nfrom Crypto.PublicKey import RSA\n\nkey = RSA.generate(2048)\nlegacy = hashlib.sha1(b"test").hexdigest()'
  );
  const [sourceLang, setSourceLang] = useState("python");
  const [sourceFile, setSourceFile] = useState<File | null>(null);

  // Folder Selection State
  const [folderFiles, setFolderFiles] = useState<File[]>([]);
  const [folderName, setFolderName] = useState<string>("");
  const [excludedCount, setExcludedCount] = useState<number>(0);
  const [totalFolderBytes, setTotalFolderBytes] = useState<number>(0);
  const [isZipping, setIsZipping] = useState<boolean>(false);

  // Binary State
  const [binaryFile, setBinaryFile] = useState<File | null>(null);

  // GitHub Repo State
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [token, setToken] = useState("");
  const [subdir, setSubdir] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(false);

  // Submission & Progress State
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const [uploadProgress, setUploadProgress] = useState<{
    active: boolean;
    currentChunk: number;
    totalChunks: number;
    uploadedBytes: number;
    totalBytes: number;
    message: string;
  } | null>(null);

  // GitHub URL Validation: must match github.com/owner/repo pattern
  const isGithubUrlValid = useMemo(() => {
    if (!repoUrl.trim()) return false;
    const pattern = /^(https:\/\/)?(www\.)?github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/;
    return pattern.test(repoUrl.trim());
  }, [repoUrl]);

  // File size validation and selection (up to 1GB with chunked streaming)
  const handleFileSelected = (file: File | null, type: "source" | "binary") => {
    setErrorMsg(null);
    if (!file) {
      if (type === "source") setSourceFile(null);
      else setBinaryFile(null);
      return;
    }

    // Max file size enforcement: reject files > 1GB before upload starts
    if (file.size > 1024 * 1024 * 1024) {
      setErrorMsg(`File "${file.name}" (${(file.size / (1024 * 1024)).toFixed(1)} MB) exceeds the maximum allowed 1GB limit. Please select a smaller file.`);
      if (type === "source") setSourceFile(null);
      else setBinaryFile(null);
      return;
    }

    if (type === "source") setSourceFile(file);
    else setBinaryFile(file);
  };

  // Folder selection and auto-exclusion handler
  const handleFolderSelected = (filesList: FileList | null) => {
    setErrorMsg(null);
    if (!filesList || filesList.length === 0) {
      setFolderFiles([]);
      setFolderName("");
      setExcludedCount(0);
      setTotalFolderBytes(0);
      return;
    }
    const allFiles = Array.from(filesList);
    const firstRel = allFiles[0]?.webkitRelativePath || "";
    const fName = firstRel.split("/")[0] || "project";
    setFolderName(fName);

    const excluded = allFiles.filter((f) => {
      const p = f.webkitRelativePath.toLowerCase();
      return (
        p.includes("node_modules/") ||
        p.includes("/node_modules/") ||
        p.includes(".git/") ||
        p.includes("/.git/") ||
        p.includes("dist/") ||
        p.includes("/dist/") ||
        p.includes("build/") ||
        p.includes("/build/") ||
        p.includes("__pycache__/") ||
        p.includes("/__pycache__/") ||
        p.includes(".venv/") ||
        p.includes("/.venv/") ||
        p.includes(".next/") ||
        p.includes("/.next/") ||
        f.name === ".DS_Store"
      );
    });

    const included = allFiles.filter((f) => !excluded.includes(f));
    const totalBytes = included.reduce((acc, f) => acc + f.size, 0);

    if (totalBytes > 1024 * 1024 * 1024) {
      setErrorMsg(`Selected folder (${(totalBytes / (1024 * 1024)).toFixed(1)} MB) exceeds the 1GB maximum size limit.`);
      return;
    }

    setFolderFiles(included);
    setExcludedCount(excluded.length);
    setTotalFolderBytes(totalBytes);
  };

  const isFormValid = useMemo(() => {
    if (scanType === "github") {
      return isGithubUrlValid && isAuthorized;
    }
    if (scanType === "network") {
      return Boolean(targetHost.trim());
    }
    if (scanType === "code") {
      if (sourceMode === "snippet") return Boolean(sourceCode.trim());
      if (sourceMode === "folder") return folderFiles.length > 0;
      return Boolean(sourceFile);
    }
    if (scanType === "binary") {
      return Boolean(binaryFile);
    }
    return true; // pcap
  }, [scanType, isGithubUrlValid, isAuthorized, targetHost, sourceMode, sourceCode, sourceFile, folderFiles, binaryFile]);

  // Sequential chunked upload function
  const uploadInChunks = async (file: File, surface: "code" | "binary"): Promise<string> => {
    const CHUNK_SIZE = 2 * 1024 * 1024; // 2MB
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const uploadId = crypto.randomUUID();
    let uploadedBytes = 0;

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(file.size, start + CHUNK_SIZE);
      const chunkBlob = file.slice(start, end);

      let chunkUploaded = false;
      let lastErr: any = null;

      // Retry up to 3 times per chunk
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          setUploadProgress({
            active: true,
            currentChunk: i + 1,
            totalChunks,
            uploadedBytes,
            totalBytes: file.size,
            message: `Uploading... chunk ${i + 1} of ${totalChunks} (${(uploadedBytes / (1024 * 1024)).toFixed(1)} MB / ${(file.size / (1024 * 1024)).toFixed(1)} MB)`,
          });

          const chunkRes = await fetch(`/api/upload/chunk`, {
            method: "POST",
            headers: {
              "Content-Type": "application/octet-stream",
              "X-Upload-ID": uploadId,
              "X-Chunk-Index": i.toString(),
              "X-Total-Chunks": totalChunks.toString(),
              "X-Filename": file.name,
              "X-Surface": surface,
              "X-Project-ID": projectId,
            },
            body: chunkBlob,
          });

          if (!chunkRes.ok) {
            const errText = await chunkRes.text();
            throw new Error(errText || `Server error ${chunkRes.status}`);
          }

          uploadedBytes += (end - start);
          chunkUploaded = true;
          break;
        } catch (err: any) {
          lastErr = err;
          if (attempt < 3) {
            setErrorMsg(`Chunk ${i + 1} failed — retrying (attempt ${attempt} of 3)...`);
            await new Promise((r) => setTimeout(r, 1000));
          }
        }
      }

      if (!chunkUploaded) {
        throw new Error(`Chunk ${i + 1} failed after 3 attempts: ${lastErr?.message || "Upload failed"}`);
      }
    }

    setUploadProgress({
      active: true,
      currentChunk: totalChunks,
      totalChunks,
      uploadedBytes: file.size,
      totalBytes: file.size,
      message: "Upload completed. Assembling on server and initiating scan...",
    });

    // Poll GET /api/upload/{upload_id}/status every 2s after last chunk
    let scanJobId: string | undefined;
    for (let p = 0; p < 30; p++) {
      await new Promise((r) => setTimeout(r, 2000));
      try {
        const pollRes = await fetch(`/api/upload/${uploadId}/status`);
        if (pollRes.ok) {
          const pollData = await pollRes.json();
          if (pollData.status === "processing" || pollData.scan_job_id) {
            scanJobId = pollData.scan_job_id;
            break;
          }
          if (pollData.status === "failed") {
            throw new Error("Server reported upload assembly or scanning failure");
          }
        }
      } catch (pollErr: any) {
        console.warn("Poll status error:", pollErr);
      }
    }

    return scanJobId || uploadId;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isFormValid) return;

    setSubmitting(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    setUploadProgress(null);

    try {
      let createdJobId: string | undefined;

      if (scanType === "github") {
        let normalizedUrl = repoUrl.trim();
        if (!normalizedUrl.startsWith("https://")) {
          normalizedUrl = "https://" + normalizedUrl.replace(/^http:\/\//, "");
        }

        const res = await fetch(`/api/scan/github?project=${encodeURIComponent(projectId)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_url: normalizedUrl,
            token: token.trim() || null,
            branch: branch.trim() || null,
            subdir: subdir.trim() || null,
            project_id: projectId,
          }),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || "Failed to submit GitHub scan job");
        }

        const data = await res.json();
        createdJobId = data.scan_id || data.id;
      } else if (scanType === "network") {
        const cleanHost = targetHost.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
        const res = await fetch(`/api/scan/network?project=${encodeURIComponent(projectId)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: cleanHost || targetHost, port: Number(targetPort) || 443 }),
        });
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || "Failed to submit network scan job");
        }
        const data = await res.json();
        createdJobId = data.scan_id || data.id;
      } else if (scanType === "code") {
        if (sourceMode === "folder" && folderFiles.length > 0) {
          setIsZipping(true);
          const zip = new JSZip();
          for (const f of folderFiles) {
            zip.file(f.webkitRelativePath, f);
          }
          const zipBlob = await zip.generateAsync({ type: "blob", compression: "DEFLATE" });
          setIsZipping(false);
          const zipFile = new File([zipBlob], `${folderName || "project"}.zip`, { type: "application/zip" });
          // Archives always go through the chunked source path: the backend
          // extracts source files and manifests from the ZIP before scanning.
          createdJobId = await uploadInChunks(zipFile, "code");
        } else if ((sourceMode === "file" || sourceMode === "archive") && sourceFile) {
          const isArchive = /\.(zip|tar|gz|tgz|7z)$/i.test(sourceFile.name);
          if (isArchive) {
            // Archives always go through the chunked source path (ZIP extraction
            // + source scanning on the backend) instead of the binary surface.
            createdJobId = await uploadInChunks(sourceFile, "code");
          } else if (sourceFile.size < 10 * 1024 * 1024) {
            const txt = await sourceFile.text();
            const res = await fetch(`/api/scan/code?project=${encodeURIComponent(projectId)}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ source_code: txt, language: sourceLang }),
            });
            if (!res.ok) {
              const errData = await res.json().catch(() => ({}));
              throw new Error(errData.detail || "Failed to submit source file scan");
            }
            const data = await res.json();
            createdJobId = data.scan_id || data.id;
          } else {
            // file.size >= 10MB: chunked upload
            createdJobId = await uploadInChunks(sourceFile, "code");
          }
        } else {
          // Paste snippet
          const res = await fetch(`/api/scan/code?project=${encodeURIComponent(projectId)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ source_code: sourceCode, language: sourceLang }),
          });
          if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || "Failed to submit source code scan");
          }
          const data = await res.json();
          createdJobId = data.scan_id || data.id;
        }
      } else if (scanType === "binary" && binaryFile) {
        // If file.size < 10MB: use existing direct upload
        if (binaryFile.size < 10 * 1024 * 1024) {
          const fd = new FormData();
          fd.append("file", binaryFile);
          const res = await fetch(`/api/scan/binary/upload?project=${encodeURIComponent(projectId)}`, {
            method: "POST",
            body: fd,
          });
          if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || "Failed to upload and scan binary");
          }
          const data = await res.json();
          createdJobId = data.scan_id || data.id;
        } else {
          // file.size >= 10MB: chunked upload
          createdJobId = await uploadInChunks(binaryFile, "binary");
        }
      } else if (scanType === "pcap") {
        const res = await fetch(
          `/api/scan/pcap/synthetic?project=${encodeURIComponent(projectId)}&with_pqc_hybrid=true`,
          { method: "POST" }
        );
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || "Failed to queue synthetic PCAP scan");
        }
        const data = await res.json();
        createdJobId = data.scan_id || data.id;
      }

      setSuccessMsg("Scan job registered successfully. Redirecting to Scan Jobs...");
      if (onJobCreated) onJobCreated(createdJobId);
      if (onNavigateToJobs) {
        setTimeout(() => {
          onNavigateToJobs();
        }, 800);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "An unexpected error occurred during job submission");
    } finally {
      setSubmitting(false);
      setUploadProgress(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight">Scan Studio</h2>
        <p className="text-xs text-quiet mt-1">
          Submit multi-modal discovery jobs across GitHub repositories, source AST, binaries, TLS endpoints, and synthetic PCAP streams.
        </p>
      </div>

      {/* Surface Cards Selection */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { key: "network", label: "Network TLS Probe", desc: "Live TLS 1.0–1.3 & Hybrid PQC", icon: Globe },
          { key: "code", label: "Source Code AST", desc: "Python, C, Go, Java Call Sites", icon: Code2 },
          { key: "binary", label: "Binary Inspection", desc: "ELF / PE / Mach-O S-Boxes", icon: Binary },
          { key: "pcap", label: "PCAP Stream", desc: "Synthetic Network Handshakes", icon: NetworkIcon },
          { key: "github", label: "GitHub Repo", desc: "Shallow Clone & Repository Analysis", icon: GitBranch },
        ].map((s) => (
          <button
            key={s.key}
            type="button"
            onClick={() => {
              setScanType(s.key as any);
              setErrorMsg(null);
              setSuccessMsg(null);
              setUploadProgress(null);
            }}
            className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
              scanType === s.key
                ? "bg-cyan-500/15 border-cyan-500/40 text-cyan-300 ring-1 ring-cyan-400/50"
                : "bg-surface border-subtle text-quiet hover:text-foreground hover:border-cyan-500/30"
            }`}
          >
            <s.icon className="h-4 w-4 mb-2 text-cyan-400" />
            <div className="text-xs font-semibold text-foreground">{s.label}</div>
            <div className="text-[11px] text-quiet mt-0.5">{s.desc}</div>
          </button>
        ))}
      </div>

      {/* Progress Bar for Chunked Upload */}
      {uploadProgress?.active && (
        <div className="p-4 rounded-xl border border-cyan-500/40 bg-cyan-500/10 space-y-2 font-mono">
          <div className="flex items-center justify-between text-xs">
            <span className="text-cyan-300 font-semibold">{uploadProgress.message}</span>
            <span className="text-cyan-400 font-bold">
              {Math.min(100, Math.round((uploadProgress.uploadedBytes / uploadProgress.totalBytes) * 100))}%
            </span>
          </div>
          <div className="h-2 rounded-full bg-canvas overflow-hidden border border-subtle">
            <div
              className="h-full bg-cyan-500 rounded-full transition-all duration-300"
              style={{
                width: `${Math.min(100, Math.round((uploadProgress.uploadedBytes / uploadProgress.totalBytes) * 100))}%`,
              }}
            />
          </div>
        </div>
      )}

      {/* Alerts */}
      {errorMsg && (
        <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-xs text-rose-300 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{errorMsg}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Form container */}
      <form onSubmit={handleSubmit} className="rounded-xl border border-subtle bg-surface p-6 space-y-4">
        {/* TAB 1: Network */}
        {scanType === "network" && (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-2">
                <label className="block text-xs font-semibold mb-1.5">Target Hostname or IP *</label>
                <input
                  type="text"
                  required
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas font-mono text-cyan-400 outline-none focus:border-cyan-500"
                  placeholder="e.g. localhost or api.internal.domain"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold mb-1.5">Port</label>
                <input
                  type="number"
                  value={targetPort}
                  onChange={(e) => setTargetPort(Number(e.target.value))}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground outline-none focus:border-cyan-500"
                />
              </div>
            </div>
            <p className="text-[11px] text-quiet">
              Executes TLS negotiation, cipher suite enumeration, leaf certificate inspection, and live PQC hybrid key establishment tests.
            </p>
          </div>
        )}

        {/* TAB 2: Source Code */}
        {scanType === "code" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-subtle pb-2.5">
              <label className="text-xs font-semibold">Source Code Ingestion</label>
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <button
                  type="button"
                  onClick={() => setSourceMode("snippet")}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    sourceMode === "snippet"
                      ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                      : "text-quiet hover:text-foreground"
                  }`}
                >
                  Paste Snippet
                </button>
                <button
                  type="button"
                  onClick={() => setSourceMode("file")}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    sourceMode === "file"
                      ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                      : "text-quiet hover:text-foreground"
                  }`}
                >
                  Single File
                </button>
                <button
                  type="button"
                  onClick={() => setSourceMode("folder")}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer flex items-center gap-1 ${
                    sourceMode === "folder"
                      ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                      : "text-quiet hover:text-foreground"
                  }`}
                >
                  <Folder className="h-3.5 w-3.5" />
                  Select Folder
                </button>
                <button
                  type="button"
                  onClick={() => setSourceMode("archive")}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer flex items-center gap-1 ${
                    sourceMode === "archive"
                      ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                      : "text-quiet hover:text-foreground"
                  }`}
                >
                  <Archive className="h-3.5 w-3.5" />
                  Upload ZIP
                </button>
              </div>
            </div>

            {sourceMode === "snippet" && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-quiet">Select Language Grammar:</span>
                  <select
                    value={sourceLang}
                    onChange={(e) => setSourceLang(e.target.value)}
                    className="px-2 py-1 text-xs rounded border border-subtle bg-canvas outline-none"
                  >
                    <option value="python">Python</option>
                    <option value="java">Java</option>
                    <option value="c_cpp">C / C++</option>
                    <option value="golang">Go</option>
                    <option value="javascript">JavaScript / TypeScript</option>
                  </select>
                </div>
                <textarea
                  rows={6}
                  value={sourceCode}
                  onChange={(e) => setSourceCode(e.target.value)}
                  className="w-full p-3 font-mono text-xs rounded-lg border border-subtle bg-canvas text-cyan-300 outline-none focus:border-cyan-500"
                />
              </div>
            )}

            {sourceMode === "file" && (
              <div className="space-y-3">
                <label className="block text-xs font-semibold mb-1">Select Single Source Code File (.py, .c, .go, .js, .java, etc.)</label>
                <input
                  type="file"
                  onChange={(e) => handleFileSelected(e.target.files?.[0] || null, "source")}
                  className="w-full text-xs file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyan-500/10 file:text-cyan-400 hover:file:bg-cyan-500/20 cursor-pointer"
                />
                {sourceFile && (
                  <div className="p-3 rounded-lg bg-canvas border border-subtle text-xs font-mono flex items-center justify-between">
                    <span className="text-foreground">{sourceFile.name} ({(sourceFile.size / (1024 * 1024)).toFixed(2)} MB)</span>
                    {sourceFile.size >= 10 * 1024 * 1024 ? (
                      <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px] font-semibold border border-amber-500/30">
                        Chunked Upload (&ge;10MB)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[10px] font-semibold border border-emerald-500/30">
                        Direct Upload (&lt;10MB)
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}

            {sourceMode === "folder" && (
              <div className="space-y-3">
                <label className="block text-xs font-semibold mb-1">
                  Select Project Folder (Auto-excludes node_modules, .git, dist, __pycache__)
                </label>
                <input
                  type="file"
                  {...({ webkitdirectory: "", directory: "", multiple: true } as any)}
                  onChange={(e) => handleFolderSelected(e.target.files)}
                  className="w-full text-xs file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyan-500/10 file:text-cyan-400 hover:file:bg-cyan-500/20 cursor-pointer"
                />
                {folderFiles.length > 0 && (
                  <div className="p-3.5 rounded-lg bg-canvas border border-subtle space-y-1 text-xs">
                    <div className="font-mono text-cyan-400 font-semibold flex items-center justify-between">
                      <span>Folder: {folderName}/ ({folderFiles.length} files included)</span>
                      <span>{(totalFolderBytes / (1024 * 1024)).toFixed(2)} MB</span>
                    </div>
                    {excludedCount > 0 && (
                      <p className="text-[11px] text-quiet">
                        Automatically excluded {excludedCount.toLocaleString()} dependency &amp; cache files in node_modules, .git, dist, build, __pycache__.
                      </p>
                    )}
                  </div>
                )}
                <p className="text-[11px] text-quiet">
                  Browser will bundle project files into an in-memory ZIP package and stream to AST scanner. Max 1GB.
                </p>
              </div>
            )}

            {sourceMode === "archive" && (
              <div className="space-y-3">
                <label className="block text-xs font-semibold mb-1">Select Code Archive (.zip, .tar.gz up to 1GB)</label>
                <input
                  type="file"
                  accept=".zip,.tar,.gz,.7z"
                  onChange={(e) => handleFileSelected(e.target.files?.[0] || null, "source")}
                  className="w-full text-xs file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyan-500/10 file:text-cyan-400 hover:file:bg-cyan-500/20 cursor-pointer"
                />
                {sourceFile && (
                  <div className="p-3 rounded-lg bg-canvas border border-subtle text-xs font-mono flex items-center justify-between">
                    <span className="text-foreground">{sourceFile.name} ({(sourceFile.size / (1024 * 1024)).toFixed(2)} MB)</span>
                    <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 text-[10px] font-semibold">
                      Archive Ready
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: Binary */}
        {scanType === "binary" && (
          <div className="space-y-4">
            <label className="block text-xs font-semibold mb-1.5">Executable, Library, or Archive Upload (Up to 1GB)</label>
            <input
              type="file"
              onChange={(e) => handleFileSelected(e.target.files?.[0] || null, "binary")}
              className="w-full text-xs file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyan-500/10 file:text-cyan-400 hover:file:bg-cyan-500/20 cursor-pointer"
            />
            {binaryFile && (
              <div className="p-3 rounded-lg bg-canvas border border-subtle text-xs font-mono flex items-center justify-between">
                <span className="text-foreground">{binaryFile.name} ({(binaryFile.size / (1024 * 1024)).toFixed(2)} MB)</span>
                {binaryFile.size >= 10 * 1024 * 1024 ? (
                  <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px] font-semibold border border-amber-500/30">
                    Chunked Upload (&ge;10MB, 2MB chunks)
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[10px] font-semibold border border-emerald-500/30">
                    Direct Upload (&lt;10MB)
                  </span>
                )}
              </div>
            )}
            <p className="text-[11px] text-quiet">
              Analyzes ELF/PE sections, S-box constants, sliding entropy, and embedded key material without executing foreign code. Files larger than 10MB are uploaded in 2MB sequential chunks. Max allowed size: 1GB.
            </p>
          </div>
        )}

        {/* TAB 4: PCAP */}
        {scanType === "pcap" && (
          <div className="space-y-2">
            <p className="text-xs text-foreground font-semibold">Synthetic PCAP Post-Quantum Stream Probing</p>
            <p className="text-[11px] text-quiet">
              Generates synthetic network capture packets testing hybrid key exchange (`X25519MLKEM768`) and classic TLS sessions.
            </p>
          </div>
        )}

        {/* TAB 5: GitHub Repo */}
        {scanType === "github" && (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold mb-1.5 flex items-center justify-between">
                <span>Repository URL *</span>
                {repoUrl && (
                  <span className={`text-[11px] font-mono ${isGithubUrlValid ? "text-emerald-400" : "text-rose-400"}`}>
                    {isGithubUrlValid ? "Valid GitHub URL" : "Must match github.com/owner/repo"}
                  </span>
                )}
              </label>
              <div className="relative">
                <input
                  type="text"
                  required
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className={`w-full pl-9 pr-3 py-2 text-xs rounded-lg border bg-canvas font-mono text-cyan-400 outline-none transition-colors ${
                    repoUrl && !isGithubUrlValid
                      ? "border-rose-500/60 focus:border-rose-500"
                      : "border-subtle focus:border-cyan-500"
                  }`}
                  placeholder="https://github.com/owner/repository"
                />
                <GitBranch className="h-4 w-4 absolute left-3 top-2.5 text-quiet" />
              </div>
              <p className="text-[11px] text-quiet mt-1">
                Enter the HTTPS URL of the target GitHub repository (e.g., https://github.com/torvalds/linux).
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold mb-1.5">Branch</label>
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas font-mono text-foreground outline-none focus:border-cyan-500"
                  placeholder="main"
                />
                <p className="text-[11px] text-quiet mt-1">
                  Optional. Leave blank to scan the default branch.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold mb-1.5 flex items-center gap-1.5">
                  <FolderGit2 className="h-3.5 w-3.5 text-quiet" />
                  <span>Subdirectory Filter</span>
                </label>
                <input
                  type="text"
                  value={subdir}
                  onChange={(e) => setSubdir(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas font-mono text-foreground outline-none focus:border-cyan-500"
                  placeholder="src/crypto"
                />
                <p className="text-[11px] text-quiet mt-1">
                  Optional. Restricts scanning to a specific path within the repository.
                </p>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold mb-1.5 flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-amber-400" />
                <span>Personal Access Token (private repos)</span>
              </label>
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas font-mono text-foreground outline-none focus:border-cyan-500"
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              />
              <p className="text-[11px] text-quiet mt-1">
                Optional. Required for private repositories. Transmitted in-memory for shallow cloning and strictly never stored in the database.
              </p>
            </div>

            {/* Authorization Checkbox */}
            <div className="pt-2 border-t border-subtle/60">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={isAuthorized}
                  onChange={(e) => setIsAuthorized(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-subtle bg-canvas text-cyan-500 focus:ring-cyan-500 cursor-pointer"
                />
                <span className="text-xs text-foreground font-medium select-none">
                  I confirm I am authorized to scan this repository
                </span>
              </label>
              <p className="text-[11px] text-quiet mt-1 pl-6.5">
                ECDAT strictly enforces authorized discovery boundaries in compliance with security guidelines.
              </p>
            </div>
          </div>
        )}

        <div className="pt-2">
          <button
            type="submit"
            disabled={submitting || !isFormValid}
            className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-2 shadow-sm disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
          >
            {submitting ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                <span>{uploadProgress?.active ? "Processing Upload..." : "Dispatching Job..."}</span>
              </>
            ) : (
              <>
                <span>Submit Scan Job</span>
                <Play className="h-3.5 w-3.5 fill-white" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
