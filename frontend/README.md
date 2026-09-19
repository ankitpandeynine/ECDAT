# ECDAT Frontend — Cryptographic Discovery & Post-Quantum Governance Console

Enterprise web console for the **Enterprise Cryptographic Discovery and Analysis Tool (ECDAT)**, built with Next.js 16.3, React 19, and Tailwind CSS. Provides an obsidian-themed, military-grade cybersecurity command interface for multi-surface cryptographic discovery, NIST post-quantum migration planning, autonomous remediation loops, and closed-loop verification.

[![Next.js](https://img.shields.io/badge/Next.js-16.3%20(App%20Router)-black?logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.0-blue?logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-v4-06B6D4?logo=tailwindcss)](https://tailwindcss.com/)

---

## 1. Architectural Highlights

- **Obsidian Command Design System**: Tailored dark-mode palette (`hsl(222.2, 84%, 4.9%)`) with high-contrast emerald (`#10b981`), cyan (`#06b6d4`), amber (`#f59e0b`), and rose (`#f43f5e`) semantic accents.
- **Enterprise Left Navigation Shell**: Dedicated unified workspace view at `/projects/[projectId]` with persistent telemetry, project switcher, fast tab navigation, and live system status indicators.
- **Autonomous Custom Remediation Loop**: Integrated one-click pipeline controller (`CustomLoopPanel`) orchestrating multi-stage scan, CBOM generation, AST patch creation, isolated test harness execution, and closed-loop verification.
- **Dedicated Before & After Changes Hub**: Standalone interactive diff page (`/projects/[projectId]/changes` and `/changes`) featuring synchronized side-by-side code diffs, vulnerability delta cards, regression test terminal output, and direct `.patch` download.
- **Deep Technical Governance Panels**:
  - **Closed-Loop Verification Engine**: Formal mathematical proof showing cryptographic asset transitions, retired weaknesses, and zero introduced regressions.
  - **Regulatory Standards Mandate Matrix**: Complete compliance mapping for NSA CNSA 2.0, NIST FIPS 203/204/205, BSI TR-02102, and PCI-DSS 4.0.
  - **Fault-Tolerant Quantum Estimator**: Interactive Shor's algorithm simulator with dynamic sliders for physical error rates, surface code distance, and cycle times.
  - **Runtime & eBPF Telemetry**: Real-time process tracking, OpenSSL `libcrypto.so` hook inspection, and active connection monitoring.
  - **Binary ML & Passive PCAP**: Byte entropy heatmaps, opcode frequency vectors, and JA3/JA4 passive handshake dissecting.
- **Zero Mock / Zero Fake Data**: Every table, graph, diff, and verification result binds directly to the live Python backend via typed REST endpoints and reverse proxy routes.

---

## 2. Directory Structure

```
frontend/
├── src/
│   ├── app/                                    # Next.js App Router root
│   │   ├── layout.tsx                          # Root layout with fonts, metadata & theme provider
│   │   ├── page.tsx                            # Landing / root redirection
│   │   ├── globals.css                         # Custom theme variables, scrollbars & animations
│   │   ├── api/
│   │   │   └── [...path]/route.ts              # Reverse proxy forwarding /api/* to FastAPI backend
│   │   ├── projects/
│   │   │   └── [projectId]/
│   │   │       ├── page.tsx                    # Primary Left Enterprise Workspace Shell
│   │   │       └── changes/
│   │   │           └── page.tsx                # Dedicated Before & After Changes Page
│   │   ├── changes/
│   │   │   └── page.tsx                        # Global redirect / fallback changes route
│   │   ├── dashboard/
│   │   │   └── page.tsx                        # Redirects to /projects/default
│   │   ├── login/page.tsx                      # Enterprise authentication (RBAC)
│   │   ├── register/page.tsx                   # User registration
│   │   └── forgot-password/page.tsx            # Password recovery flow
│   │
│   ├── components/
│   │   ├── ecdat/                              # Domain-specific cybersecurity components
│   │   │   ├── project-shell.tsx               # Enterprise sidebar, header & tab controller
│   │   │   ├── overview.tsx                    # Posture score, asset cards & CBOM download
│   │   │   ├── custom-loop-panel.tsx           # Autonomous 1-click remediation pipeline UI
│   │   │   ├── verification-panel.tsx          # Closed-loop verification & delta proof
│   │   │   ├── standards-panel.tsx             # Compliance matrix (NIST, CNSA, BSI, PCI)
│   │   │   ├── experimental-hub.tsx            # Quantum Estimator, AutoPatch, eBPF, Binary ML & PCAP
│   │   │   ├── sih-demo-panel.tsx              # Smart India Hackathon live execution scenario
│   │   │   ├── feature-scan-history.tsx        # Temporal scan timeline & snapshot management
│   │   │   ├── evidence-panels.tsx             # Asset tables, drill-down modals & blast radius graph
│   │   │   ├── migration-planner.tsx           # PQC transition timelines & work breakdown
│   │   │   └── theme-toggle.tsx                # System / dark mode toggle
│   │   │
│   │   └── ui/                                 # Accessible base components (Radix + Tailwind)
│   │       ├── alert.tsx                       # Status & warning callouts
│   │       ├── badge.tsx                       # Risk, confidence & protocol badges
│   │       ├── button.tsx                      # Primary, ghost, outline & destructive buttons
│   │       ├── card.tsx                        # Structural panel containers
│   │       ├── dialog.tsx                      # Accessible modal dialogs
│   │       ├── slider.tsx                      # Multi-touch range slider for quantum parameters
│   │       ├── table.tsx                       # Responsive evidence and asset data tables
│   │       ├── tabs.tsx                        # Accessible tab headers and panels
│   │       └── ...                             # Select, sheet, separator, skeleton, tooltip
│   │
│   └── lib/
│       ├── api.ts                              # Strongly typed API client & endpoint contracts
│       ├── migration.ts                        # Algorithm deprecation rules & PQC replacement maps
│       └── utils.ts                            # ClassName merger (clsx + tailwind-merge)
│
├── public/                                     # Static assets & icons
├── next.config.ts                              # Next.js compilation & proxy configuration
├── tailwind.config.ts / globals.css            # Styling and theme token definitions
├── tsconfig.json                               # Strict TypeScript configuration
└── package.json                                # Dependencies and npm scripts
```

---

## 3. Primary Views & Navigation

### 1. Enterprise Workspace (`/projects/[projectId]`)
The core interface combines a multi-panel telemetry overview with instant access to deep inspection modules:
- **Left Command Sidebar**: Fast switching across all tools:
  - `overview`: Executive posture score, total cryptographic assets, classical vs. PQC breakdown, and CycloneDX 1.6 CBOM export.
  - `custom-loop`: Autonomous single-click remediation loop for source code and compiled binaries.
  - `verify`: Closed-loop verification engine displaying mathematical pre/post asset deltas and regression outcomes.
  - `standards`: Real-time compliance matrix against NSA CNSA 2.0, NIST FIPS 203/204/205, BSI TR-02102, and PCI-DSS 4.0.
  - `quantum-estimator`: Interactive surface-code Shor's algorithm resource simulator.
  - `autopatch`: AST-level cryptographic patch generator with safe replacements.
  - `runtime`: eBPF and dynamic instrumentation telemetry monitoring active cryptographic calls.
  - `binary-pcap`: Combined deep binary ML classification (entropy, byte histograms) and passive PCAP dissection (JA3/JA4, post-quantum key shares).
  - `sih-demo`: One-click deterministic NTRO / SIH scenario runner.
- **Header Telemetry**: Real-time project switcher (`default`, `enterprise-core`, `legacy-gateway`), live API status pill, and direct link to the Changes Hub.

### 2. Autonomous Custom Remediation Loop (`custom-loop`)
Orchestrates the entire remediation life cycle without requiring fragmented manual steps:
1. **Target Selection**: Choose between Python Source (`vulnerable_sample.py`), C / OpenSSL (`crypto_sample.c`), or Compiled Binary (`crypto_test_bin`).
2. **One-Click Execution**: Triggers `POST /api/custom-loop/run`.
3. **Real-Time Step Progression**:
   - `[1/4] Discovery Scan`: Generates raw `EvidenceRecord` list.
   - `[2/4] CBOM Generation`: Formulates CycloneDX 1.6 compliant bill of materials.
   - `[3/4] Patch Creation`: Produces non-destructive AST modifications (e.g. `MD5` $\rightarrow$ `SHA-256`, `DES` $\rightarrow$ `AES-256-GCM`).
   - `[4/4] Verification & Regression`: Executes test harness in an isolated environment and confirms elimination of vulnerable assets.
4. **Instant Link to Changes Hub**: Direct button navigates to the side-by-side Before & After inspection view.

### 3. Dedicated Before & After Changes Hub (`/projects/[projectId]/changes`)
An interactive, side-by-side code review and audit environment:
- **Security Posture Improvement Cards**:
  - **Active Vulnerabilities**: Displays drop (e.g. $2 \rightarrow 0$).
  - **Security Posture Score**: Displays improvement (e.g. $28\% \rightarrow 98\%$).
  - **Quantum Risk Deficit**: Displays eliminated exposure (e.g. $4\text{y} \rightarrow 0\text{y}$).
- **Split Code Diff Viewer**: Synchronized, dual-pane view showing Original Source (red gutter) alongside Remediated Source (emerald gutter) with exact line number alignment.
- **Audit Tabs**:
  - **Code Changes**: Full syntax diff.
  - **Test Suite Logs**: Exact terminal output from isolated regression test runner (`PASSED (3/3 tests)`).
  - **Verification Evidence**: Tabular delta showing retired primitives, replaced primitives, and zero added weaknesses.
- **Export Capabilities**: One-click **"Download .patch"** button (generates unified diff file) and **"Copy Diff"** button.

---

## 4. Setup & Local Development

### Prerequisites
- **Node.js**: `v20.x` or `v22.x` (LTS recommended)
- **npm**: `v10.x` or higher
- **ECDAT Backend**: Running on `http://localhost:8000` (see `backend/README.md`)

### Installation
From the `frontend/` directory:

```bash
# Install dependencies
npm install
```

### Environment Configuration
Create a `.env.local` file (or use `.env.example`):

```env
# Backend API Base URL
NEXT_PUBLIC_API_URL=http://localhost:8000

# Next.js Application Port (default: 3000)
PORT=3000
```

### Starting the Development Server
```bash
npm run dev
```
The application will be accessible at:
- **Primary Workspace**: `http://localhost:3000/projects/default`
- **Changes Hub**: `http://localhost:3000/projects/default/changes`
- **API Health Proxy**: `http://localhost:3000/api/health`

### Production Build
To validate TypeScript types, bundling, and build artifacts:

```bash
# Compile and package for production
npm run build

# Start the optimized production server
npm start
```

---

## 5. API Proxy & Backend Integration

The frontend uses Next.js Route Handlers (`src/app/api/[...path]/route.ts`) to provide seamless proxying to the FastAPI backend:
- Prevents cross-origin (CORS) complications during local and containerized deployments.
- Automatically handles stream responses, JSON payloads, and binary downloads (`.cbom.json`, `.patch`).
- Configurable via `NEXT_PUBLIC_API_URL` environment variable.

All frontend components call standardized functions in `src/lib/api.ts`:
- `api.getProject(id)` $\rightarrow$ Project metadata, inventory, and status.
- `api.runCustomLoop(target, targetType)` $\rightarrow$ Executes the autonomous scan-to-verify pipeline.
- `api.getCustomLoopLatest()` $\rightarrow$ Fetches the most recent remediation diff and verification report.
- `api.verifyPatch(id)` $\rightarrow$ Requests closed-loop differential verification.
- `api.estimateQuantum(params)` $\rightarrow$ Simulates physical qubit requirements via Shor's algorithm.

---

## 6. Testing & Quality Assurance

- **Type Safety**: Fully typed TypeScript codebase with zero loose `any` declarations in critical data models.
- **Next.js Production Build Validation**: Verified with zero compilation or lint errors:
  ```bash
  npm run build
  ```
- **Responsive Layout**: Tested across high-resolution displays ($1920\times1080$, $2560\times1440$) and tablet viewports down to 768px.
