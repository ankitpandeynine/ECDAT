import Link from "next/link";
import {
  ArrowUpRight,
  ArrowRight,
  ShieldCheck,
  Globe2,
  Code2,
  Binary,
  Fingerprint,
  Check,
  Layers3,
  Route,
  LockKeyhole,
} from "lucide-react";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";
const capabilities = [
  {
    icon: Globe2,
    tag: "01 / NETWORK",
    title: "See the connection.",
    text: "Inspect live TLS, certificates and public deployment clues. Know what was measured and what remains unknown.",
  },
  {
    icon: Code2,
    tag: "02 / SOURCE CODE",
    title: "Find the weak links.",
    text: "Trace cryptographic usage to files and lines. Review dependencies and understand exactly which files were checked.",
  },
  {
    icon: Binary,
    tag: "03 / BINARY & FIRMWARE",
    title: "Look inside the build.",
    text: "Find algorithm signatures and embedded key material in compiled files, firmware and bounded ZIP archives.",
  },
];
export default function Home() {
  return (
    <div className="landing">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="landing-nav">
        <Link href="/" className="brand">
          <span className="brand-icon">
            <ShieldCheck size={23} />
          </span>
          <span>
            ECDAT<small>DISCOVERY & MIGRATION</small>
          </span>
        </Link>
        <nav aria-label="Main navigation">
          <a href="#platform">Platform</a>
          <a href="#workflow">How it works</a>
          <a href="#migration">Migration</a>
        </nav>
        <div className="button-row">
          <ThemeToggle />
          <Link href="/dashboard" className="ec-button">
            Open dashboard <ArrowUpRight size={16} />
          </Link>
        </div>
      </header>
      <main id="main">
        <section className="hero grid-texture">
          <div className="hero-copy">
            <p className="eyebrow">
              <span className="status-dot" /> KNOW YOUR SYSTEM. PLAN YOUR NEXT
              MOVE.
            </p>
            <h1>
              Clarity before
              <br />
              you <span>change.</span>
            </h1>
            <p className="hero-description">
              Discover cryptography across your websites, code, and binaries.
              Turn real evidence into a practical plan for stronger security and
              your next hosting move.
            </p>
            <div className="button-row">
              <Link href="/dashboard" className="ec-button large">
                Open dashboard <ArrowRight size={18} />
              </Link>
              <a href="#workflow" className="ec-button secondary large">
                Explore the workflow
              </a>
            </div>
            <p className="hero-note">
              <Check size={14} /> Three scan types <span>·</span> Saved evidence{" "}
              <span>·</span> Clear next steps
            </p>
          </div>
          <div className="system-visual-wrap" aria-hidden="true">
            <span className="visual-orb visual-orb-one" />
            <span className="visual-orb visual-orb-two" />
          </div>
          <div className="system-visual" aria-label="Discovery workflow: websites and TLS, source and binaries, then a migration plan">
            <span className="visual-sheen" aria-hidden="true" />
            <div className="visual-top">
              <Fingerprint size={18} />
              <span>YOUR SYSTEM, MADE VISIBLE</span>
              <span className="status-dot" />
            </div>
            <div className="visual-heading">
              <span>Discovery</span>
              <ArrowRight size={23} />
              <span>Decision</span>
            </div>
            <div className="discovery-node node-one">
              <div className="node-icon">
                <Globe2 />
              </div>
              <div>
                <strong>Website & TLS</strong>
                <small>Connection · certificate · hosting clues</small>
              </div>
              <span className="node-number">01</span>
            </div>
            <div className="connector-line" />
            <div className="discovery-node node-two">
              <div className="node-icon">
                <Layers3 />
              </div>
              <div>
                <strong>Source & binaries</strong>
                <small>Algorithms · dependencies · evidence</small>
              </div>
              <span className="node-number">02</span>
            </div>
            <div className="connector-line" />
            <div className="discovery-node highlight node-plan">
              <div className="node-icon">
                <Route />
              </div>
              <div>
                <strong>Your migration plan</strong>
                <small>Priorities · effort · cutover · rollback</small>
              </div>
              <ArrowUpRight size={20} />
            </div>
            <p className="visual-caption">
              Product workflow illustration • no sample telemetry
            </p>
          </div>
        </section>
        <div className="platform-strip">
          <span>BUILT FOR THE WORK BETWEEN</span>
          <strong>Security review</strong>
          <span>/</span>
          <strong>Engineering</strong>
          <span>/</span>
          <strong>Infrastructure change</strong>
        </div>
        <section id="platform" className="landing-section">
          <p className="eyebrow">FROM DISCOVERY TO A DECISION</p>
          <div className="section-heading">
            <h2>
              One workspace.
              <br />
              Three ways to look deeper.
            </h2>
            <p>
              A clean starting point for understanding your cryptographic
              footprint. Each result carries evidence, coverage, and
              limitations.
            </p>
          </div>
          <div className="capability-grid">
            {capabilities.map(({ icon: Icon, tag, title, text }) => (
              <article key={tag} className="capability-card">
                <div className="capability-top">
                  <Icon size={24} />
                  <span>{tag}</span>
                </div>
                <h3>{title}</h3>
                <p>{text}</p>
                <Link
                  href={`/dashboard#${tag.includes("NETWORK") ? "network" : tag.includes("SOURCE") ? "code" : "binary"}`}
                >
                  Start discovery <ArrowUpRight size={16} />
                </Link>
              </article>
            ))}
          </div>
        </section>
        <section id="workflow" className="landing-section workflow-section">
          <p className="eyebrow">A SIMPLE WAY TO START</p>
          <h2>Less noise. A clearer next step.</h2>
          <div className="workflow-grid">
            {[
              [
                "01",
                "Run a scan",
                "Choose a website, source files or a binary you are authorized to inspect.",
              ],
              [
                "02",
                "Review the evidence",
                "Inspect findings, confidence and skipped checks. Save a CycloneDX report.",
              ],
              [
                "03",
                "Build your plan",
                "Add hosting and traffic context. Get a draft roadmap with assumptions you can review.",
              ],
            ].map(([n, t, d]) => (
              <article key={n}>
                <span className="step-number">{n}</span>
                <h3>{t}</h3>
                <p>{d}</p>
              </article>
            ))}
          </div>
        </section>
        <section id="migration" className="landing-section">
          <div className="migration-callout">
            <div>
              <p className="eyebrow">SECURITY + INFRASTRUCTURE</p>
              <h2>
                Your next move,
                <br />
                with a plan.
              </h2>
              <p>
                Upgrade cryptography and migrate hosting in one roadmap.
                Understand prerequisites, effort ranges, validation, and the way
                back.
              </p>
              <Link href="/dashboard#migration" className="ec-button">
                Build a migration plan <ArrowRight size={16} />
              </Link>
            </div>
            <div className="plan-promises">
              {[
                [
                  LockKeyhole,
                  "Cryptographic upgrades",
                  "Prioritize findings and test compatibility before rollout.",
                ],
                [
                  Route,
                  "Hosting migration",
                  "Rebuild, move data, cut over, and rehearse rollback.",
                ],
                [
                  Fingerprint,
                  "Evidence you can inspect",
                  "Traffic comes from your analytics. Unknowns stay visible.",
                ],
              ].map(([Icon, title, desc]) => {
                const I = Icon as typeof Route;
                return (
                  <div key={String(title)}>
                    <I size={22} />
                    <span>
                      <strong>{String(title)}</strong>
                      <small>{String(desc)}</small>
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      </main>
      <footer className="landing-footer">
        <Link href="/" className="brand">
          <ShieldCheck size={20} /> ECDAT
        </Link>
        <p>Measured evidence. Visible limitations. Actionable next steps.</p>
        <Link href="/dashboard">
          Open workspace <ArrowUpRight size={14} />
        </Link>
      </footer>
    </div>
  );
}
