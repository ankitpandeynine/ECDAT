"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ShieldCheck, Lock, Mail, ArrowRight, AlertCircle, Sparkles } from "lucide-react";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@ecdat.local");
  const [password, setPassword] = useState("admin123");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Authentication failed");
      }

      // Save token and user in localStorage
      localStorage.setItem("ecdat_token", data.token);
      localStorage.setItem("ecdat_user", JSON.stringify(data));
      router.push("/dashboard");
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const fillDemoAdmin = () => {
    setEmail("admin@ecdat.local");
    setPassword("admin123");
  };

  return (
    <div className="min-h-screen bg-canvas flex flex-col justify-between p-4 sm:p-6 lg:p-8">
      <header className="flex items-center justify-between max-w-6xl w-full mx-auto">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="h-9 w-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <span className="font-semibold text-lg text-foreground tracking-tight">ECDAT <span className="text-xs font-mono text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">V4</span></span>
        </Link>
        <ThemeToggle />
      </header>

      <main className="w-full max-w-md mx-auto my-auto py-8">
        <div className="rounded-xl border border-subtle bg-surface p-6 sm:p-8 shadow-xl">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">Sign In to ECDAT</h1>
            <p className="text-sm text-quiet mt-1.5">
              Enterprise Cryptographic Discovery & Agility Platform
            </p>
          </div>

          {error && (
            <div className="mb-5 p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs flex items-start gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1.5">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-quiet" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-subtle bg-canvas text-foreground placeholder:text-quiet outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  placeholder="analyst@enterprise.com"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-medium text-foreground">Password</label>
                <Link href="/forgot-password" className="text-xs text-cyan-400 hover:underline">
                  Forgot?
                </Link>
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 h-4 w-4 text-quiet" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-subtle bg-canvas text-foreground placeholder:text-quiet outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
            >
              {loading ? "Authenticating..." : "Sign In to Command Center"}
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          <div className="mt-5 pt-5 border-t border-subtle">
            <button
              type="button"
              onClick={fillDemoAdmin}
              className="w-full py-2 px-3 rounded-lg border border-subtle hover:border-cyan-500/40 bg-surface text-xs text-quiet hover:text-foreground flex items-center justify-center gap-2 transition-colors"
            >
              <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
              Quick Fill Administrator Credentials (admin123)
            </button>
          </div>

          <div className="mt-5 text-center text-xs text-quiet">
            Need an enterprise account?{" "}
            <Link href="/register" className="text-cyan-400 hover:underline font-medium">
              Register now
            </Link>
          </div>
        </div>
      </main>

      <footer className="text-center text-xs text-quiet py-4">
        ECDAT V4 · Zero-Fabrication Cryptographic Intelligence
      </footer>
    </div>
  );
}
