"use client";

import { useState } from "react";
import Link from "next/link";
import { ShieldCheck, Mail, ArrowLeft, CheckCircle2 } from "lucide-react";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email) setSubmitted(true);
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
            <h1 className="text-2xl font-bold tracking-tight text-foreground">Reset Password</h1>
            <p className="text-sm text-quiet mt-1.5">
              Enter your enterprise email to receive recovery instructions.
            </p>
          </div>

          {submitted ? (
            <div className="text-center py-4 space-y-4">
              <div className="h-12 w-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mx-auto">
                <CheckCircle2 className="h-6 w-6" />
              </div>
              <p className="text-sm text-foreground">
                If an enterprise account exists for <span className="font-semibold text-cyan-400">{email}</span>, security recovery instructions have been dispatched.
              </p>
              <Link
                href="/login"
                className="inline-flex items-center gap-2 text-sm text-cyan-400 hover:underline font-medium pt-2"
              >
                <ArrowLeft className="h-4 w-4" />
                Return to Login
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
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

              <button
                type="submit"
                className="w-full py-2.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors"
              >
                Send Recovery Instructions
              </button>

              <div className="pt-2 text-center">
                <Link
                  href="/login"
                  className="inline-flex items-center gap-1.5 text-xs text-quiet hover:text-foreground"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  Back to Sign In
                </Link>
              </div>
            </form>
          )}
        </div>
      </main>

      <footer className="text-center text-xs text-quiet py-4">
        ECDAT V4 · Security Assurance
      </footer>
    </div>
  );
}
