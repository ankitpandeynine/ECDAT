import React, { ReactNode } from "react";
import Link from "next/link";
import { ArrowRight } from "lucide-react";

export interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  actionHref?: string;
  onAction?: () => void;
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  actionLabel,
  actionHref,
  onAction,
  className = "",
}: EmptyStateProps) {
  return (
    <div className={`rounded-xl border border-dashed border-subtle bg-surface/40 p-8 sm:p-12 text-center space-y-4 ${className}`}>
      {icon && (
        <div className="h-12 w-12 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto">
          {icon}
        </div>
      )}
      <div className="space-y-1">
        <h3 className="text-sm sm:text-base font-bold text-foreground tracking-tight uppercase">
          {title}
        </h3>
        <p className="text-xs text-quiet max-w-md mx-auto leading-relaxed">
          {description}
        </p>
      </div>
      {actionLabel && (
        <div className="pt-2 flex justify-center">
          {actionHref ? (
            <Link
              href={actionHref}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold inline-flex items-center gap-2 shadow-sm transition-colors"
            >
              {actionLabel}
              <ArrowRight size={14} />
            </Link>
          ) : onAction ? (
            <button
              onClick={onAction}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold inline-flex items-center gap-2 shadow-sm transition-colors"
            >
              {actionLabel}
              <ArrowRight size={14} />
            </button>
          ) : null}
        </div>
      )}
    </div>
  );
}
