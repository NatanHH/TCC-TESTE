"use client";
import React from "react";

type Props =
  | {
      getText: () => string | null | undefined;
      fallback?: string;
      children?: never;
    }
  | { children: React.ReactNode; getText?: never; fallback?: never };

/**
 * Cliente-only helper:
 * - Quando usado com `getText`, executa a função diretamente (com try/catch).
 * - Quando usado com `children`, apenas renderiza os filhos.
 *
 * Removemos o useEffect/useState para evitar o aviso "Calling setState synchronously within an effect".
 */
export default function ClientOnlyText(props: Props) {
  if ("getText" in props) {
    const { getText, fallback = "—" } = props;
    try {
      const val = getText?.() ?? fallback;
      // Defensive: ensure we never return a raw plain object as a React child.
      // If getText unexpectedly returned an object, coerce it to a safe string.
      if (React.isValidElement(val)) return <>{val}</>;
      if (val === null || val === undefined) return <>{fallback}</>;
      if (typeof val === "object") {
        try {
          return <>{JSON.stringify(val)}</>;
        } catch {
          return <>{String(val)}</>;
        }
      }
      return <>{String(val)}</>;
    } catch {
      return <>{fallback}</>;
    }
  }

  return <>{props.children}</>;
}
