"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { getBillingStatus, type BillingStatus } from "@/lib/api";

export type BillingGateState =
  | { kind: "loading" }
  | { kind: "error"; refresh: () => void }
  | { kind: "ready"; billing: BillingStatus };

interface BillingContextValue {
  state: BillingGateState;
  refresh: () => void;
}

const BillingContext = createContext<BillingContextValue>({
  state: { kind: "loading" },
  refresh: () => undefined,
});

export function BillingProvider({ children }: { children: ReactNode }) {
  const [billing, setBilling] = useState<BillingStatus | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchStatus = useCallback(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getBillingStatus()
      .then((data) => {
        if (!cancelled) setBilling(data);
      })
      .catch(() => {
        if (!cancelled) {
          setBilling(null);
          setError(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const cancel = fetchStatus();
    return cancel;
  }, [fetchStatus]);

  const refresh = useCallback(() => {
    fetchStatus();
  }, [fetchStatus]);

  const state: BillingGateState = loading
    ? { kind: "loading" }
    : error
      ? { kind: "error", refresh }
      : { kind: "ready", billing: billing! };

  return (
    <BillingContext.Provider value={{ state, refresh }}>
      {children}
    </BillingContext.Provider>
  );
}

export function useBilling() {
  return useContext(BillingContext);
}

export function formatPlanDate(iso: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return new Intl.DateTimeFormat("es", {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(date);
}

export function daysUntil(iso: string | null): number | null {
  if (!iso) return null;
  const diff = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(diff)) return null;
  return Math.max(0, Math.ceil(diff / 86_400_000));
}
