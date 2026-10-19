import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function compact(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + "G";
  if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return Math.round(n).toString();
}

export function fmtBps(bps: number): string {
  const bits = bps * 8;
  if (bits >= 1e9) return (bits / 1e9).toFixed(2) + " Gbps";
  if (bits >= 1e6) return (bits / 1e6).toFixed(1) + " Mbps";
  if (bits >= 1e3) return (bits / 1e3).toFixed(0) + " kbps";
  return Math.round(bits) + " bps";
}

// A duration with the unit that keeps it readable: 3.1 ms, 0.76 s, 12.4 s.
export function fmtDuration(seconds: number): string {
  if (seconds < 0.1) return `${(seconds * 1000).toFixed(seconds < 0.01 ? 1 : 0)} ms`;
  return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
}
