const SEVERITY_CLASS: Record<string, string> = {
  critical: "badge badge-critical",
  high: "badge badge-high",
  medium: "badge badge-medium",
  low: "badge badge-low",
  info: "badge badge-low",
};

const STATUS_CLASS: Record<string, string> = {
  open: "badge badge-high",
  in_progress: "badge badge-medium",
  new: "badge badge-high",
  acknowledged: "badge badge-medium",
  resolved: "badge badge-success",
  closed: "badge badge-success",
  false_positive: "badge badge-neutral",
  completed: "badge badge-success",
  failed: "badge badge-critical",
  running: "badge badge-medium",
  pending: "badge badge-medium",
  simulated: "badge badge-neutral",
  executed: "badge badge-success",
  sent: "badge badge-success",
};

export function SeverityBadge({ value }: { value: string }) {
  return <span className={SEVERITY_CLASS[value] ?? "badge badge-neutral"}>{value}</span>;
}

export function StatusBadge({ value }: { value: string }) {
  return <span className={STATUS_CLASS[value] ?? "badge badge-neutral"}>{value}</span>;
}
