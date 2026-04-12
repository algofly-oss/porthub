import { MdComputer, MdCloudDone, MdCloudOff } from "react-icons/md";

export default function InfoCard({ stats }) {
  const metricRows = [
    {
      key: "registered",
      label: "Registered",
      value: stats?.registered ?? 0,
      icon: MdComputer,
      valueClassName: "text-zinc-900 dark:text-zinc-100",
    },
    {
      key: "online",
      label: "Online",
      value: stats?.online ?? 0,
      icon: MdCloudDone,
      valueClassName: "text-emerald-600 dark:text-emerald-400",
    },
    {
      key: "offline",
      label: "Offline",
      value: stats?.offline ?? 0,
      icon: MdCloudOff,
      valueClassName: "text-red-600 dark:text-red-400",
    },
  ];

  return (
    <div className="rounded-lg bg-zinc-200 p-4 text-sm dark:bg-zinc-900">
      <p className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500 dark:text-zinc-400">
        Machine Summary
      </p>
      <div className="space-y-3">
        {metricRows.map((row) => {
          const Icon = row.icon;

          return (
            <div key={row.key} className="flex items-center justify-between gap-3">
              <div className="flex items-center space-x-2 text-zinc-600 dark:text-zinc-300">
                <Icon size={18} />
                <p>{row.label}</p>
              </div>
              <p className={`font-semibold ${row.valueClassName}`}>{row.value}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
