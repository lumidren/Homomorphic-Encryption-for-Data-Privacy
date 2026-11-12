/**
 * Minimal, dependency-free SVG bar chart. Charting libraries cost ~100 kB of JavaScript; this
 * costs nothing and is accessible: the SVG is labelled, and a visually hidden table carries the
 * exact numbers for screen readers.
 */
export interface Datum {
  label: string;
  value: number;
}

export function BarChart({ data, title, unit = "", height = 160 }: { data: Datum[]; title: string; unit?: string; height?: number }) {
  if (data.length === 0) return <p className="text-sm text-fg-muted">No data for this period.</p>;
  const max = Math.max(...data.map((d) => d.value), 1);
  const barWidth = 100 / data.length;
  return (
    <figure>
      <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" role="img" aria-label={`${title}: bar chart`} className="h-40 w-full">
        {data.map((d, i) => {
          const h = (d.value / max) * (height - 4);
          return (
            <rect key={d.label} x={i * barWidth + barWidth * 0.15} y={height - h} width={barWidth * 0.7} height={h} rx={0.8} className="fill-primary">
              <title>{`${d.label}: ${d.value}${unit}`}</title>
            </rect>
          );
        })}
      </svg>
      <figcaption className="mt-1 flex justify-between text-xs text-fg-muted" aria-hidden="true">
        <span>{data[0]?.label}</span>
        <span>{data[data.length - 1]?.label}</span>
      </figcaption>
      <table className="sr-only">
        <caption>{title}</caption>
        <thead>
          <tr>
            <th scope="col">Label</th>
            <th scope="col">Value</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d) => (
            <tr key={d.label}>
              <td>{d.label}</td>
              <td>{`${d.value}${unit}`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
