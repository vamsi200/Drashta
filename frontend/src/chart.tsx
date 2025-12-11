import { useMemo, useRef, useEffect, useState } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
} from "recharts";
import { THEME_CONFIG, type ThemeType, type EventData } from "./test";

interface LogCountChartProps {
  logs: EventData[];
  timeRange: number;
  theme?: ThemeType;
}

const THEME_COLORS: Record<ThemeType, string> = {
  emerald: "#10b981",
  white: "#3b82f6",
  black: "#a1a1aa",
};

const textColorMap: Record<ThemeType, string> = {
  emerald: "#4ade80",
  white: "#111827",
  black: "#ffffff",
};

const accentColorMap: Record<ThemeType, string> = {
  emerald: "#059669",
  white: "#3b82f6",
  black: "#a1a1aa",
};

const ONE_MIN = 60 * 1000;
const ONE_HOUR = 60 * ONE_MIN;
const ONE_DAY = 24 * ONE_HOUR;
const ONE_WEEK = 7 * ONE_DAY;

const NICE_BUCKETS = [
  1 * ONE_MIN,
  5 * ONE_MIN,
  15 * ONE_MIN,
  30 * ONE_MIN,
  1 * ONE_HOUR,
  3 * ONE_HOUR,
  6 * ONE_HOUR,
  12 * ONE_HOUR,
  1 * ONE_DAY,
  2 * ONE_DAY,
  1 * ONE_WEEK,
  2 * ONE_WEEK,
  4 * ONE_WEEK,
];

function chooseBucketSize(rangeMs: number, targetCount = 60, maxBuckets = 100): number {
  for (const size of NICE_BUCKETS) {
    if (Math.ceil(rangeMs / size) <= targetCount) return size;
  }
  const rough = Math.ceil(rangeMs / Math.min(targetCount, maxBuckets));
  if (rough <= ONE_HOUR) return ONE_HOUR;
  if (rough <= ONE_DAY) return ONE_DAY;
  if (rough <= ONE_WEEK) return ONE_WEEK;
  const weeks = Math.ceil(rough / ONE_WEEK);
  return weeks * ONE_WEEK;
}

function alignFloor(ts: number, bucket: number): number {
  return Math.floor(ts / bucket) * bucket;
}

function alignCeil(ts: number, bucket: number): number {
  return Math.ceil(ts / bucket) * bucket;
}

const parseTimestamp = (ts: string): number => {
  try {
    const s = ts.trim();

    const iso = s.match(
      /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+\-]\d{2}:?\d{2})?$/
    );
    if (iso) {
      const [, y, m, d, hh, mm, ss, frac, off] = iso;
      const year = parseInt(y, 10);
      const month = parseInt(m, 10) - 1;
      const day = parseInt(d, 10);
      const hours = parseInt(hh, 10);
      const minutes = parseInt(mm, 10);
      const seconds = parseInt(ss, 10);
      const ms = frac ? Math.round(parseInt(frac.padEnd(6, "0").slice(0, 6), 10) / 1000) : 0;

      let offsetMs = 0;
      if (off && off !== "Z") {
        const norm = off.includes(":") ? off : off.slice(0, 3) + ":" + off.slice(3);
        const sign = norm[0] === "+" ? 1 : -1;
        const oh = parseInt(norm.slice(1, 3), 10);
        const om = parseInt(norm.slice(4, 6), 10);
        offsetMs = sign * (oh * 60 + om) * 60 * 1000;
      }
      const utcMs = Date.UTC(year, month, day, hours, minutes, seconds, ms);
      return utcMs - offsetMs;
    }

    const sys = s.match(/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/);
    if (sys) {
      const [, monStr, d2, hh2, mm2, ss2] = sys;
      const monthMap: Record<string, number> = {
        Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
        Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
      };
      const mon = monthMap[monStr];
      if (mon === undefined) return 0;

      const now = new Date();
      const year = now.getFullYear();

      const a = new Date(year, mon, parseInt(d2, 10), parseInt(hh2, 10), parseInt(mm2, 10), parseInt(ss2, 10)).getTime();
      const b = new Date(year - 1, mon, parseInt(d2, 10), parseInt(hh2, 10), parseInt(mm2, 10), parseInt(ss2, 10)).getTime();

      return Math.abs(a - now.getTime()) < Math.abs(b - now.getTime()) ? a : b;
    }

    return 0;
  } catch {
    return 0;
  }
};

export default function LogCountChart({ logs, theme = "emerald" }: LogCountChartProps) {
  const themeClasses = THEME_CONFIG[theme];
  const barColor = THEME_COLORS[theme];
  const textColor = textColorMap[theme];
  const accentColor = accentColorMap[theme];

  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const { width, height } = containerRef.current.getBoundingClientRect();
        setDimensions({ width: Math.floor(width), height: Math.floor(height) });
      }
    };

    updateDimensions();
    const resizeObserver = new ResizeObserver(updateDimensions);
    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }

    return () => resizeObserver.disconnect();
  }, []);

  const { chartData, stats } = useMemo(() => {
    if (logs.length === 0) return { chartData: [], stats: null };

    const times = logs.map(l => parseTimestamp(l.timestamp)).filter(t => t > 0);
    if (times.length === 0) return { chartData: [], stats: null };

    times.sort((a, b) => a - b);
    const rawMin = times[0];
    const rawMax = times[times.length - 1];

    if (rawMax === rawMin) {
      return {
        chartData: [{
          time: rawMin,
          count: times.length,
          label: new Date(rawMin).toLocaleDateString("en-US", { month: "short", day: "numeric" })
        }],
        stats: { total: logs.length, min: rawMin, max: rawMax }
      };
    }

    const rangeMs = rawMax - rawMin;
    const bucketSize = chooseBucketSize(rangeMs, 60, 100);
    const start = alignFloor(rawMin, bucketSize);
    const end = alignCeil(rawMax, bucketSize);
    const bucketCount = Math.max(1, Math.floor((end - start) / bucketSize) + 1);

    const buckets = new Array<number>(bucketCount).fill(0);
    for (const t of times) {
      const idx = Math.floor((t - start) / bucketSize);
      if (idx >= 0 && idx < bucketCount) buckets[idx]++;
    }

    const days = rangeMs / ONE_DAY;
    const data = buckets.map((count, i) => {
      const bucketTime = start + i * bucketSize;
      const d = new Date(bucketTime);
      let label = "";

      if (days < 1) {
        label = d.toLocaleString("en-US", { hour: "numeric", minute: "2-digit" });
      } else if (days < 90) {
        label = d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
      } else {
        label = d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "2-digit" });
      }

      return {
        time: bucketTime,
        count,
        label,
        index: i,
      };
    });

    return {
      chartData: data,
      stats: { total: logs.length, min: rawMin, max: rawMax }
    };
  }, [logs]);

  if (logs.length === 0) {
    return (
      <div className={`w-full h-full flex items-center justify-center ${themeClasses.bg} rounded-lg border ${themeClasses.border}`}>
        <div className="text-center">
          <p className={`${themeClasses.accent} text-sm`}>No data to display</p>
          <p className={`${themeClasses.accent} text-xs mt-1 opacity-50`}>Logs will appear here when available</p>
        </div>
      </div>
    );
  }

  if (chartData.length === 0) {
    return (
      <div className={`w-full h-full flex items-center justify-center ${themeClasses.bg} rounded-lg border ${themeClasses.border}`}>
        <div className="text-center">
          <p className={`${themeClasses.accent} text-sm`}>Unable to parse timestamps</p>
          <p className={`${themeClasses.accent} text-xs mt-1 opacity-50`}>{logs.length} logs with invalid timestamps</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`w-full h-full ${themeClasses.bg} rounded-lg border ${themeClasses.border} overflow-hidden`}>
      <div className="p-3 pb-2 border-b" style={{ borderColor: accentColor, opacity: 1 }}>
        <p className={`text-xs ${themeClasses.accent} mt-0.5`}>
          {stats?.total.toLocaleString()} logs • {chartData.length} periods
        </p>
      </div>

      <div
        ref={containerRef}
        className="w-full"
        style={{
          height: 'calc(100% - 10px)',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        {dimensions.width > 0 && dimensions.height > 0 && (
          <BarChart
            width={dimensions.width}
            height={dimensions.height}
            data={chartData}
            margin={{ top: 15, right: 15, left: 0, bottom: 45 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={accentColor}
              vertical={false}
              opacity={0.5}
            />
            <XAxis
              dataKey="label"
              stroke={accentColor}
              tick={{ fill: textColor, fontSize: 10 }}
              tickLine={{ stroke: accentColor, opacity: 0.3 }}
              axisLine={{ stroke: accentColor, opacity: 0.4 }}
              angle={-40}
              textAnchor="end"
              height={30}
              interval="preserveStartEnd"
            />
            <YAxis
              stroke={accentColor}
              tick={{ fill: textColor, fontSize: 10 }}
              tickLine={{ stroke: accentColor, opacity: 0.3 }}
              axisLine={{ stroke: accentColor, opacity: 0.4 }}
              width={30}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: theme === "white" ? "#ffffff" : "#1a1a1a",
                border: `1px solid ${accentColor}`,
                borderRadius: 6,
                padding: "8px 12px",
              }}
              labelStyle={{ color: textColor, fontSize: 11, fontWeight: 600 }}
              itemStyle={{ color: barColor, fontSize: 10 }}
              cursor={{ fill: barColor, opacity: 0.1 }}
              formatter={(value: any) => [`${value} logs`, ""]}
            />
            <Bar
              dataKey="count"
              fill={barColor}
              radius={[4, 4, 0, 0]}
              isAnimationActive={false}
            />
          </BarChart>
        )}
      </div>
    </div>
  );
}
