import { useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { THEME_CONFIG, type ThemeType } from "./test";

type EventData = {
  timestamp: string;
  service: string;
  event_type: string;
  data: Record<string, string>;
  raw_msg: any;
};

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

const ParseTimeStamp = (timestamp: string, logIndex: number = 0): number => {
  const now = new Date();
  const currentYear = now.getFullYear();

  try {
    const parts = timestamp.trim().match(/^(\w{3})\s+([ \d]{1,2})\s+(\d{2}:\d{2}:\d{2})$/);
    if (!parts) {
      return 0;
    }

    const [, monthStr, dayStrRaw, timeStr] = parts;
    const dayStr = dayStrRaw.trim();
    const day = parseInt(dayStr, 10);

    if (isNaN(day) || day < 1 || day > 31) {
      return 0;
    }

    const monthMap: Record<string, number> = {
      Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
      Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
    };
    const month = monthMap[monthStr as keyof typeof monthMap];
    if (month === undefined) {
      return 0;
    }

    const timeParts = timeStr.split(":").map(Number);
    const [hours, minutes, seconds] = timeParts;
    if (timeParts.length !== 3 || isNaN(hours) || isNaN(minutes) || isNaN(seconds) ||
      hours < 0 || hours > 23 || minutes < 0 || minutes > 59 || seconds < 0 || seconds > 59) {
      return 0;
    }

    const parsedDate = new Date(currentYear, month, day, hours, minutes, seconds);
    if (parsedDate > now) {
      parsedDate.setFullYear(currentYear - 1);
    }

    return parsedDate.getTime();
  } catch (e) {
    return Date.now() + logIndex * 1000;
  }
};

export default function LogCountChart({ logs, timeRange, theme = 'emerald' }: LogCountChartProps) {
  const themeClasses = THEME_CONFIG[theme];
  const barColor = THEME_COLORS[theme];

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

  const textColor = textColorMap[theme];
  const accentColor = accentColorMap[theme];

  const chartData = useMemo(() => {
    if (logs.length === 0) return [];

    const now = Date.now();
    let startTime: number;
    let rangeMs: number;

    if (timeRange >= 999999999) {
      const timestamps = logs.map((log, index) => ParseTimeStamp(log.timestamp, index)).filter(t => t !== 0);
      if (timestamps.length === 0) return [];

      startTime = Math.min(...timestamps);
      const endTime = Math.max(...timestamps);
      rangeMs = endTime - startTime;
    } else {
      rangeMs = timeRange * 60 * 1000;
      startTime = now - rangeMs;
    }

    let bucketSize: number;
    let timeFormat: (date: Date) => string;

    const rangeDays = rangeMs / (1000 * 60 * 60 * 24);

    if (rangeDays <= 0.042) {
      bucketSize = 60 * 1000;
      timeFormat = (date) => date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } else if (rangeDays <= 1) {
      bucketSize = 30 * 60 * 1000;
      timeFormat = (date) => date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } else if (rangeDays <= 7) {
      bucketSize = 4 * 60 * 60 * 1000;
      timeFormat = (date) => date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit' });
    } else if (rangeDays <= 90) {
      bucketSize = 24 * 60 * 60 * 1000;
      timeFormat = (date) => date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } else {
      bucketSize = 7 * 24 * 60 * 60 * 1000;
      timeFormat = (date) => date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    }

    const buckets: Map<number, number> = new Map();
    const numBuckets = Math.ceil(rangeMs / bucketSize);
    const maxBuckets = 100;

    if (numBuckets > maxBuckets) {
      bucketSize = Math.ceil(rangeMs / maxBuckets);
    }

    for (let i = 0; i <= Math.min(numBuckets, maxBuckets); i++) {
      const bucketTime = startTime + (i * bucketSize);
      buckets.set(bucketTime, 0);
    }

    logs.forEach((log, index) => {
      const logTime = ParseTimeStamp(log.timestamp, index);
      if (logTime === 0 || logTime < startTime) return;

      const bucketIndex = Math.floor((logTime - startTime) / bucketSize);
      const bucketTime = startTime + (bucketIndex * bucketSize);

      if (buckets.has(bucketTime)) {
        buckets.set(bucketTime, (buckets.get(bucketTime) || 0) + 1);
      }
    });

    const data = Array.from(buckets.entries())
      .map(([time, count]) => ({
        time,
        timeLabel: timeFormat(new Date(time)),
        count
      }))
      .sort((a, b) => a.time - b.time);

    return data;
  }, [logs, timeRange]);

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

  return (
    <div className={`w-full h-full ${themeClasses.bg} rounded-lg border ${themeClasses.border} p-3 flex flex-col`}>
      <div className="flex-shrink-0 mb-2">
        <h3 className={`text-sm font-semibold ${themeClasses.text}`}>Log Count Over Time</h3>
        <p className={`text-xs ${themeClasses.accent} mt-0.5`}>
          {logs.length.toLocaleString()} logs
        </p>
      </div>

      <div className="flex-1" style={{ minHeight: 0 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            margin={{ top: 8, right: 12, left: 0, bottom: 20 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke={accentColor} vertical={false} opacity={0.2} />
            <XAxis
              dataKey="timeLabel"
              stroke={accentColor}
              tick={{ fill: accentColor, fontSize: 10 }}
              tickLine={{ stroke: accentColor, opacity: 0.3 }}
              angle={-45}
              textAnchor="end"
              height={20}
            />
            <YAxis
              stroke={accentColor}
              tick={{ fill: accentColor, fontSize: 10 }}
              tickLine={{ stroke: accentColor, opacity: 0.3 }}
              axisLine={{ stroke: accentColor, opacity: 0.3 }}
              width={40}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: theme === 'white' ? '#ffffff' : '#1a1a1a',
                border: `1px solid ${accentColor}`,
                borderRadius: '4px',
                padding: '6px 10px'
              }}
              labelStyle={{ color: textColor, fontSize: '11px', fontWeight: 600 }}
              itemStyle={{ color: barColor, fontSize: '10px' }}
              cursor={{ fill: barColor, opacity: 0.15 }}
              formatter={(value: any) => [`${value}`, 'logs']}
            />
            <Bar
              dataKey="count"
              fill={barColor}
              radius={[2, 2, 0, 0]}
              isAnimationActive={false}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
