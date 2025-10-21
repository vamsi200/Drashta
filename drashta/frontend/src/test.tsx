import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import LogCountChart from "./chart";
import DateRangePicker from "./DateRangePicker";

type RawMsg =
  | { type: "Structured"; value: Record<string, string> }
  | { type: "Plain"; value: string };

type EventData = {
  timestamp: string;
  service: string;
  event_type: string;
  data: Record<string, string>;
  raw_msg: RawMsg;
};

type SortDirection = "asc" | "desc" | null;
type EventSourceType = "drain" | "live";

const SERVICES = [
  "All",
  "Sshd",
  "Sudo",
  "Login",
  "Kernel",
  "ConfigChange",
  "PkgManager",
  "Firewall",
  "Network",
];

const LIFETIME_VALUE = 999999999;

const TIME_RANGES = [
  { label: "Last 15 minutes", value: 15 },
  { label: "Last 30 minutes", value: 30 },
  { label: "Last 1 hour", value: 60 },
  { label: "Last 4 hours", value: 240 },
  { label: "Last 12 hours", value: 720 },
  { label: "Last 24 hours", value: 1440 },
  { label: "Last 7 days", value: 10080 },
  { label: "Last 30 days", value: 43200 },
  { label: "Lifetime", value: LIFETIME_VALUE },
];


function EventSourceToggle({
  selectedSource,
  onSourceChange,
  drainCount,
  liveCount
}: {
  selectedSource: EventSourceType;
  onSourceChange: (source: EventSourceType) => void;
  drainCount: number;
  liveCount: number;
}) {
  return (
    <div className="flex items-center bg-zinc-900 rounded-lg p-1 gap-1 border border-zinc-800">
      <button
        onClick={() => onSourceChange("drain")}
        className={`flex-1 px-3 py-2 text-sm rounded-md transition-all flex items-center justify-center gap-2 font-medium ${selectedSource === "drain"
          ? "bg-zinc-50 text-zinc-900 shadow-sm"
          : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
          }`}
      >
        <div className={`w-2 h-2 rounded-full ${selectedSource === "drain" ? "bg-zinc-900" : "bg-zinc-600"}`}></div>
        <span>Drain ({drainCount.toLocaleString()})</span>
      </button>
      <button
        onClick={() => onSourceChange("live")}
        className={`flex-1 px-3 py-2 text-sm rounded-md transition-all flex items-center justify-center gap-2 font-medium ${selectedSource === "live"
          ? "bg-zinc-50 text-zinc-900 shadow-sm"
          : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
          }`}
      >
        <div className={`w-2 h-2 rounded-full ${selectedSource === "live" ? "bg-zinc-900 animate-pulse" : "bg-zinc-600"}`}></div>
        <span>Live ({liveCount.toLocaleString()})</span>
      </button>
    </div>
  );
}

function EventTypeDropdown({
  selectedTypes,
  onTypeToggle,
  isOpen,
  onToggle,
  availableTypes
}: {
  selectedTypes: string[];
  onTypeToggle: (type: string) => void;
  isOpen: boolean;
  onToggle: () => void;
  availableTypes: string[];
}) {
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        onToggle();
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen, onToggle]);

  if (!isOpen) return null;

  const isAllSelected = selectedTypes.length === 0;

  return (
    <div
      ref={dropdownRef}
      className="absolute top-full right-0 mt-2 bg-zinc-900 border border-zinc-800 rounded-lg shadow-lg z-20 min-w-[200px] max-h-64 overflow-y-auto"
    >
      <button
        className={`w-full text-left px-4 py-2.5 text-sm hover:bg-zinc-800 transition-colors flex items-center gap-3 border-b border-zinc-800 ${isAllSelected ? 'bg-zinc-800 text-zinc-50 font-medium' : 'text-zinc-300'
          }`}
        onClick={() => onTypeToggle("All")}
      >
        <span className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${isAllSelected ? 'bg-zinc-50 text-zinc-900 border-zinc-50' : 'border-zinc-700'
          }`}>
          {isAllSelected ? '✓' : ''}
        </span>
        <span>All ({availableTypes.length - 1} types)</span>
      </button>

      {availableTypes.slice(1).map((type) => {
        const isSelected = selectedTypes.includes(type);
        return (
          <button
            key={type}
            className={`w-full text-left px-4 py-2.5 text-sm hover:bg-zinc-800 transition-colors flex items-center gap-3 border-b border-zinc-800 last:border-b-0 ${isSelected ? 'bg-zinc-800 text-zinc-50 font-medium' : 'text-zinc-300'
              }`}
            onClick={() => onTypeToggle(type)}
          >
            <span className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${isSelected ? 'bg-zinc-50 text-zinc-900 border-zinc-50' : 'border-zinc-700'
              }`}>
              {isSelected ? '✓' : ''}
            </span>
            <span className="truncate">{type}</span>
          </button>
        );
      })}

      {selectedTypes.length > 0 && (
        <button
          className="w-full text-left px-4 py-2 text-xs text-zinc-400 hover:bg-zinc-800 transition-colors border-t border-zinc-800 font-medium"
          onClick={() => onTypeToggle("All")}
        >
          Clear All
        </button>
      )}
    </div>
  );
}

function JsonPart({
  isOpen,
  onClose,
  rawMsg
}: {
  isOpen: boolean;
  onClose: () => void;
  rawMsg: RawMsg | null;
}) {
  if (!isOpen || !rawMsg) return null;

  const displayValue =
    rawMsg.type === "Structured"
      ? JSON.stringify(rawMsg.value, null, 2)
      : rawMsg.value;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative bg-zinc-900 rounded-lg shadow-2xl max-w-4xl max-h-[80vh] w-full mx-4 flex flex-col border border-zinc-800">
        <div className="flex items-center justify-between p-4 border-b border-zinc-800">
          <h3 className="text-lg font-semibold text-zinc-50">Raw JSON Data</h3>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-zinc-800 text-zinc-400 hover:text-zinc-50 transition-colors"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4 bg-zinc-950">
          <pre className="bg-black text-xs text-green-400 p-4 rounded border border-zinc-800 font-mono overflow-auto">
            {displayValue}
          </pre>
        </div>

        <div className="flex justify-end gap-2 p-4 border-t border-zinc-800">
          <button
            onClick={() => navigator.clipboard.writeText(displayValue)}
            className="px-4 py-2 text-sm bg-zinc-50 text-zinc-900 rounded-md hover:bg-zinc-200 transition-colors font-medium"
          >
            Copy JSON
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm bg-zinc-800 text-zinc-50 rounded-md hover:bg-zinc-700 transition-colors font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

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

function LogCardThingy({
  log,
  isExpanded,
  onToggle,
  onViewJson,
}: {
  log: EventData;
  isExpanded: boolean;
  onToggle: () => void;
  onViewJson: (rawMsg: RawMsg, e: React.MouseEvent) => void;
}) {
  const getEventColor = (eventType: string) => {
    const type = eventType.toLowerCase();
    if (type.includes("error") || type.includes("incorrect")) return "error";
    if (type.includes("failure")) return "failure";
    if (type.includes("warn")) return "warn";
    return "info";
  };

  const eventColorClass = getEventColor(log.event_type);
  const message = typeof log.raw_msg === "string"
    ? log.raw_msg
    : log.raw_msg.type === "Structured"
      ? log.raw_msg.value.MESSAGE
      : log.raw_msg.value;

  return (
    <div className="border-b border-zinc-800 hover:bg-zinc-900/50 transition-colors">
      <div className="flex items-start gap-3 px-4 py-3">
        <button
          onClick={onToggle}
          className="flex-shrink-0 mt-1 p-1 hover:bg-zinc-800 rounded transition-colors"
        >
          <svg
            className={`w-4 h-4 text-zinc-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
        </button>

        {/* Timestamp Column */}
        <div className="flex-shrink-0 w-32 pt-1">
          <div className="text-xs text-zinc-500 font-mono">
            {log.timestamp}
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1.5">
            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${eventColorClass === 'error' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
              eventColorClass === 'failure' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                eventColorClass === 'warn' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                  'bg-blue-500/10 text-blue-400 border border-blue-500/20'
              }`}>
              {log.event_type}
            </span>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-zinc-800 text-zinc-300 border border-zinc-700">
              {log.service}
            </span>
            {Object.entries(log.data).map(([key, value]) => (
              <span key={key} className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20">
                <span className="font-semibold">{key}:</span>
                <span className="ml-1">{value}</span>
              </span>
            ))}
          </div>

          {/* Message text */}
          <div className="text-sm text-zinc-300 leading-relaxed">
            {message}
          </div>

          {/* Expanded view */}
          {isExpanded && (
            <div className="mt-3 p-3 bg-zinc-900 border border-zinc-800 rounded-lg text-xs">
              <div className="space-y-2">
                <div className="flex">
                  <span className="font-semibold text-zinc-500 w-24">Timestamp:</span>
                  <span className="text-zinc-300 font-mono">{log.timestamp}</span>
                </div>
                <div className="flex">
                  <span className="font-semibold text-zinc-500 w-24">Service:</span>
                  <span className="text-zinc-300">{log.service}</span>
                </div>
                <div className="flex">
                  <span className="font-semibold text-zinc-500 w-24">Event Type:</span>
                  <span className="text-zinc-300">{log.event_type}</span>
                </div>
                {Object.entries(log.data).length > 0 && (
                  <div className="flex">
                    <span className="font-semibold text-zinc-500 w-24">Data:</span>
                    <div className="flex-1">
                      {Object.entries(log.data).map(([key, value]) => (
                        <div key={key} className="mb-1">
                          <span className="text-purple-400 font-semibold">{key}:</span>{' '}
                          <span className="text-zinc-300">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="flex">
                  <span className="font-semibold text-zinc-500 w-24">Message:</span>
                  <span className="text-zinc-300 flex-1 break-words">{message}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="flex-shrink-0 flex items-start gap-2 pt-1">
          <button
            onClick={(e) => onViewJson(log.raw_msg, e)}
            className="px-3 py-1 text-xs bg-zinc-50 text-zinc-900 rounded-md hover:bg-zinc-200 transition-colors font-medium border border-zinc-700"
          >
            JSON
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [prefetchedNext, setPrefetchedNext] = useState<{
    logs: EventData[];
    cursor: string | null;
  }>({ logs: [], cursor: null });

  const [prefetchedPrev, setPrefetchedPrev] = useState<{
    logs: EventData[];
    cursor: string | null;
  } | null>(null);

  const [drainLogs, setDrainLogs] = useState<EventData[]>([]);
  const [liveLogs, setLiveLogs] = useState<EventData[]>([]);
  const [selectedSource, setSelectedSource] = useState<EventSourceType>("drain");
  const [selectedService, setSelectedService] = useState("All");
  const [selectedType, setSelectedType] = useState<string[]>([]);
  const [currentEventSource, setCurrentEventSource] = useState<EventSource | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [jsonModal, setJsonPart] = useState<{ isOpen: boolean; rawMsg: RawMsg | null }>({
    isOpen: false,
    rawMsg: null,
  });
  const [dateRangeMode, setDateRangeMode] = useState<'relative' | 'absolute'>('relative');
  const [absoluteDateRange, setAbsoluteDateRange] = useState<{ start: Date; end: Date } | null>(null);
  const [dateRangeDropdownOpen, setDateRangeDropdownOpen] = useState(false);

  const [cursor, setCursor] = useState<string | null>(null);
  const [pageSize, _setPageSize] = useState<number>(500);
  const [currentPage, setCurrentPage] = useState<number>(0);
  const [_isFetching, setIsFetching] = useState(false);

  const [typeDropdownOpen, setEventTypeDropdownOpen] = useState(false);
  const [selectedTimeRange, setSelectedTimeRange] = useState(43200);
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [showAnalytics, setShowAnalytics] = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const parentRef = useRef<HTMLDivElement>(null);

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(256);
  const [isResizingSidebar, setIsResizingSidebar] = useState(false);
  const sidebarResizeRef = useRef({
    isResizing: false,
    startX: 0,
    startWidth: 250
  });

  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [expandedLogs, setExpandedLogs] = useState<Set<number>>(new Set());
  const eventName = selectedService === "All" ? "all.events" : `${selectedService.toLowerCase()}.events`;
  const currentLogs = selectedSource === "drain" ? drainLogs : liveLogs;


  const handleDateRangeApply = (mode: 'relative' | 'absolute', value: number | { start: Date; end: Date }) => {
    setDateRangeMode(mode);

    if (mode === 'relative') {
      setSelectedTimeRange(value as number);
      setAbsoluteDateRange(null);
    } else {
      const range = value as { start: Date; end: Date };
      setAbsoluteDateRange(range);

      const diffMs = range.end.getTime() - range.start.getTime();
      const diffMinutes = Math.ceil(diffMs / (1000 * 60));
      setSelectedTimeRange(diffMinutes);
    }
  };


  const extractCursor = useCallback((dataLine: string): string | null => {
    try {
      const parsed = JSON.parse(dataLine);
      const cursorData = parsed.cursor;

      if (!cursorData) return null;

      return JSON.stringify(cursorData);
    } catch (err) {
      console.error("Error parsing cursor:", err);
      return null;
    }
  }, []);

  const fetchInitialDrain = useCallback(async () => {
    setIsFetching(true);
    try {
      const res = await fetch(
        `http://localhost:3200/drain?event_name=${encodeURIComponent(eventName)}&limit=${pageSize}`
      );
      if (!res.ok) throw new Error(`Failed to fetch drain: ${res.status}`);
      const text = await res.text();

      const logs: EventData[] = [];
      let newCursor: string | null = null;

      text.split("\n\n").forEach((evt) => {
        if (!evt.trim()) return;
        const lines = evt.split("\n");
        let type = "";
        let dataLine = "";
        lines.forEach((line) => {
          if (line.startsWith("event:")) type = line.replace("event:", "").trim();
          if (line.startsWith("data:")) dataLine = line.replace("data:", "").trim();
        });

        if (type === "log") logs.push(JSON.parse(dataLine));
        if (type === "cursor") newCursor = extractCursor(dataLine);
      });

      setDrainLogs(logs);
      setCursor(newCursor);
      setCurrentPage(0);
      setCursorStack([]);
    } catch (err) {
      console.error("Error fetching drain:", err);
    } finally {
      setIsFetching(false);
    }
  }, [eventName, pageSize]);


  const prefetchPreviousPage = useCallback(
    async () => {
      if (cursorStack.length === 0) return;

      if (currentPage === 1) {
        return;
      }

      const previousCursor = cursorStack[cursorStack.length - 1];
      if (prefetchedPrev?.cursor === previousCursor) return;

      try {
        const res = await fetch(
          `http://localhost:3200/previous?event_name=${encodeURIComponent(eventName)}&cursor=${encodeURIComponent(previousCursor)}&limit=${pageSize}`
        );
        if (!res.ok) return;
        const text = await res.text();

        const logs: EventData[] = [];

        text.split("\n\n").forEach((evt) => {
          if (!evt.trim()) return;
          const lines = evt.split("\n");
          let type = "";
          let dataLine = "";
          lines.forEach((line) => {
            if (line.startsWith("event:")) type = line.replace("event:", "").trim();
            if (line.startsWith("data:")) dataLine = line.replace("data:", "").trim();
          });

          if (type === "log") logs.push(JSON.parse(dataLine));
        });

        setPrefetchedPrev({ logs, cursor: previousCursor });
      } catch (err) {
        console.error("Error prefetching previous page:", err);
      }
    },
    [eventName, pageSize, cursorStack, currentPage, prefetchedPrev?.cursor]
  );

  const fetchPreviousPage = useCallback(
    async () => {
      if (cursorStack.length === 0) return;
      setIsFetching(true);

      try {
        if (currentPage === 1) {
          await fetchInitialDrain();
          setIsFetching(false);
          return;
        }

        if (prefetchedPrev && prefetchedPrev.logs.length > 0) {
          setDrainLogs(prefetchedPrev.logs);

          const newStack = cursorStack.slice(0, -1);
          setCursorStack(newStack);

          setCursor(prefetchedPrev.cursor);
          setCurrentPage((prev) => Math.max(prev - 1, 0));
          setPrefetchedPrev(null);
          setIsFetching(false);
          return;
        }

        const previousCursor = cursorStack[cursorStack.length - 1];

        const res = await fetch(
          `http://localhost:3200/previous?event_name=${encodeURIComponent(eventName)}&cursor=${encodeURIComponent(previousCursor)}&limit=${pageSize}`
        );
        if (!res.ok) throw new Error(`Failed to fetch previous: ${res.status}`);
        const text = await res.text();

        const logs: EventData[] = [];

        text.split("\n\n").forEach((evt) => {
          if (!evt.trim()) return;
          const lines = evt.split("\n");
          let type = "";
          let dataLine = "";
          lines.forEach((line) => {
            if (line.startsWith("event:")) type = line.replace("event:", "").trim();
            if (line.startsWith("data:")) dataLine = line.replace("data:", "").trim();
          });

          if (type === "log") logs.push(JSON.parse(dataLine));
        });

        setDrainLogs(logs);

        const newStack = cursorStack.slice(0, -1);
        setCursorStack(newStack);
        setCursor(previousCursor);
        setCurrentPage((prev) => Math.max(prev - 1, 0));
      } catch (err) {
        console.error("Error fetching previous page:", err);
      } finally {
        setIsFetching(false);
      }
    },
    [eventName, pageSize, cursorStack, currentPage, prefetchedPrev, fetchInitialDrain]
  );

  const prefetchNextPage = useCallback(
    async (cursorValue: string) => {
      if (!cursorValue || prefetchedNext.cursor) return;

      try {
        const res = await fetch(
          `http://localhost:3200/older?event_name=${encodeURIComponent(eventName)}&cursor=${encodeURIComponent(cursorValue)}&limit=${pageSize}`
        );
        if (!res.ok) return;
        const text = await res.text();

        const logs: EventData[] = [];
        let newCursor: string | null = null;

        text.split("\n\n").forEach((evt) => {
          if (!evt.trim()) return;
          const lines = evt.split("\n");
          let type = "";
          let dataLine = "";
          lines.forEach((line) => {
            if (line.startsWith("event:")) type = line.replace("event:", "").trim();
            if (line.startsWith("data:")) dataLine = line.replace("data:", "").trim();
          });

          if (type === "log") logs.push(JSON.parse(dataLine));
          if (type === "cursor") newCursor = extractCursor(dataLine);
        });

        setPrefetchedNext({ logs, cursor: newCursor });
      } catch (err) {
        console.error("Error prefetching next page:", err);
      }
    },
    [eventName, pageSize, prefetchedNext]
  );

  const fetchOlderPage = useCallback(
    async (cursorValue: string) => {
      if (!cursorValue) return;
      setIsFetching(true);

      try {
        if (prefetchedNext.logs.length > 0 && prefetchedNext.cursor !== null) {
          setDrainLogs((prev) => [...prev, ...prefetchedNext.logs]);
          setCursorStack((prev) => [...prev, cursorValue]);
          setCursor(prefetchedNext.cursor);
          setCurrentPage((prev) => prev + 1);

          const nextCursor = prefetchedNext.cursor;
          setPrefetchedNext({ logs: [], cursor: null });

          if (nextCursor) {
            prefetchNextPage(nextCursor);
          }

          setIsFetching(false);
          return;
        }

        const res = await fetch(
          `http://localhost:3200/older?event_name=${encodeURIComponent(eventName)}&cursor=${encodeURIComponent(cursorValue)}&limit=${pageSize}`
        );
        if (!res.ok) throw new Error(`Failed to fetch older: ${res.status}`);
        const text = await res.text();

        const logs: EventData[] = [];
        let newCursor: string | null = null;

        text.split("\n\n").forEach((evt) => {
          if (!evt.trim()) return;
          const lines = evt.split("\n");
          let type = "";
          let dataLine = "";
          lines.forEach((line) => {
            if (line.startsWith("event:")) type = line.replace("event:", "").trim();
            if (line.startsWith("data:")) dataLine = line.replace("data:", "").trim();
          });

          if (type === "log") logs.push(JSON.parse(dataLine));
          if (type === "cursor") newCursor = extractCursor(dataLine);
        });

        if (logs.length === 0) {
          setCursor(null);
        } else {
          setDrainLogs((prev) => [...prev, ...logs]);
          setCursorStack((prev) => [...prev, cursorValue]);
          setCursor(newCursor);
          setCurrentPage((prev) => prev + 1);

          if (newCursor) {
            prefetchNextPage(newCursor);
          }
        }
      } catch (err) {
        console.error("Error fetching older page:", err);
        setCursor(null);
      } finally {
        setIsFetching(false);
      }
    },
    [eventName, pageSize, prefetchedNext, extractCursor, prefetchNextPage]
  );

  const availableTypes = useMemo(() => {
    let relevantLogs = currentLogs;
    if (selectedService !== "All") {
      relevantLogs = currentLogs.filter(
        log => log.service.toLowerCase() === selectedService.toLowerCase()
      );
    }

    const uniqueTypes = [...new Set(relevantLogs.map(log => log.event_type))].sort();
    return ["All", ...uniqueTypes];
  }, [currentLogs, selectedService]);

  useEffect(() => {
    if (
      selectedType.length > 0 &&
      !selectedType.every(type => availableTypes.includes(type))
    ) {
      setSelectedType([]);
    }
  }, [availableTypes, selectedType]);

  const handleGlobalKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.target === searchInputRef.current || e.ctrlKey || e.altKey || e.metaKey) {
      return;
    }

    if (e.shiftKey && e.key.toLowerCase() === "s") {
      e.preventDefault();
      searchInputRef.current?.focus();
      return;
    }

    if (e.key === "/") {
      e.preventDefault();
      searchInputRef.current?.focus();
      return;
    }
  }, []);

  useEffect(() => {
    document.addEventListener("keydown", handleGlobalKeyDown);
    return () => {
      document.removeEventListener("keydown", handleGlobalKeyDown);
    };
  }, [handleGlobalKeyDown]);

  const toggleTypeSelection = useCallback((type: string) => {
    setSelectedType(prev => {
      if (type === "All") return [];
      if (prev.includes(type)) return prev.filter(t => t !== type);
      return [...prev, type];
    });
  }, []);

  const toggleTimestampSort = useCallback(() => {
    setSortDirection(prev => {
      if (prev === "desc") return "asc";
      if (prev === "asc") return "desc";
      return "desc";
    });
  }, []);


  const handleNextPage = useCallback(() => {
    if (!cursor) return;
    fetchOlderPage(cursor);
  }, [cursor, fetchOlderPage]);

  const handlePrevPage = useCallback(() => {
    fetchPreviousPage();
  }, [fetchPreviousPage]);

  function PaginationBar() {
    return (
      <div className="flex items-center gap-2">
        <button
          onMouseEnter={() => prefetchPreviousPage()}
          onClick={handlePrevPage}
          disabled={currentPage === 0}
          className="px-3 py-1.5 text-sm bg-zinc-900 text-zinc-300 rounded-md border border-zinc-800 hover:bg-zinc-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
        >
          Previous
        </button>
        <div className="text-sm text-zinc-400 px-2">
          Page {currentPage + 1}
        </div>
        <button
          onMouseEnter={() => cursor && prefetchNextPage(cursor)}
          onClick={handleNextPage}
          disabled={!cursor}
          className="px-3 py-1.5 text-sm bg-zinc-900 text-zinc-300 rounded-md border border-zinc-800 hover:bg-zinc-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
        >
          Next
        </button>
      </div>
    );
  }

  useEffect(() => {
    if (selectedSource === "drain") {
      setDrainLogs([]);
      setCursor(null);
      setCurrentPage(0);
      fetchInitialDrain();
    }
  }, [selectedSource, fetchInitialDrain]);

  const filteredAndSortedLogs = useMemo(() => {
    let startTime: number;
    let endTime: number = Date.now();

    if (dateRangeMode === 'absolute' && absoluteDateRange) {
      startTime = absoluteDateRange.start.getTime();
      endTime = absoluteDateRange.end.getTime();
    } else {
      const rangeMs = selectedTimeRange * 60 * 1000;
      startTime = endTime - rangeMs;
    }

    let filtered = currentLogs.filter((log, index) => {
      if (selectedService !== "All" && log.service !== selectedService) return false;

      if (selectedType.length > 0) {
        const logTypeLower = log.event_type.toLowerCase();
        const selectedLower = selectedType.map(t => t.toLowerCase());
        if (!selectedLower.includes(logTypeLower)) return false;
      }

      if (
        searchTerm &&
        !Object.values(log)
          .join(" ")
          .toLowerCase()
          .includes(searchTerm.toLowerCase())
      )
        return false;

      const logTime = ParseTimeStamp(log.timestamp, index);
      if (logTime !== 0 && (logTime < startTime || logTime > endTime)) return false;

      return true;
    });

    if (sortDirection) {
      filtered = [...filtered].sort((a, b) => {
        const indexA = currentLogs.indexOf(a);
        const indexB = currentLogs.indexOf(b);
        const timeA = ParseTimeStamp(a.timestamp, indexA);
        const timeB = ParseTimeStamp(b.timestamp, indexB);

        if (isNaN(timeA) || isNaN(timeB) || timeA === 0 || timeB === 0) {
          return sortDirection === "asc"
            ? a.timestamp.localeCompare(b.timestamp)
            : b.timestamp.localeCompare(a.timestamp);
        }

        if (sortDirection === "asc") {
          return timeA - timeB;
        } else {
          return timeB - timeA;
        }
      });
    }

    return filtered;
  }, [currentLogs, selectedService, selectedType, searchTerm, sortDirection, selectedTimeRange, dateRangeMode, absoluteDateRange]);

  const handleSourceChange = (source: EventSourceType) => {
    setSelectedSource(source);
    setSelectedType([]);
  };

  const clearCurrentLogs = () => {
    if (selectedSource === "drain") {
      setDrainLogs([]);
    } else {
      setLiveLogs([]);
    }
  };

  const handleRefresh = useCallback(() => {
    if (selectedSource === "drain") {
      setDrainLogs([]);
      fetchInitialDrain();
    } else {
      setLiveLogs([]);
    }
    if (currentEventSource) {
      currentEventSource.close();
      setCurrentEventSource(null);
    }
  }, [selectedSource, currentEventSource, fetchInitialDrain]);

  const handleSidebarMouseDown = useCallback((e: React.MouseEvent) => {
    if (sidebarCollapsed) return;
    e.preventDefault();
    setIsResizingSidebar(true);
    sidebarResizeRef.current = {
      isResizing: true,
      startX: e.clientX,
      startWidth: sidebarWidth
    };
  }, [sidebarWidth, sidebarCollapsed]);

  const handleSidebarMouseMove = useCallback((e: MouseEvent) => {
    if (!sidebarResizeRef.current.isResizing) return;

    const diff = e.clientX - sidebarResizeRef.current.startX;
    const newWidth = Math.max(200, Math.min(500, sidebarResizeRef.current.startWidth + diff));
    setSidebarWidth(newWidth);
  }, []);

  const handleSidebarMouseUp = useCallback(() => {
    setIsResizingSidebar(false);
    sidebarResizeRef.current.isResizing = false;
  }, []);

  useEffect(() => {
    if (isResizingSidebar) {
      document.addEventListener('mousemove', handleSidebarMouseMove);
      document.addEventListener('mouseup', handleSidebarMouseUp);
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    } else {
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }

    return () => {
      document.removeEventListener('mousemove', handleSidebarMouseMove);
      document.removeEventListener('mouseup', handleSidebarMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isResizingSidebar, handleSidebarMouseMove, handleSidebarMouseUp]);

  const openJsonPart = (rawMsg: RawMsg, e: React.MouseEvent) => {
    e.stopPropagation();
    setJsonPart({ isOpen: true, rawMsg });
  };

  const closeJsonPart = () => {
    setJsonPart({ isOpen: false, rawMsg: null });
  };

  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  const toggleLogExpansion = (index: number) => {
    setExpandedLogs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(index)) {
        newSet.delete(index);
      } else {
        newSet.add(index);
      }
      return newSet;
    });
  };

  const rowVirtualizer = useVirtualizer({
    count: filteredAndSortedLogs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 80,
    measureElement: (el) => el.getBoundingClientRect().height,
    overscan: 5,
  });

  const getSelectedTimeRangeLabel = () => {
    const range = TIME_RANGES.find(r => r.value === selectedTimeRange);
    return range ? range.label : "Last 15 minutes";
  };

  return (
    <>
      <style>{`
      body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      
      .shadcn-scrollbar::-webkit-scrollbar {
        width: 8px;
        height: 8px;
      }
      .shadcn-scrollbar::-webkit-scrollbar-track {
        background: transparent;
      }
      .shadcn-scrollbar::-webkit-scrollbar-thumb {
        background: #52525b;
        border-radius: 4px;
      }
      .shadcn-scrollbar::-webkit-scrollbar-thumb:hover {
        background: #71717a;
      }
      
      /* Modern DatePicker Styles */
      .react-datepicker {
        background-color: #18181b !important;
        border: 1px solid rgba(63, 63, 70, 0.5) !important;
        border-radius: 12px !important;
        font-family: inherit;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
      }
      .react-datepicker__header {
        background-color: #09090b !important;
        border-bottom: 1px solid #27272a !important;
        border-radius: 12px 12px 0 0 !important;
        padding-top: 12px;
      }
      .react-datepicker__current-month {
        color: #fafafa !important;
        font-weight: 700 !important;
        font-size: 0.875rem !important;
      }
      .react-datepicker__day-name {
        color: #71717a !important;
        font-weight: 700 !important;
        font-size: 0.7rem !important;
      }
      .react-datepicker__day {
        color: #e4e4e7 !important;
        border-radius: 8px !important;
        margin: 3px !important;
        font-weight: 500 !important;
      }
      .react-datepicker__day:hover {
        background-color: #27272a !important;
        color: #ffffff !important;
      }
      .react-datepicker__day--selected {
        background-color: white !important;
        color: black !important;
        font-weight: 700 !important;
      }
      .react-datepicker__day--keyboard-selected {
        background-color: #3f3f46 !important;
        color: white !important;
      }
      .react-datepicker__day--disabled {
        color: #3f3f46 !important;
      }
      .react-datepicker__time-container {
        border-left: 1px solid #27272a !important;
      }
      .react-datepicker__time {
        background-color: #18181b !important;
        border-radius: 0 0 12px 0 !important;
      }
      .react-datepicker__time-list {
        scrollbar-width: thin;
        scrollbar-color: #52525b transparent;
      }
      .react-datepicker__time-list::-webkit-scrollbar {
        width: 6px;
      }
      .react-datepicker__time-list::-webkit-scrollbar-track {
        background: transparent;
      }
      .react-datepicker__time-list::-webkit-scrollbar-thumb {
        background: #52525b;
        border-radius: 3px;
      }
      .react-datepicker__time-list-item {
        color: #e4e4e7 !important;
        font-weight: 500 !important;
        padding: 8px 12px !important;
      }
      .react-datepicker__time-list-item:hover {
        background-color: #27272a !important;
        color: #ffffff !important;
      }
      .react-datepicker__time-list-item--selected {
        background-color: white !important;
        color: black !important;
        font-weight: 700 !important;
      }
      .react-datepicker__navigation {
        top: 14px;
      }
      .react-datepicker__navigation-icon::before {
        border-color: #71717a !important;
        border-width: 2px 2px 0 0 !important;
      }
      .react-datepicker__navigation:hover .react-datepicker__navigation-icon::before {
        border-color: #fafafa !important;
      }
    `}</style>

      <div className="flex h-screen bg-black text-zinc-50 overflow-hidden flex-col">
        <div className="bg-zinc-950 border-b border-zinc-800 px-6 py-2.5 flex items-center justify-between flex-shrink-0">
          <div className="flex-1 max-w-2xl">
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search logs... (Press / or Shift+S)"
              className="w-full bg-zinc-900 placeholder-zinc-500 text-sm px-4 py-2 rounded-lg border border-zinc-800 focus:outline-none focus:ring-2 focus:ring-zinc-700 focus:border-transparent text-zinc-50"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <div className="flex items-center gap-2 ml-4">
            <div className="relative">
              <button
                onClick={() => setDateRangeDropdownOpen(!dateRangeDropdownOpen)}
                className="flex items-center gap-2 px-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg hover:bg-zinc-800 hover:border-zinc-700 transition-all text-sm"
              >
                <svg className="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                <span className="text-zinc-300 font-medium">{getSelectedTimeRangeLabel()}</span>
              </button>
              <DateRangePicker
                isOpen={dateRangeDropdownOpen}
                onClose={() => setDateRangeDropdownOpen(false)}
                onApply={handleDateRangeApply}
                selectedRange={selectedTimeRange}
              />
            </div>

            <button
              onClick={handleRefresh}
              className="p-2 bg-zinc-900 border border-zinc-800 rounded-lg hover:bg-zinc-800 hover:border-zinc-700 transition-all"
              title="Refresh"
            >
              <svg className="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          </div>
        </div>

        <div className="flex flex-1 min-h-0">
          <div
            className={`flex flex-shrink-0 transition-all ${sidebarCollapsed ? 'w-0' : ''}`}
            style={{ width: sidebarCollapsed ? '0px' : `${sidebarWidth}px` }}
          >
            <div className={`bg-zinc-950 border-r border-zinc-800 flex flex-col flex-1 ${sidebarCollapsed ? 'overflow-hidden' : ''}`}>
              <div className="p-4 border-b border-zinc-800">
                <h1 className="text-xl font-bold text-zinc-50 whitespace-nowrap">Drashta</h1>
              </div>

              <div className="p-4 border-b border-zinc-800">
                <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-wide mb-3 whitespace-nowrap">
                  Event Source
                </h2>
                <EventSourceToggle
                  selectedSource={selectedSource}
                  onSourceChange={handleSourceChange}
                  drainCount={drainLogs.length}
                  liveCount={liveLogs.length}
                />
              </div>

              <div className="flex-1 p-4 space-y-4 overflow-y-auto shadcn-scrollbar">
                <div>
                  <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-wide mb-3 whitespace-nowrap">
                    Services
                  </h2>
                  <div className="space-y-1">
                    {SERVICES.map((svc) => (
                      <button
                        key={svc}
                        className={`w-full text-left px-3 py-2 rounded-md text-sm whitespace-nowrap font-medium transition-colors border ${selectedService === svc
                          ? "bg-zinc-50 text-zinc-900 border-zinc-700"
                          : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100 border-transparent"
                          }`}
                        onClick={() => setSelectedService(svc)}
                      >
                        {svc}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {!sidebarCollapsed && (
              <div
                className="w-1 bg-zinc-800 cursor-col-resize flex-shrink-0 hover:bg-zinc-600 transition-colors"
                onMouseDown={handleSidebarMouseDown}
              />
            )}
          </div>

          <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
            <div className="bg-zinc-950 border-b border-zinc-800 px-6 py-3 flex-shrink-0">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <button
                    onClick={toggleSidebar}
                    className="p-2 rounded-md hover:bg-zinc-900 transition-colors"
                    aria-label="Toggle sidebar"
                  >
                    <div className="w-5 h-4 flex flex-col justify-between">
                      <span className="block h-0.5 bg-zinc-400"></span>
                      <span className="block h-0.5 bg-zinc-400"></span>
                      <span className="block h-0.5 bg-zinc-400"></span>
                    </div>
                  </button>

                  <div className="text-sm px-3 py-1.5 bg-zinc-900 rounded-md border border-zinc-800">
                    <span className="text-zinc-400">Total: </span>
                    <span className="text-zinc-50 font-semibold">{filteredAndSortedLogs.length.toLocaleString()}</span>
                  </div>
                  <div className="text-sm px-3 py-1.5 bg-red-500/10 rounded-md border border-red-500/20">
                    <span className="text-red-400">Errors: </span>
                    <span className="text-red-300 font-semibold">
                      {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "error").length.toLocaleString()}
                    </span>
                  </div>
                  <div className="text-sm px-3 py-1.5 bg-orange-500/10 rounded-md border border-orange-500/20">
                    <span className="text-orange-400">Failures: </span>
                    <span className="text-orange-300 font-semibold">
                      {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "failure").length.toLocaleString()}
                    </span>
                  </div>
                  <div className="text-sm px-3 py-1.5 bg-yellow-500/10 rounded-md border border-yellow-500/20">
                    <span className="text-yellow-400">Warnings: </span>
                    <span className="text-yellow-300 font-semibold">
                      {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "warn").length.toLocaleString()}
                    </span>
                  </div>
                  <div className="text-sm px-3 py-1.5 bg-blue-500/10 rounded-md border border-blue-500/20">
                    <span className="text-blue-400">Info: </span>
                    <span className="text-blue-300 font-semibold">
                      {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "info").length.toLocaleString()}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={toggleTimestampSort}
                    className="px-3 py-1.5 text-sm rounded-md border font-medium transition-colors bg-zinc-900 text-zinc-300 border-zinc-800 hover:bg-zinc-800 flex items-center gap-2"
                    title={`Sort: ${sortDirection === 'desc' ? 'Newest first' : 'Oldest first'}`}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="flex items-center gap-1">
                      Time
                      {sortDirection === 'desc' ? (
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      ) : (
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                        </svg>
                      )}
                    </span>
                  </button>

                  <div className="relative">
                    <button
                      onClick={() => setEventTypeDropdownOpen(!typeDropdownOpen)}
                      className="px-3 py-1.5 text-sm rounded-md border font-medium transition-colors bg-zinc-900 text-zinc-300 border-zinc-800 hover:bg-zinc-800 flex items-center gap-2"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
                      </svg>
                      <span>Event Type</span>
                      {selectedType.length > 0 && (
                        <span className="bg-zinc-700 text-zinc-200 px-1.5 py-0.5 rounded text-xs font-semibold">
                          {selectedType.length}
                        </span>
                      )}
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>
                    <EventTypeDropdown
                      selectedTypes={selectedType}
                      onTypeToggle={toggleTypeSelection}
                      isOpen={typeDropdownOpen}
                      onToggle={() => setEventTypeDropdownOpen(false)}
                      availableTypes={availableTypes}
                    />
                  </div>

                  <button
                    onClick={() => setShowAnalytics(!showAnalytics)}
                    className={`px-3 py-1.5 text-sm rounded-md border font-medium transition-colors ${showAnalytics
                      ? 'bg-zinc-50 text-zinc-900 border-zinc-700'
                      : 'bg-zinc-900 text-zinc-300 border-zinc-800 hover:bg-zinc-800'
                      }`}
                  >
                    {showAnalytics ? 'Hide' : 'Show'} Analytics
                  </button>
                  <button
                    onClick={clearCurrentLogs}
                    className="px-3 py-1.5 text-sm bg-zinc-900 text-zinc-300 rounded-md border border-zinc-800 hover:bg-zinc-800 transition-colors font-medium"
                  >
                    Clear Logs
                  </button>
                </div>
              </div>
            </div>

            <div className="flex-1 flex flex-col overflow-hidden m-4 gap-4" style={{ height: 'calc(100vh - 250px)' }}>
              {showAnalytics && (
                <div className="flex-shrink-0" style={{ height: '30%', minHeight: '280px' }}>
                  <LogCountChart logs={filteredAndSortedLogs} timeRange={selectedTimeRange} />
                </div>
              )}

              <div className="flex-1 bg-zinc-950 rounded-lg overflow-hidden flex flex-col border border-zinc-800">
                <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {selectedSource === "drain" && <PaginationBar />}
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-xs text-zinc-500 font-medium">
                      Showing {filteredAndSortedLogs.length} of {currentLogs.length} logs
                    </div>
                    <div className="text-xs text-zinc-600 font-medium">
                      {sortDirection === 'desc' ? '↓ Newest first' : '↑ Oldest first'}
                    </div>
                  </div>
                </div>

                <div ref={parentRef} className="flex-1 overflow-auto shadcn-scrollbar bg-zinc-950">
                  {filteredAndSortedLogs.length === 0 ? (
                    <div className="flex items-center justify-center h-full text-zinc-500">
                      <div className="text-center p-8 border border-zinc-800 rounded-lg bg-zinc-900">
                        <div className="text-lg font-semibold text-zinc-300">No logs found</div>
                        <div className="text-sm text-zinc-500 mt-2">
                          {selectedService !== "All" && availableTypes.length === 1
                            ? `No event types available for ${selectedService}`
                            : "Try adjusting filters or wait for new events"
                          }
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div
                      style={{
                        height: `${rowVirtualizer.getTotalSize()}px`,
                        position: "relative",
                      }}
                    >
                      {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                        const log = filteredAndSortedLogs[virtualRow.index];
                        const isExpanded = expandedLogs.has(virtualRow.index);

                        return (
                          <div
                            key={virtualRow.key}
                            data-index={virtualRow.index}
                            ref={rowVirtualizer.measureElement}
                            className="absolute left-0 right-0"
                            style={{
                              transform: `translateY(${virtualRow.start}px)`,
                            }}
                          >
                            <LogCardThingy
                              log={log}
                              isExpanded={isExpanded}
                              onToggle={() => toggleLogExpansion(virtualRow.index)}
                              onViewJson={openJsonPart}
                            />
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        <JsonPart
          isOpen={jsonModal.isOpen}
          onClose={closeJsonPart}
          rawMsg={jsonModal.rawMsg}
        />
      </div>
    </>
  );
}
