import { useEffect, useState, useMemo, useRef, useCallback, memo } from "react";
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
export type ThemeType = "emerald" | "white" | "black";

const SERVICES = [
  "All",
  "Sshd",
  "Sudo",
  "Login",
  "Kernel",
  "ConfigChange",
  "PkgManager",
  "Firewalld",
  "NetworkManager",
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

export const THEME_CONFIG: Record<ThemeType, {
  bg: string;
  text: string;
  border: string;
  accent: string;
  hover: string;
  activeBtn: string;
  inactiveBtn: string;
  logRowBg: string;
  logRowHover: string;
  logRowBorder: string;
  expandedBg: string;
  modalBg: string;
}> = {
  emerald: {
    bg: "bg-black",
    text: "text-green-400",
    border: "border-green-600",
    accent: "text-green-600",
    hover: "hover:bg-green-950",
    activeBtn: "bg-green-600 text-black",
    inactiveBtn: "bg-black text-green-400",
    logRowBg: "bg-black",
    logRowHover: "hover:bg-green-950/30",
    logRowBorder: "border-green-600/20",
    expandedBg: "bg-black/50 border-l-green-600",
    modalBg: "bg-black",
  },
  white: {
    bg: "bg-white",
    text: "text-gray-900",
    border: "border-gray-300",
    accent: "text-gray-600",
    hover: "hover:bg-gray-100",
    activeBtn: "bg-gray-900 text-white",
    inactiveBtn: "bg-white text-gray-900",
    logRowBg: "bg-white",
    logRowHover: "hover:bg-gray-50",
    logRowBorder: "border-gray-200",
    expandedBg: "bg-gray-50 border-l-gray-400",
    modalBg: "bg-white",
  },
  black: {
    bg: "bg-black",
    text: "text-white",
    border: "border-zinc-800",
    accent: "text-zinc-400",
    hover: "hover:bg-zinc-950",
    activeBtn: "bg-white text-black",
    inactiveBtn: "bg-black text-white border-zinc-800",
    logRowBg: "bg-black",
    logRowHover: "hover:bg-zinc-950",
    logRowBorder: "border-zinc-800",
    expandedBg: "bg-zinc-950 border-l-zinc-600",
    modalBg: "bg-black",
  },
};


const ServiceDropdown = memo(function ServiceDropdown({
  selectedService,
  onServiceChange,
  isOpen,
  onToggle,
  services,
  theme = 'emerald',
}: {
  selectedService: string;
  onServiceChange: (service: string) => void;
  isOpen: boolean;
  onToggle: () => void;
  services: string[];
  theme?: ThemeType;
}) {
  const dropdownRef = useRef<HTMLDivElement>(null);
  const themeClasses = THEME_CONFIG[theme];

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

  return (
    <div
      ref={dropdownRef}
      className={`absolute top-full right-0 mt-1 ${themeClasses.bg} border ${themeClasses.border} rounded shadow-2xl z-20 min-w-[200px] max-h-64 overflow-y-auto`}
      onClick={(e) => e.stopPropagation()}
    >
      {services.map((service) => {
        const isSelected = selectedService === service;
        return (
          <button
            key={service}
            className={`w-full text-left px-2 py-1 text-xs ${themeClasses.hover} transition-colors border-b ${themeClasses.border} last:border-b-0 font-mono ${isSelected ? `${themeClasses.hover} ${themeClasses.text}` : themeClasses.accent
              }`}
            onClick={(e) => {
              e.stopPropagation();
              onServiceChange(service);
              onToggle();
            }}
          >
            <span
              className={`w-2 h-2 rounded-full inline-block mr-2 ${isSelected ? themeClasses.text.replace('text-', 'bg-') : themeClasses.accent.replace('text-', 'bg-')
                }`}
            ></span>
            <span className="truncate">{service}</span>
          </button>
        );
      })}
    </div>
  );
});

const EventTypeDropdown = memo(function EventTypeDropdown({
  selectedTypes,
  onTypeToggle,
  isOpen,
  onToggle,
  availableTypes,
  theme = 'emerald',
}: {
  selectedTypes: string[];
  onTypeToggle: (type: string) => void;
  isOpen: boolean;
  onToggle: () => void;
  availableTypes: string[];
  theme?: ThemeType;
}) {
  const dropdownRef = useRef<HTMLDivElement>(null);
  const themeClasses = THEME_CONFIG[theme];

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
      className={`absolute top-full right-0 mt-1 ${themeClasses.bg} border ${themeClasses.border} rounded shadow-2xl z-20 min-w-[200px] max-h-64 overflow-y-auto`}
      onClick={(e) => e.stopPropagation()}
    >
      <button
        className={`w-full text-left px-2 py-1 text-xs ${themeClasses.hover} transition-colors border-b ${themeClasses.border} font-mono ${isAllSelected ? `${themeClasses.hover} ${themeClasses.text}` : themeClasses.accent
          }`}
        onClick={(e) => {
          e.stopPropagation();
          onTypeToggle("All");
        }}
      >
        <span
          className={`w-2 h-2 rounded-full inline-block mr-2 ${isAllSelected ? themeClasses.text.replace('text-', 'bg-') : themeClasses.accent.replace('text-', 'bg-')
            }`}
        ></span>
        All ({availableTypes.length - 1})
      </button>

      {availableTypes.slice(1).map((type) => {
        const isSelected = selectedTypes.includes(type);
        return (
          <button
            key={type}
            className={`w-full text-left px-2 py-1 text-xs ${themeClasses.hover} transition-colors border-b ${themeClasses.border} last:border-b-0 font-mono ${isSelected ? `${themeClasses.hover} ${themeClasses.text}` : themeClasses.accent
              }`}
            onClick={(e) => {
              e.stopPropagation();
              onTypeToggle(type);
            }}
          >
            <span
              className={`w-2 h-2 rounded-full inline-block mr-2 ${isSelected ? themeClasses.text.replace('text-', 'bg-') : themeClasses.accent.replace('text-', 'bg-')
                }`}
            ></span>
            <span className="truncate">{type}</span>
          </button>
        );
      })}

      {selectedTypes.length > 0 && (
        <button
          className={`w-full text-left px-2 py-1 text-xs ${themeClasses.accent} ${themeClasses.hover} transition-colors border-t ${themeClasses.border} font-mono`}
          onClick={(e) => {
            e.stopPropagation();
            onTypeToggle("All");
          }}
        >
          CLEAR
        </button>
      )}
    </div>
  );
});

function JsonPart({
  isOpen,
  onClose,
  rawMsg,
  theme,
}: {
  isOpen: boolean;
  onClose: () => void;
  rawMsg: RawMsg | null;
  theme: ThemeType;
}) {
  if (!isOpen || !rawMsg) return null;
  const config = THEME_CONFIG[theme];

  const displayValue =
    rawMsg.type === "Structured"
      ? JSON.stringify(rawMsg.value, null, 2)
      : rawMsg.value;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className={`absolute inset-0 ${config.modalBg} bg-opacity-90 backdrop-blur-sm`}
        onClick={onClose}
      />
      <div className={`relative ${config.modalBg} rounded-none shadow-2xl max-w-5xl max-h-[85vh] w-full mx-4 flex flex-col border ${config.border}`}>
        <div className={`flex items-center justify-between p-3 border-b ${config.border}`}>
          <h3 className={`${config.text} font-mono text-xs`}><span className={config.accent}>$</span> view_event_data</h3>
          <button
            onClick={onClose}
            className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}

          >
            ×
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4">
          <pre className={`${config.text} text-xs font-mono overflow-auto leading-relaxed whitespace-pre-wrap break-words`}>
            {displayValue}
          </pre>
        </div>

        <div className={`flex justify-end gap-2 p-3 border-t ${config.border}`}>
          <button
            onClick={() => navigator.clipboard.writeText(displayValue)}
            className={`px-3 py-1 text-xs border ${config.border} ${config.text} ${config.hover} transition-colors font-mono`}
          >
            [COPY]
          </button>
          <button
            onClick={onClose}
            className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}

          >
            [EXIT]
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

const TableLogRow = memo(function TableLogRow({
  log,
  isExpanded,
  onToggle,
  onViewJson,
  theme,
}: {
  log: EventData;
  isExpanded: boolean;
  onToggle: () => void;
  onViewJson: (rawMsg: RawMsg, e: React.MouseEvent) => void;
  theme: ThemeType;
}) {
  const config = THEME_CONFIG[theme];
  const message = useMemo(() => {
    return typeof log.raw_msg === "string"
      ? log.raw_msg
      : log.raw_msg.type === "Structured"
        ? log.raw_msg.value.MESSAGE
        : log.raw_msg.value;
  }, [log.raw_msg]);

  const dataEntries = useMemo(() => Object.entries(log.data), [log.data]);

  const isError = useMemo(() => {
    const type = log.event_type.toLowerCase();
    return type.includes("error") || type.includes("fail") || type.includes("denied");
  }, [log.event_type]);

  const isWarning = useMemo(() => {
    const type = log.event_type.toLowerCase();
    return type.includes("warn") || type.includes("attempt");
  }, [log.event_type]);

  const textColor = isError ? "text-red-500" : isWarning ? "text-yellow-500" : config.text;

  return (
    <>
      <div
        onClick={onToggle}
        className={`cursor-pointer px-3 py-2 transition-colors font-mono text-xs ${textColor} ${isExpanded ? config.logRowHover : config.logRowHover} border-b ${config.logRowBorder}`}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <span className={config.accent}>[{String(log.service).padEnd(12)}]</span>
            <span className={config.accent}>{" > "}</span>
            <span className={`${config.accent} opacity-70`}>{log.timestamp}</span>
            <span className={config.accent}>{" | "}</span>
            <span className={isError ? "text-red-500" : isWarning ? "text-yellow-500" : "text-cyan-400"}>
              {log.event_type}
            </span>
            <span className={config.accent}>{" >> "}</span>
            <span className={textColor}>{message.substring(0, 60)}</span>
            {message.length > 60 && <span className={config.accent}>...</span>}
          </div>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onViewJson(log.raw_msg, e);
            }}
            className={`ml-4 ${config.accent} hover:${config.text} transition-colors flex-shrink-0 font-mono text-xs whitespace-nowrap`}
          >
            [INSPECT]
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className={`${config.expandedBg} border-b ${config.logRowBorder} border-l-2 pl-3 py-2 px-3 font-mono text-xs ${config.text}`}>
          <div className={`${config.accent} mb-2`}>
            <span className={`${config.accent} opacity-60`}>└─</span> EVENT_DETAILS:
          </div>

          {dataEntries.length > 0 && (
            <div className="ml-2 space-y-1 mb-2">
              {dataEntries.map(([key, value]) => (
                <div key={key} className={config.text}>
                  <span className={config.accent}>├─</span>
                  <span className="text-cyan-400">{key}</span>
                  <span className={config.accent}>: </span>
                  <span className={`${config.text} break-words`}>{value}</span>
                </div>
              ))}
            </div>
          )}

        </div>
      )}
    </>
  );
});

export default function Dashboard() {
  const [theme, setTheme] = useState<ThemeType>(() => {
    return (localStorage.getItem('drashta_theme') || "emerald") as ThemeType;
  });

  const [prefetchedNext, setPrefetchedNext] = useState<{
    logs: EventData[];
    cursor: string | null;
  }>({ logs: [], cursor: null });

  const [prefetchedPrev, setPrefetchedPrev] = useState<{
    logs: EventData[];
    cursor: string | null;
  } | null>(null);

  const [searchTerm, setSearchTerm] = useState(() => {
    return localStorage.getItem('drashta_searchTerm') || "";
  });

  const [activeQuery, setActiveQuery] = useState(() => {
    return localStorage.getItem('drashta_activeQuery') || "";
  });

  const [drainLogs, setDrainLogs] = useState<EventData[]>([]);
  const [liveLogs, setLiveLogs] = useState<EventData[]>([]);

  const [selectedSource, setSelectedSource] = useState<EventSourceType>(() => {
    return (localStorage.getItem('drashta_selectedSource') || "drain") as EventSourceType;
  });

  const [selectedService, setSelectedService] = useState(() => {
    return localStorage.getItem('drashta_selectedService') || "All";
  });

  const [selectedType, setSelectedType] = useState<string[]>(() => {
    const saved = localStorage.getItem('drashta_selectedType');
    try {
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });
  const [isServiceDropdownOpen, setIsServiceDropdownOpen] = useState(false);
  const [allAvailableTypes, setAllAvailableTypes] = useState<string[]>(["All"]);
  const [currentEventSource, setCurrentEventSource] = useState<EventSource | null>(null);
  const [jsonModal, setJsonPart] = useState<{ isOpen: boolean; rawMsg: RawMsg | null }>({
    isOpen: false,
    rawMsg: null,
  });
  const [dateRangeMode, setDateRangeMode] = useState<'relative' | 'absolute'>('relative');
  const [absoluteDateRange, setAbsoluteDateRange] = useState<{ start: Date; end: Date } | null>(null);
  const [dateRangeDropdownOpen, setDateRangeDropdownOpen] = useState(false);

  const [cursor, setCursor] = useState<string | null>(null);
  const [pageSize, _setPageSize] = useState<number>(500);

  const [currentPage, setCurrentPage] = useState<number>(() => {
    const saved = localStorage.getItem('drashta_currentPage');
    return saved ? parseInt(saved) : 0;
  });

  const [_isFetching, setIsFetching] = useState(false);

  const [typeDropdownOpen, setEventTypeDropdownOpen] = useState(false);

  const [selectedTimeRange, setSelectedTimeRange] = useState(() => {
    const saved = localStorage.getItem('drashta_selectedTimeRange');
    return saved ? parseInt(saved) : 43200;
  });

  const [sortDirection, setSortDirection] = useState<SortDirection>(() => {
    return (localStorage.getItem('drashta_sortDirection') || "desc") as SortDirection;
  });

  const [showAnalytics, setShowAnalytics] = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const parentRef = useRef<HTMLDivElement>(null);

  const [_sidebarWidth, setSidebarWidth] = useState(256);
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

  useEffect(() => {
    localStorage.setItem('drashta_searchTerm', searchTerm);
  }, [searchTerm]);

  useEffect(() => {
    localStorage.setItem('drashta_activeQuery', activeQuery);
  }, [activeQuery]);

  useEffect(() => {
    localStorage.setItem('drashta_selectedSource', selectedSource);
  }, [selectedSource]);

  useEffect(() => {
    localStorage.setItem('drashta_selectedService', selectedService);
  }, [selectedService]);

  useEffect(() => {
    localStorage.setItem('drashta_selectedType', JSON.stringify(selectedType));
  }, [selectedType]);

  useEffect(() => {
    localStorage.setItem('drashta_currentPage', currentPage.toString());
  }, [currentPage]);

  useEffect(() => {
    localStorage.setItem('drashta_selectedTimeRange', selectedTimeRange.toString());
  }, [selectedTimeRange]);

  useEffect(() => {
    if (sortDirection) {
      localStorage.setItem('drashta_sortDirection', sortDirection);
    }
  }, [sortDirection]);

  useEffect(() => {
    localStorage.setItem('drashta_theme', theme);
  }, [theme]);

  useEffect(() => {
    if (selectedSource === "live") {
      setSelectedTimeRange(15);
    } else {
      setSelectedTimeRange(LIFETIME_VALUE);
    }
  }, [selectedSource]);

  const buildQueryParams = useCallback((
    baseParams: Record<string, string | string[] | undefined>
  ) => {
    const params = new URLSearchParams();

    for (const key in baseParams) {
      const value = baseParams[key];
      if (Array.isArray(value)) {
        value.forEach(v => params.append(key, v));
      } else if (value) {
        params.append(key, value);
      }
    }

    if (activeQuery && activeQuery.trim() !== "") {
      params.append("query", activeQuery.trim());
    }

    return params.toString();
  }, [activeQuery]);

  useEffect(() => {
    if (currentLogs.length > 0) {
      const uniqueTypes = [...new Set(currentLogs.map(log => log.event_type))].sort();
      setAllAvailableTypes(["All", ...uniqueTypes]);
    }
  }, [currentLogs]);

  useEffect(() => {
    if (selectedSource !== "live") {
      if (currentEventSource) {
        currentEventSource.close();
        setCurrentEventSource(null);
      }
      return;
    }

    let eventSource: EventSource | null = null;
    let reconnectTimer: number | null = null;

    const connect = () => {
      const url = `http://localhost:3200/live?event_name=${encodeURIComponent(eventName)}`;
      const es = new EventSource(url);

      es.onopen = () => {
        if (reconnectTimer !== null) {
          clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
      };

      es.onmessage = (event) => {
        try {
          const logData: EventData = JSON.parse(event.data);
          setLiveLogs((prev) => [logData, ...prev]);
        } catch (err) {
          console.error("Error parsing message:", err);
        }
      };

      es.addEventListener("log", (event) => {
        try {
          const logData: EventData = JSON.parse((event as MessageEvent).data);
          setLiveLogs((prev) => [logData, ...prev]);
        } catch (err) {
          console.error("Error parsing log event:", err);
        }
      });

      es.onerror = () => {
        console.error("EventSource error, reconnecting in 3s...");
        es.close();

        reconnectTimer = window.setTimeout(() => {
          connect();
        }, 3000);
      };

      eventSource = es;
      setCurrentEventSource(es);
    };

    connect();

    return () => {
      if (eventSource) eventSource.close();
      if (reconnectTimer !== null) clearTimeout(reconnectTimer);
    };
  }, [selectedSource, eventName]);

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
    setDateRangeDropdownOpen(false);
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
      const queryParams = buildQueryParams({
        event_name: eventName,
        limit: pageSize.toString(),
        event_type: selectedType.length > 0 ? selectedType : undefined,
      });

      const res = await fetch(`http://localhost:3200/drain?${queryParams}`);
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
      setPrefetchedNext({ logs: [], cursor: null });
      setPrefetchedPrev(null);

      if (newCursor) {
        prefetchNextPage(newCursor);
      }
    } catch (err) {
      console.error("Error fetching drain:", err);
    } finally {
      setIsFetching(false);
    }
  }, [eventName, pageSize, buildQueryParams, extractCursor, activeQuery, selectedType]);

  const handleSearchSubmit = useCallback(() => {
    const trimmedQuery = searchTerm.trim();

    if (activeQuery === trimmedQuery) return;

    setDrainLogs([]);
    setCursor(null);
    setCurrentPage(0);
    setCursorStack([]);
    setPrefetchedNext({ logs: [], cursor: null });
    setPrefetchedPrev(null);

    setActiveQuery(trimmedQuery);
  }, [searchTerm, activeQuery]);

  const prefetchPreviousPage = useCallback(
    async () => {
      if (cursorStack.length === 0) return;
      if (currentPage === 1) return;

      const previousCursor = cursorStack[cursorStack.length - 1];
      if (prefetchedPrev?.cursor === previousCursor) return;

      try {
        const queryParams = buildQueryParams({
          event_name: eventName,
          cursor: previousCursor,
          limit: pageSize.toString(),
          event_type: selectedType.length > 0 ? selectedType : undefined,
        });

        const res = await fetch(`http://localhost:3200/previous?${queryParams}`);
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
    [eventName, pageSize, cursorStack, currentPage, prefetchedPrev?.cursor, buildQueryParams, selectedType]
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
        const queryParams = buildQueryParams({
          event_name: eventName,
          cursor: previousCursor,
          limit: pageSize.toString(),
          event_type: selectedType.length > 0 ? selectedType : undefined,
        });

        const res = await fetch(`http://localhost:3200/previous?${queryParams}`);
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
    [eventName, pageSize, cursorStack, currentPage, prefetchedPrev, fetchInitialDrain, buildQueryParams, selectedType]
  );

  const prefetchNextPage = useCallback(
    async (cursorValue: string) => {
      if (!cursorValue) return;
      if (prefetchedNext.cursor === cursorValue) return;

      try {
        const queryParams = buildQueryParams({
          event_name: eventName,
          cursor: cursorValue,
          limit: pageSize.toString(),
          event_type: selectedType.length > 0 ? selectedType : undefined,
        });

        const res = await fetch(`http://localhost:3200/older?${queryParams}`);
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
    [eventName, pageSize, extractCursor, prefetchedNext.cursor, buildQueryParams, selectedType]
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

        const queryParams = buildQueryParams({
          event_name: eventName,
          cursor: cursorValue,
          limit: pageSize.toString(),
          event_type: selectedType.length > 0 ? selectedType : undefined,
        });

        const res = await fetch(`http://localhost:3200/older?${queryParams}`);
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
    [eventName, pageSize, prefetchedNext, extractCursor, prefetchNextPage, buildQueryParams, selectedType]
  );

  const handleGlobalKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.target === searchInputRef.current || e.ctrlKey || e.altKey || e.metaKey) {
      return;
    }

    if (e.key.toLowerCase() === 's' || e.key === '/') {
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

      if (prev.includes(type)) {
        return prev.filter(t => t !== type);
      }
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

  useEffect(() => {
    if (selectedSource === "drain") {
      fetchInitialDrain();
    }
  }, [selectedSource, activeQuery, selectedService, selectedType, fetchInitialDrain]);

  useEffect(() => {
    if (selectedSource === "live") {
      setSelectedTimeRange(15);
    }
  }, [selectedSource]);

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
      if (selectedService !== "All" &&
        log.service.toLowerCase() !== selectedService.toLowerCase()) {
        return false;
      }

      if (selectedSource === "live" && selectedType.length > 0) {
        if (!selectedType.includes(log.event_type)) {
          return false;
        }
      }

      const logTime = ParseTimeStamp(log.timestamp, index);
      if (logTime !== 0 && (logTime < startTime || logTime > endTime)) {
        return false;
      }

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

        return sortDirection === "asc" ? timeA - timeB : timeB - timeA;
      });
    }

    return filtered;
  }, [currentLogs, selectedService, selectedType, selectedSource, sortDirection, selectedTimeRange, dateRangeMode, absoluteDateRange]);

  const handleSourceChange = (source: EventSourceType) => {
    if (currentEventSource) {
      currentEventSource.close();
      setCurrentEventSource(null);
    }
    setSelectedSource(source);
    setSelectedType([]);
  };

  const handleRefresh = useCallback(() => {
    if (selectedSource === "drain") {
      setDrainLogs([]);
      fetchInitialDrain();
    } else {
      setLiveLogs([]);
      if (currentEventSource) {
        currentEventSource.close();
        setCurrentEventSource(null);
      }
    }
  }, [selectedSource, currentEventSource, fetchInitialDrain]);

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

  const toggleLogExpansion = useCallback((index: number) => {
    setExpandedLogs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(index)) {
        newSet.delete(index);
      } else {
        newSet.add(index);
      }
      return newSet;
    });
  }, []);

  const rowVirtualizer = useVirtualizer({
    count: filteredAndSortedLogs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 50,
    overscan: 10,
    measureElement: typeof window !== 'undefined' && navigator.userAgent.indexOf('Firefox') === -1
      ? element => element?.getBoundingClientRect().height
      : undefined,
  });

  const getSelectedTimeRangeLabel = () => {
    const range = TIME_RANGES.find(r => r.value === selectedTimeRange);
    return range ? range.label : "Last 15 minutes";
  };
  const config = THEME_CONFIG[theme];
  const [themeDropdownOpen, setThemeDropdownOpen] = useState(false);

  return (
    <div className={`h-screen ${config.bg} flex flex-col overflow-hidden font-mono ${config.text}`}>
      <div className={`${config.bg} px-3 py-3 shadow-lg`}>
        <div className="flex items-center justify-between gap-3">
          <div className="flex-1">
            <input
              ref={searchInputRef}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearchSubmit()}
              placeholder="$ Type 'S' or '/' to search"
              className={`w-full px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs placeholder-opacity-50 focus:outline-none focus:ring-1 focus:ring-opacity-50 font-mono`}
            />
          </div>

          <div className="flex gap-1">
            <div className="relative">
              <button
                onClick={() => setIsServiceDropdownOpen(!isServiceDropdownOpen)}
                className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs focus:outline-none font-mono hover:opacity-80 transition-colors min-w-[120px] text-left`}
              >
                {selectedService}
              </button>

              <ServiceDropdown
                selectedService={selectedService}
                onServiceChange={setSelectedService}
                isOpen={isServiceDropdownOpen}
                onToggle={() => setIsServiceDropdownOpen(false)}
                services={SERVICES}
                theme={theme}
              />
            </div>

            <div className="relative">
              <button
                onClick={() => setEventTypeDropdownOpen(!typeDropdownOpen)}
                className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}

              >
                [TYPES]
              </button>
              <EventTypeDropdown
                selectedTypes={selectedType}
                onTypeToggle={toggleTypeSelection}
                isOpen={typeDropdownOpen}
                onToggle={() => setEventTypeDropdownOpen(false)}
                availableTypes={allAvailableTypes}
                theme={theme}
              />
            </div>

            <div className="relative">
              <button
                onClick={() => setDateRangeDropdownOpen(!dateRangeDropdownOpen)}
                className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}
              >
                [{getSelectedTimeRangeLabel().substring(0, 8)}]
              </button>
              <DateRangePicker
                isOpen={dateRangeDropdownOpen}
                onClose={() => setDateRangeDropdownOpen(false)}
                onApply={handleDateRangeApply}
                selectedRange={selectedTimeRange}
                theme={theme}
              />
            </div>

            <button
              onClick={toggleTimestampSort}
              className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}

            >
              [SORT]
            </button>
            <div className={`flex border ${config.border} rounded overflow-hidden`}>
              <button
                onClick={() => handleSourceChange("drain")}
                className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono ${selectedSource === "drain" ? "font-bold" : "font-normal"
                  }`}
              >
                DRAIN
              </button>
              <button
                onClick={() => handleSourceChange("live")}
                className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono ${selectedSource === "live" ? "font-bold" : "font-normal"
                  }`}
              >
                LIVE
              </button>
            </div>


            <button
              onClick={handleRefresh}
              className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}
            >
              [REFRESH]
            </button>

            <button
              onClick={() => setShowAnalytics(!showAnalytics)}
              className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}

            >
              [CHART]
            </button>

            <div className="relative">
              <button
                onClick={() => setThemeDropdownOpen(!themeDropdownOpen)}
                className={`px-2 py-1 ${config.bg} border ${config.border} rounded ${config.text} text-xs hover:opacity-80 transition-colors font-mono`}

              >
                [THEME]
              </button>
              {themeDropdownOpen && (
                <div className={`absolute top-full right-0 mt-1 ${config.bg} border ${config.border} rounded shadow-2xl z-20 overflow-hidden`}>
                  <button
                    onClick={() => {
                      setTheme("emerald");
                      setThemeDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1 text-xs hover:opacity-80 transition-colors border-b ${config.border} font-mono ${theme === "emerald" ? "bg-green-600 text-black" : config.text}`}
                  >
                    HECKER
                  </button>
                  <button
                    onClick={() => {
                      setTheme("white");
                      setThemeDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1 text-xs hover:opacity-80 transition-colors border-b ${config.border} font-mono ${theme === "white" ? "bg-gray-900 text-white" : config.text}`}
                  >
                    WHITE
                  </button>
                  <button
                    onClick={() => {
                      setTheme("black");
                      setThemeDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1 text-xs hover:opacity-80 transition-colors font-mono ${theme === "black" ? "bg-gray-300 text-black" : config.text}`}
                  >
                    BLACK
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {showAnalytics && (
        <div className={`h-100 p-4 bg-opacity-50 overflow-auto`}>
          <LogCountChart logs={filteredAndSortedLogs} timeRange={selectedTimeRange} theme={theme} />
        </div>
      )}
      <div className={`flex-1 flex flex-col overflow-hidden ${config.bg} relative`}>
        <div className={`flex-1 flex flex-col overflow-hidden border ${config.border} rounded-lg m-2 ${config.logRowBg}`}>
          {selectedSource === "drain" && filteredAndSortedLogs.length > 0 && (
            <div className={`px-3 py-4 flex justify-between items-center -mt-2`}>

              <span className={`text-xs font-mono ${config.accent}`}>
                Page {currentPage + 1} • {filteredAndSortedLogs.length} entries
              </span>
              <div className="flex items-center gap-2">
                <button
                  onMouseEnter={prefetchPreviousPage}
                  onClick={handlePrevPage}
                  disabled={currentPage === 0}
                  className={`px-2 py-0.5 border ${config.border} rounded hover:opacity-80 disabled:opacity-30 transition-colors ${config.text} text-xs font-mono`}
                >
                  PREV
                </button>
                <button
                  onMouseEnter={() => cursor && prefetchNextPage(cursor)}
                  onClick={handleNextPage}
                  disabled={!cursor}
                  className={`px-2 py-0.5 rounded hover:opacity-80 disabled:opacity-30 transition-colors font-bold ${config.activeBtn} text-xs font-mono`}
                >
                  NEXT
                </button>
              </div>
            </div>
          )}

          <div ref={parentRef} className={`flex-1 overflow-y-auto ${config.bg}`}>
            {filteredAndSortedLogs.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <div className={`${config.accent} text-xs space-y-1 font-mono`}>
                  <div>$ no_logs_found --search</div>
                  <div className="opacity-50">✗ No results matching your query</div>
                </div>
              </div>
            ) : (
              <div style={{ height: `${rowVirtualizer.getTotalSize()}px`, position: "relative" }}>
                {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                  const log = filteredAndSortedLogs[virtualRow.index];
                  const isExpanded = expandedLogs.has(virtualRow.index);

                  return (
                    <div
                      key={virtualRow.key}
                      data-index={virtualRow.index}
                      ref={rowVirtualizer.measureElement}
                      style={{
                        position: "absolute",
                        top: 0,
                        left: 0,
                        width: "100%",
                        transform: `translateY(${virtualRow.start}px)`,
                        willChange: 'transform',
                        contain: 'layout style paint',
                      }}
                    >
                      <TableLogRow
                        log={log}
                        isExpanded={isExpanded}
                        onToggle={() => toggleLogExpansion(virtualRow.index)}
                        onViewJson={openJsonPart}
                        theme={theme}
                      />
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
      <JsonPart isOpen={jsonModal.isOpen} onClose={closeJsonPart} rawMsg={jsonModal.rawMsg} theme={theme} />

    </div>
  );
}
