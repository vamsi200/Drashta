import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

type EventData = {
  timestamp: string;
  service: string;
  event_type: string;
  data: Record<string, string>;
  raw_msg: string;
};

type SortDirection = "asc" | "desc" | null;
type EventSourceType = "drain" | "live";

const SERVICES = [
  "All",
  "Sshd",
  "Sudo",
  "Login",
  "Kernel",
  "Pkg",
  "Firewall",
  "Network",
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
    <div className="flex items-center bg-gray-700/20 rounded-lg border border-gray-600/40 p-1 gap-1">
      <button
        onClick={() => onSourceChange("drain")}
        className={`flex-1 px-3 py-1.5 text-sm rounded-md transition-all flex items-center justify-center gap-2 ${selectedSource === "drain"
          ? "bg-blue-600 text-white border border-blue-500/50"
          : "text-gray-300 hover:bg-gray-600/30 border border-transparent"
          }`}
      >
        <div className="w-2 h-2 rounded-full bg-gray-400"></div>
        <span>Drain ({drainCount.toLocaleString()})</span>
      </button>
      <button
        onClick={() => onSourceChange("live")}
        className={`flex-1 px-3 py-1.5 text-sm rounded-md transition-all flex items-center justify-center gap-2 ${selectedSource === "live"
          ? "bg-green-600 text-white border border-green-500/50"
          : "text-gray-300 hover:bg-gray-600/30 border border-transparent"
          }`}
      >
        <div className={`w-2 h-2 rounded-full ${selectedSource === "live" ? "bg-green-300 animate-pulse" : "bg-gray-400"}`}></div>
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
      className="absolute top-full left-0 mt-1 bg-[#141822] border border-gray-700/50 rounded shadow-lg z-20 min-w-[120px] max-h-48 overflow-y-auto custom-scrollbar"
    >
      <button
        className={`w-full text-left px-3 py-2 text-sm hover:bg-[#232a3c] transition-colors flex items-center gap-3 border-b border-gray-700/30 ${isAllSelected
          ? 'bg-blue-600 text-white'
          : 'text-gray-300'
          }`}
        onClick={() => onTypeToggle("All")}
      >
        <span className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${isAllSelected
          ? 'bg-blue-500 border-blue-400 text-white'
          : 'border-gray-600'
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
            className={`w-full text-left px-3 py-2 text-sm hover:bg-[#232a3c] transition-colors flex items-center gap-3 border-b border-gray-700/30 last:border-b-0 ${isSelected ? 'bg-blue-600 text-white' : 'text-gray-300'
              }`}
            onClick={() => onTypeToggle(type)}
          >
            <span className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${isSelected
              ? 'bg-blue-500 border-blue-400 text-white'
              : 'border-gray-600'
              }`}>
              {isSelected ? '✓' : ''}
            </span>
            <span className="truncate">{type}</span>
          </button>
        );
      })}

      {selectedTypes.length > 0 && (
        <button
          className="w-full text-left px-3 py-2 text-xs text-red-400 hover:bg-red-900/20 transition-colors border-t border-gray-700/30"
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
  logData
}: {
  isOpen: boolean;
  onClose: () => void;
  logData: EventData | null;
}) {
  if (!isOpen || !logData) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black bg-opacity-50 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative bg-[#141822] rounded-lg border border-gray-600/60 shadow-2xl max-w-4xl max-h-[80vh] w-full mx-4 flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-gray-600/40">
          <h3 className="text-lg font-semibold text-gray-200">Raw JSON Data</h3>
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-400 px-2 py-1 bg-gray-700/30 rounded border border-gray-600/30">
              {logData.service} • {logData.event_type}
            </span>
            <button
              onClick={onClose}
              className="p-1.5 rounded-md hover:bg-gray-700 text-gray-400 hover:text-gray-200 transition-colors border border-gray-600/30 hover:border-gray-500/50"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
        <div className="flex-1 overflow-auto p-4">
          <pre className="bg-[#0c0f16] text-xs text-gray-300 p-4 rounded border border-gray-700/40 overflow-auto">
            {JSON.stringify(logData, null, 2)}
          </pre>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-gray-600/40">
          <button
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(logData, null, 2));
            }}
            className="px-3 py-1.5 text-xs bg-gray-600 hover:bg-gray-500 text-gray-200 rounded transition-colors border border-gray-500/50"
          >
            Copy JSON
          </button>
          <button
            onClick={onClose}
            className="px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 text-gray-200 rounded transition-colors border border-gray-600/50"
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
    return Date.now() + logIndex * 1000; // is this a good way??
  }
};

export default function Dashboard() {
  const [drainLogs, setDrainLogs] = useState<EventData[]>([]);
  const [liveLogs, setLiveLogs] = useState<EventData[]>([]);
  const [selectedSource, setSelectedSource] = useState<EventSourceType>("drain");
  const [selectedService, setSelectedService] = useState("All");
  const [selectedType, setSelectedType] = useState<string[]>([]);
  const [currentEventSource, setCurrentEventSource] = useState<EventSource | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [jsonModal, setJsonPart] = useState<{ isOpen: boolean; logData: EventData | null }>({
    isOpen: false,
    logData: null
  });
  const [typeDropdownOpen, setEventTypeDropdownOpen] = useState(false);
  const [sortDirection, setSortDirection] = useState<SortDirection>(null);
  const parentRef = useRef<HTMLDivElement>(null);

  const searchInputRef = useRef<HTMLInputElement>(null);
  // Sidebar
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(256);
  const [isResizingSidebar, setIsResizingSidebar] = useState(false);
  const sidebarResizeRef = useRef({
    isResizing: false,
    startX: 0,
    startWidth: 256
  });

  // Column widths
  const [columnWidths, setColumnWidths] = useState({
    timestamp: 160,
    service: 90,
    type: 130,
    message: 400
  });
  const [resizing, setResizing] = useState<{ column: string; startX: number; startWidth: number } | null>(null);

  const currentLogs = selectedSource === "drain" ? drainLogs : liveLogs;

  const availableTypes = useMemo(() => {
    let relevantLogs = currentLogs;

    if (selectedService !== "All") {
      relevantLogs = currentLogs.filter(log => log.service === selectedService);
    }

    const uniqueTypes = [...new Set(relevantLogs.map(log => log.event_type))].sort();
    return ["All", ...uniqueTypes];
  }, [currentLogs, selectedService]);

  useEffect(() => {
    if (selectedType.length > 0 &&
      !selectedType.every(type => availableTypes.includes(type))) {
      setSelectedType([]);
    }
  }, [availableTypes, selectedType]);

  const handleGlobalKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.target === searchInputRef.current || e.ctrlKey || e.altKey || e.metaKey) {
      return;
    }

    if (e.shiftKey && e.key.toLowerCase() === 's') {
      e.preventDefault();
      searchInputRef.current?.focus();
      return;
    }

    if (e.key === '/') {
      e.preventDefault();
      searchInputRef.current?.focus();
      return;
    }
  }, []);

  useEffect(() => {
    document.addEventListener('keydown', handleGlobalKeyDown);
    return () => {
      document.removeEventListener('keydown', handleGlobalKeyDown);
    };
  }, [handleGlobalKeyDown]);

  const toggleTypeSelection = useCallback((type: string) => {
    setSelectedType(prev => {
      if (type === "All") {
        return [];
      }

      if (prev.includes(type)) {
        return prev.filter(t => t !== type);
      } else {
        return [...prev, type];
      }
    });
  }, []);

  // Close existing connection and clear the logs for every new conn
  useEffect(() => {
    if (currentEventSource) {
      currentEventSource.close();
      setCurrentEventSource(null);
    }

    if (selectedSource === "drain") {
      setDrainLogs([]);
    } else {
      setLiveLogs([]);
    }

    const endpoint = selectedSource === "drain" ? "drain" : "live";
    const eventName = selectedService === "All" ? "pkg.events" : `${selectedService.toLowerCase()}.events`;

    const es = new EventSource(`http://localhost:3200/${endpoint}?event_name=${eventName}`);
    setCurrentEventSource(es);

    es.onmessage = (event) => {
      try {
        const parsed: EventData = JSON.parse(event.data);

        //TODO: Have to rethink below approach!
        if (selectedSource === "drain") {
          setDrainLogs((prev) => [...prev, parsed]);
        } else {
          setLiveLogs((prev) => {
            const updated = [...prev, parsed];
            return updated.length > 1000 ? updated.slice(-1000) : updated;
          });
        }
      } catch (e) {
        console.error(`Failed to parse ${selectedSource} the event:`, e);
      }
    };

    es.onerror = (err) => {
      console.error(`${selectedSource} EventSource failed:`, err);
      es.close();
    };

    return () => {
      es.close();
    };
  }, [selectedSource, selectedService]);

  const filteredAndSortedLogs = useMemo(() => {
    let filtered = currentLogs.filter((log) => {
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
      return true;
    });

    if (sortDirection) {
      filtered = [...filtered].sort((a, b) => {
        const indexA = filtered.indexOf(a);
        const indexB = filtered.indexOf(b);
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
  }, [currentLogs, selectedService, selectedType, searchTerm, sortDirection]);

  //TODO: Need to change below as well
  const getEventColor = (eventType: string) => {
    const type = eventType.toLowerCase();
    if (type.includes("error")) return "text-red-400";
    if (type.includes("warn")) return "text-yellow-400";
    if (type.includes("info")) return "text-blue-400";
    return "text-green-400";
  };

  const handleTimestampSort = () => {
    if (sortDirection === null) {
      setSortDirection("desc");
    } else if (sortDirection === "desc") {
      setSortDirection("asc");
    } else {
      setSortDirection(null);
    }
  };

  const rowVirtualizer = useVirtualizer({
    count: filteredAndSortedLogs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 10,
  });

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

  // should I keep both??
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

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!resizing) return;
    const diff = e.clientX - resizing.startX;
    const newWidth = Math.max(50, resizing.startWidth + diff);
    setColumnWidths(prev => ({
      ...prev,
      [resizing.column]: newWidth
    }));
  }, [resizing]);

  const handleMouseUp = useCallback(() => {
    setResizing(null);
  }, []);

  useEffect(() => {
    if (isResizingSidebar || resizing) {
      const moveHandler = isResizingSidebar ? handleSidebarMouseMove : handleMouseMove;
      const upHandler = isResizingSidebar ? handleSidebarMouseUp : handleMouseUp;

      document.addEventListener('mousemove', moveHandler);
      document.addEventListener('mouseup', upHandler);

      if (isResizingSidebar || resizing) {
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
      }
    } else {
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }

    return () => {
      document.removeEventListener('mousemove', handleSidebarMouseMove);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleSidebarMouseUp);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isResizingSidebar, resizing, handleSidebarMouseMove, handleSidebarMouseUp, handleMouseMove, handleMouseUp]);

  const handleResizeStart = (column: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setResizing({
      column,
      startX: e.clientX,
      startWidth: columnWidths[column as keyof typeof columnWidths]
    });
  };

  const openJsonPart = (logData: EventData, e: React.MouseEvent) => {
    e.stopPropagation();
    setJsonPart({ isOpen: true, logData });
  };

  const closeJsonPart = () => {
    setJsonPart({ isOpen: false, logData: null });
  };

  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  return (
    <>
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }
        
        .custom-scrollbar::-webkit-scrollbar-track {
          background: #1a1f2e;
          border-radius: 4px;
          border: 1px solid rgba(75, 85, 99, 0.2);
        }
        
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #4a5568;
          border-radius: 4px;
          border: 1px solid #2d3748;
        }
        
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #5a6c7d;
        }
        .custom-scrollbar {
          scrollbar-width: thin;
          scrollbar-color: #4a5568 #1a1f2e;
        }
      `}</style>

      <div className="flex h-screen bg-[#0c0f16] text-gray-200 font-mono overflow-hidden border border-gray-800/40">
        <div
          className={`flex flex-shrink-0 transition-all duration-300 ${sidebarCollapsed ? 'w-0' : ''
            }`}
          style={{ width: sidebarCollapsed ? '0px' : `${sidebarWidth}px` }}
        >
          <div className={`bg-[#141822] border-r border-gray-700/50 flex flex-col flex-1 ${sidebarCollapsed ? 'overflow-hidden' : ''
            }`}>
            <div className="p-4 border-b border-gray-700/40">
              <h1 className="text-lg font-semibold text-blue-400 whitespace-nowrap">Drashta</h1>
            </div>

            <div className="p-4 border-b border-gray-700/40">
              <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3 whitespace-nowrap">
                Event Source
              </h2>
              <EventSourceToggle
                selectedSource={selectedSource}
                onSourceChange={handleSourceChange}
                drainCount={drainLogs.length}
                liveCount={liveLogs.length}
              />
            </div>

            <div className="flex-1 p-4 space-y-4 overflow-y-auto custom-scrollbar">
              <div>
                <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3 whitespace-nowrap border-b border-gray-700/30 pb-2">
                  Services
                </h2>
                <div className="space-y-1">
                  {SERVICES.map((svc) => (
                    <button
                      key={svc}
                      className={`w-full text-left px-3 py-2 rounded text-sm transition-all whitespace-nowrap border border-transparent ${selectedService === svc
                        ? "bg-blue-600 text-white border-blue-500/50"
                        : "text-gray-300 hover:bg-[#232a3c] hover:text-white hover:border-gray-600/40"
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
              className="w-1 bg-gray-700/60 hover:bg-blue-400 cursor-col-resize transition-colors flex-shrink-0 relative group border-r border-gray-600/30"
              onMouseDown={handleSidebarMouseDown}
            >
              <div className="absolute inset-y-0 -left-1 -right-1 group-hover:bg-blue-400 group-hover:opacity-20 transition-all" />
            </div>
          )}
        </div>

        {/* Main Part */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <div className="bg-[#141822] border-b border-gray-700/50 px-6 py-4 flex-shrink-0">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-6">
                <button
                  onClick={toggleSidebar}
                  className="p-2 rounded-md hover:bg-gray-700 transition-colors group border border-gray-600/30 hover:border-gray-500/50"
                  aria-label="Toggle sidebar"
                >
                  <div className="w-5 h-4 flex flex-col justify-between">
                    <span className="block h-0.5 bg-gray-400 group-hover:bg-gray-200 transition-colors"></span>
                    <span className="block h-0.5 bg-gray-400 group-hover:bg-gray-200 transition-colors"></span>
                    <span className="block h-0.5 bg-gray-400 group-hover:bg-gray-200 transition-colors"></span>
                  </div>
                </button>

                {/*TODO: Need to think whether to keep these*/}
                <div className="text-sm px-2 py-1 bg-gray-700/20 rounded border border-gray-600/30">
                  <span className="text-gray-400">Total: </span>
                  <span className="text-green-400 font-semibold">{filteredAndSortedLogs.length.toLocaleString()}</span>
                </div>
                <div className="text-sm px-2 py-1 bg-gray-700/20 rounded border border-gray-600/30">
                  <span className="text-gray-400">Errors: </span>
                  <span className="text-red-400 font-semibold">
                    {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "error").length.toLocaleString()}
                  </span>
                </div>
                <div className="text-sm px-2 py-1 bg-gray-700/20 rounded border border-gray-600/30">
                  <span className="text-gray-400">Failures: </span>
                  <span className="text-red-400 font-semibold">
                    {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "failure").length.toLocaleString()}
                  </span>
                </div>

                <div className="text-sm px-2 py-1 bg-gray-700/20 rounded border border-gray-600/30">
                  <span className="text-gray-400">Warnings: </span>
                  <span className="text-yellow-400 font-semibold">
                    {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "warn").length.toLocaleString()}
                  </span>
                </div>
                <div className="text-sm px-2 py-1 bg-gray-700/20 rounded border border-gray-600/30">
                  <span className="text-gray-400">Info: </span>
                  <span className="text-blue-400 font-semibold">
                    {filteredAndSortedLogs.filter((l) => l.event_type.toLowerCase() === "info").length.toLocaleString()}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <button
                  onClick={clearCurrentLogs}
                  className="px-3 py-1.5 text-xs bg-red-600/80 hover:bg-red-600 text-white rounded transition-colors border border-red-500/50"
                >
                  Clear Logs
                </button>
                <div className="text-xs text-gray-500 px-2 py-1 bg-gray-700/20 rounded border border-gray-600/30">
                  Source: <span className={selectedSource === "drain" ? "text-blue-400" : "text-green-400"}>
                    {selectedSource === "drain" ? "Drain" : "Live"}
                  </span>
                  <span className="ml-2">
                    • Service: <span className="text-blue-400">{selectedService}</span>
                  </span>
                  {selectedType.length > 0 && (
                    <span className="ml-2">
                      • Types: <span className="text-blue-400">
                        {selectedType.length > 2
                          ? `${selectedType.length} selected`
                          : selectedType.join(', ')
                        }
                      </span>
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="flex-1 m-4 bg-[#10131b] rounded-lg overflow-hidden flex flex-col min-h-0 border border-gray-700/50">
            <div className="p-3 border-b border-gray-700/40 flex-shrink-0">
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Type 'S' or '/' to search logs"
                className="w-full bg-[#1b2130] text-sm px-3 py-2 rounded border border-gray-600/60 focus:outline-none focus:border-blue-500/70 text-gray-200"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <div className="bg-[#141822] border-b border-gray-600/50 flex-shrink-0">
              <div className="flex text-xs font-medium text-gray-300 uppercase tracking-wide">
                <div
                  className="flex-shrink-0 relative group cursor-pointer select-none flex items-center px-3 py-3 border-r border-gray-700/40"
                  style={{ width: `${columnWidths.timestamp}px` }}
                  onClick={handleTimestampSort}
                >
                  <div className="flex items-center gap-1">
                    <span>Timestamp</span>
                    <div className="flex flex-col">
                      <div className={`text-xs leading-none ${sortDirection === 'asc' ? 'text-blue-400' : 'text-gray-500'}`}>▲</div>
                      <div className={`text-xs leading-none ${sortDirection === 'desc' ? 'text-blue-400' : 'text-gray-500'}`}>▼</div>
                    </div>
                  </div>
                  <div
                    className="absolute right-0 top-0 h-full w-2 cursor-col-resize bg-blue-400 opacity-0 hover:opacity-100 transition-opacity"
                    onMouseDown={(e) => {
                      e.stopPropagation();
                      handleResizeStart('timestamp', e);
                    }}
                  />
                </div>

                <div
                  className="flex-shrink-0 relative group flex items-center px-3 py-3 border-r border-gray-700/40"
                  style={{ width: `${columnWidths.service}px` }}
                >
                  <span>Service</span>
                  <div
                    className="absolute right-0 top-0 h-full w-2 cursor-col-resize bg-blue-400 opacity-0 hover:opacity-100 transition-opacity"
                    onMouseDown={(e) => handleResizeStart('service', e)}
                  />
                </div>

                <div
                  className="flex-shrink-0 relative group cursor-pointer flex items-center px-3 py-3 border-r border-gray-700/40"
                  style={{ width: `${columnWidths.type}px` }}
                  onClick={() => setEventTypeDropdownOpen(!typeDropdownOpen)}
                >
                  <div className="flex items-center gap-1">
                    <span>Type</span>
                    <span className="text-gray-500">▼</span>
                    {selectedType.length > 0 ? (
                      <span className="text-xs text-blue-400">
                        ({selectedType.length} {selectedType.length === 1 ? 'selected' : 'selected'})
                      </span>
                    ) : (
                      availableTypes.length > 1 && (
                        <span className="text-xs text-gray-500">({availableTypes.length - 1})</span>
                      )
                    )}
                  </div>
                  <div
                    className="absolute right-0 top-0 h-full w-2 cursor-col-resize bg-blue-400 opacity-0 hover:opacity-100 transition-opacity"
                    onMouseDown={(e) => {
                      e.stopPropagation();
                      handleResizeStart('type', e);
                    }}
                  />
                  <EventTypeDropdown
                    selectedTypes={selectedType}
                    onTypeToggle={toggleTypeSelection}
                    isOpen={typeDropdownOpen}
                    onToggle={() => setEventTypeDropdownOpen(false)}
                    availableTypes={availableTypes}
                  />
                </div>

                <div
                  className="flex-1 flex items-center px-3 py-3 border-r border-gray-700/40"
                  style={{ minWidth: `${columnWidths.message}px` }}
                >
                  <span>Message</span>
                </div>

                <div className="w-16 flex-shrink-0 flex items-center justify-center px-3 py-3">
                  <span>Actions</span>
                </div>
              </div>
            </div>

            <div ref={parentRef} className="flex-1 overflow-auto custom-scrollbar">
              {filteredAndSortedLogs.length === 0 ? (
                <div className="flex items-center justify-center h-full text-gray-500">
                  <div className="text-center p-6 border border-gray-700/30 rounded-lg bg-gray-800/20">
                    <div className="text-4xl mb-2"></div>
                    <div>No logs found</div>
                    <div className="text-sm text-gray-600 mt-1">
                      {selectedService !== "All" && availableTypes.length === 1
                        ? `No event types available for ${selectedService}`
                        : "Try adjusting your filters or wait for new events"
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

                    return (
                      <div
                        key={virtualRow.key}
                        className="absolute left-0 right-0"
                        style={{
                          transform: `translateY(${virtualRow.start}px)`,
                          height: `${virtualRow.size}px`,
                        }}
                      >
                        <div className="flex hover:bg-[#161b28] transition-colors h-full items-center border-b border-gray-800/30 hover:border-gray-700/50">
                          <div
                            className="flex-shrink-0 px-3 py-2 text-sm border-r border-gray-800/30 flex items-center"
                            style={{ width: `${columnWidths.timestamp}px` }}
                          >
                            <div className="text-gray-500 truncate">
                              {log.timestamp}
                            </div>
                          </div>

                          <div
                            className="flex-shrink-0 px-3 py-2 text-sm border-r border-gray-800/30 flex items-center"
                            style={{ width: `${columnWidths.service}px` }}
                          >
                            <div className="text-gray-300 truncate">
                              {log.service}
                            </div>
                          </div>

                          <div
                            className="flex-shrink-0 px-3 py-2 text-sm border-r border-gray-800/30 flex items-center"
                            style={{ width: `${columnWidths.type}px` }}
                          >
                            <div className={`${getEventColor(log.event_type)} truncate font-medium`}>
                              {log.event_type}
                            </div>
                          </div>

                          <div
                            className="flex-1 px-3 py-2 text-sm border-r border-gray-800/30 flex items-center"
                            style={{ minWidth: `${columnWidths.message}px` }}
                          >
                            <div className="text-gray-200 truncate">
                              {log.raw_msg}
                            </div>
                          </div>

                          <div className="w-16 flex-shrink-0 flex items-center justify-center px-3 py-2">
                            <button
                              onClick={(e) => openJsonPart(log, e)}
                              className="px-1 py-0.5 text-xs bg-gray-600 hover:bg-gray-500 text-gray-200 rounded transition-colors border border-gray-500/50"
                            >
                              JSON
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        <JsonPart
          isOpen={jsonModal.isOpen}
          onClose={closeJsonPart}
          logData={jsonModal.logData}
        />
      </div>
    </>
  );
}
