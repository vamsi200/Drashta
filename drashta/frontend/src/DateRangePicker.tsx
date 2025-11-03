import { useState, useRef, useEffect } from "react";
import { THEME_CONFIG, type ThemeType } from "./test";

interface DateRangePickerProps {
  isOpen: boolean;
  onClose: () => void;
  onApply: (mode: 'relative' | 'absolute', value: number | { start: Date; end: Date }) => void;
  selectedRange: number;
  theme?: ThemeType;
}

const LIFETIME_VALUE = 999999999;

const QUICK_RANGES = [
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

export default function DateRangePicker({
  isOpen,
  onClose,
  onApply,
  selectedRange,
  theme = 'emerald',
}: DateRangePickerProps) {
  const [mode, setMode] = useState<"relative" | "absolute">("relative");
  const [startDate, setStartDate] = useState<string>("");
  const [endDate, setEndDate] = useState<string>("");
  const dropdownRef = useRef<HTMLDivElement>(null);
  const themeClasses = THEME_CONFIG[theme];

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        onClose();
      }
    }

    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleQuickSelect = (value: number) => {
    onApply("relative", value);
    onClose();
  };

  const handleCustomApply = () => {
    if (!startDate || !endDate) return;

    const start = new Date(startDate);
    const end = new Date(endDate);

    if (start >= end) {
      alert("Start date must be before end date");
      return;
    }

    onApply("absolute", { start, end });
    onClose();
  };

  return (
    <div
      ref={dropdownRef}
      className={`absolute top-full right-0 mt-2 ${themeClasses.bg} border ${themeClasses.border} rounded-lg shadow-2xl z-50 w-[450px] max-w-[90vw]`}
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex h-[380px]">
        <div className={`w-[160px] border-r ${themeClasses.border} overflow-y-auto ${themeClasses.bg} opacity-80`}>
          {QUICK_RANGES.map((range) => (
            <button
              key={range.value}
              className={`w-full px-3 py-2 text-left text-xs transition-colors border-b ${themeClasses.border} ${selectedRange === range.value
                ? `${themeClasses.activeBtn} font-semibold`
                : `${themeClasses.accent} ${themeClasses.hover}`
                }`}
              onClick={() => handleQuickSelect(range.value)}
            >
              {range.label}
            </button>
          ))}
        </div>

        <div className={`flex-1 p-4 flex flex-col ${themeClasses.bg}`}>
          <div className="mb-4">
            <div className="flex gap-2 mb-4">
              <button
                onClick={() => setMode("relative")}
                className={`flex-1 px-2 py-1.5 rounded text-xs font-medium transition ${mode === "relative"
                  ? themeClasses.activeBtn
                  : `${themeClasses.text} border ${themeClasses.border} ${themeClasses.hover}`
                  }`}
              >
                Quick
              </button>
              <button
                onClick={() => setMode("absolute")}
                className={`flex-1 px-2 py-1.5 rounded text-xs font-medium transition ${mode === "absolute"
                  ? themeClasses.activeBtn
                  : `${themeClasses.text} border ${themeClasses.border} ${themeClasses.hover}`
                  }`}
              >
                Custom
              </button>
            </div>
          </div>

          {mode === "absolute" ? (
            <div className="space-y-3 flex-1">
              <div>
                <label className={`text-xs ${themeClasses.accent} block mb-1`}>From</label>
                <input
                  type="datetime-local"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className={`w-full px-2 py-1.5 ${themeClasses.modalBg} border ${themeClasses.border} rounded text-xs ${themeClasses.text} focus:outline-none focus:ring-1 ${themeClasses.border}`}
                />
              </div>
              <div>
                <label className={`text-xs ${themeClasses.accent} block mb-1`}>To</label>
                <input
                  type="datetime-local"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className={`w-full px-2 py-1.5 ${themeClasses.modalBg} border ${themeClasses.border} rounded text-xs ${themeClasses.text} focus:outline-none focus:ring-1 ${themeClasses.border}`}
                />
              </div>
              <div className="flex-1" />
              <div className={`flex gap-2 pt-3 border-t ${themeClasses.border}`}>
                <button
                  onClick={onClose}
                  className={`flex-1 px-2 py-1.5 text-xs ${themeClasses.text} border ${themeClasses.border} rounded ${themeClasses.hover} transition`}
                >
                  Cancel
                </button>
                <button
                  onClick={handleCustomApply}
                  className={`flex-1 px-2 py-1.5 text-xs ${themeClasses.activeBtn} rounded font-medium hover:opacity-80 transition`}
                >
                  Apply
                </button>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center flex-1">
              <p className={`text-xs ${themeClasses.accent} opacity-50`}>Select from quick options</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
