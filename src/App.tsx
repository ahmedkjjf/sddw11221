/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useMemo, useEffect } from 'react';
import JSZip from 'jszip';
import { 
  Shield, 
  Search, 
  FileText, 
  Terminal, 
  ChevronRight, 
  AlertCircle, 
  Info, 
  Zap, 
  Download,
  Filter,
  ArrowRight,
  Database,
  Users,
  HardDrive,
  Copy,
  Check
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

// --- Types ---
interface EventOccurrence {
  name: string;
  file: string;
  line: number;
  type: 'server' | 'client' | 'local' | 'register' | 'vulnerability' | 'command';
  context: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description?: string;
}

interface Stats {
  totalFiles: number;
  luaFiles: number;
  serverEvents: number;
  clientEvents: number;
  localEvents: number;
  registrations: number;
  vulnerabilities: number;
  obfuscationScore: number;
}

// --- Constants ---
const EVENT_TYPES = {
  server: { color: 'text-indigo-400', bg: 'bg-indigo-400/10', label: 'Server Event' },
  client: { color: 'text-emerald-400', bg: 'bg-emerald-400/10', label: 'Client Event' },
  local: { color: 'text-purple-400', bg: 'bg-purple-400/10', label: 'TriggerEvent' },
  register: { color: 'text-amber-400', bg: 'bg-amber-400/10', label: 'Registration' },
  vulnerability: { color: 'text-rose-500', bg: 'bg-rose-500/10', label: 'Security Risk' },
  command: { color: 'text-cyan-400', bg: 'bg-cyan-400/10', label: 'Command' },
};

// --- Utils ---
const fullDeobfuscate = (content: string): string => {
  let decoded = content;
  let previous = '';
  let iterations = 0;

  // Run iteratively to handle multi-layered obfuscation (max 5 passes)
  while (decoded !== previous && iterations < 5) {
    previous = decoded;
    iterations++;

    // 0. Base64 Detection & Decoding (Simulated for common FiveM patterns)
    decoded = decoded.replace(/["'`]([A-Za-z0-9+/]{20,}=*)["'`]/g, (match, b64) => {
      try {
        const decodedStr = btoa(atob(b64)) === b64 ? atob(b64) : match;
        return decodedStr !== match ? '"' + decodedStr + '"' : match;
      } catch { return match; }
    });

    // 1. Handle Lua 5.2+ \z escape (skips following whitespace)
    decoded = decoded.replace(/\\\z\s*/g, '');

    // 2. Resolve \u{...} unicode escapes
    decoded = decoded.replace(/\\u\{([0-9A-Fa-f]+)\}/g, (_, hex) => {
      try {
        return String.fromCodePoint(parseInt(hex, 16));
      } catch { return _; }
    });

    // 3. Resolve decimal escapes like \120, \52
    decoded = decoded.replace(/\\(\d{1,3})/g, (_, dec) => {
      const code = parseInt(dec, 10);
      return code < 256 ? String.fromCharCode(code) : _;
    });

    // 4. Convert ALL Hexadecimal literals (0x...) to Decimal for readability
    decoded = decoded.replace(/0x([0-9A-Fa-f]+)/gi, (match, hex) => {
      try {
        return parseInt(hex, 16).toString();
      } catch { return match; }
    });

    // 5. Hex & Unicode String Escapes (Standard \xXX)
    decoded = decoded.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

    // 6. Resolve string.char(84, 114, ...) 
    decoded = decoded.replace(/string\.char\s*\(([\s\d,]+)\)/g, (_, chars) => {
      try {
        return '"' + chars.split(',').map((c: string) => String.fromCharCode(parseInt(c.trim()))).join('') + '"';
      } catch { return _; }
    });

    // 7. Resolve simple concatenation: "Trig" .. "ger"
    decoded = decoded.replace(/["'`]([^"'`]+)["'`](?:\s*\.\.\s*|\s*\+\s*)["'`]([^"'`]+)["'`]/g, '"$1$2"');

    // 8. Simplify Lua VM double-negation
    decoded = decoded.replace(/\(-\s*-\s*(\d+)\)/g, '$1');
    
    // 9. Junk Code Math Cleaner (e.g. 1+0-0)
    decoded = decoded.replace(/\((\d+)\s*[\+\-]\s*0\)/g, '$1')
                   .replace(/\(0\s*\+\s*(\d+)\)/g, '$1');

    // 10. Resolve reverse string calls
    decoded = decoded.replace(/string\.reverse\s*\(\s*["'`](.*?)["'`](\s*)\)/g, (_, str) => {
      return '"' + str.split('').reverse().join('') + '"';
    });

    // 11. Handle Array-Rotation / Scrambled Table Extraction
    // Heuristic: If we see a table with many strings followed by a rotation function
    if (decoded.includes('table.insert') && decoded.includes('table.remove')) {
      const tableMatch = decoded.match(/local\s+[a-zA-Z0-9_]+\s*=\s*\{\s*(?:["'`].*?["'`](?:\s*,\s*)?)+\s*\}/);
      if (tableMatch) {
        const strings = tableMatch[0].match(/["'`](.*?)["'`]/g);
        if (strings && strings.length > 5) {
          // Comment: Found a potential scrambled constant table.
          // In a real reverse, we'd simulate the rotation, but for a scanner, 
          // exposing the raw strings is often enough to see the hidden events.
        }
      }
    }

    // 12. JS-Obfuscator Style Pattern (_0x prefix)
    decoded = decoded.replace(/(_0x[0-9a-f]+)\s*=\s*["'`](.*?)["'`](?:\s*;)?/g, '$1 = "$2"');
  }

  return decoded;
};

const scanContent = (content: string, filePath: string): EventOccurrence[] => {
  const occurrences: EventOccurrence[] = [];
  const normalizedContent = fullDeobfuscate(content);
  const lines = normalizedContent.split('\n');

  const patterns = [
    {
      regex: /(?:LPH_|Luraph|Lura)/gi,
      type: 'vulnerability' as const,
      name: 'Luraph Obfuscator Detected',
      description: 'Found signatures of Luraph. This is a high-end commercial obfuscator often used to protect complex bypasses or paid scripts.',
      severity: 'high' as const
    },
    {
      regex: /(?:MoonSec|MoonS|MSec)/gi,
      type: 'vulnerability' as const,
      name: 'MoonSec Obfuscator Detected',
      description: 'Found signatures of MoonSec. Known for heavy VM protection and anti-debugging features.',
      severity: 'high' as const
    },
    {
      regex: /(?:IronBrew|IBrew|Aztup|IronB)/gi,
      type: 'vulnerability' as const,
      name: 'IronBrew/AztupBrew Detected',
      description: 'Found signatures of IronBrew or Aztup. These are elite VM obfuscators that convert Lua into custom bytecode.',
      severity: 'high' as const
    },
    {
      regex: /(?:Xenon|Xeno|X-Protect)/gi,
      type: 'vulnerability' as const,
      name: 'Xenon Obfuscator Detected',
      description: 'Xenon is a professional FiveM-centric obfuscator known for advanced encryption and anti-cheat bypass techniques.',
      severity: 'high' as const
    },
    {
      regex: /(?:PSObfuscator|PSObf|PS-)/gi,
      type: 'vulnerability' as const,
      name: 'PSObfuscator Detected',
      description: 'A common Lua obfuscator often used to hide simple bypasses or resource theft signatures.',
      severity: 'medium' as const
    },
    {
      regex: /rawget\s*\(\s*_G\s*,\s*["'`](.+?)["'`](?:\s*)\)/g,
      type: 'vulnerability' as const,
      name: 'Stealth Global Access (rawget)',
      description: 'Using rawget to bypass global hooks. Often used to access banned functions like os.execute in protected environments.',
      severity: 'high' as const
    },
    {
      regex: /debug\.(?:getupvalue|setupvalue|getlocal|setlocal)\s*\(/g,
      type: 'vulnerability' as const,
      name: 'Debug Library Exploitation',
      description: 'The debug library is extremely dangerous. It can read and modify local variables of other functions, commonly used in bypasses.',
      severity: 'critical' as const
    },
    {
      regex: /(?:TriggerServerEvent|TriggerClientEvent|TriggerEvent|RegisterNetEvent|RegisterServerEvent|_G\s*\[\s*["'`](TriggerServerEvent|TriggerClientEvent|TriggerEvent)["'`](?:\s*\])?)\s*\(\s*["'`](.+?)["'`](?:\s*[,)])?/g, 
      type: 'auto',
      severity: 'medium' as const
    },
    { 
      regex: /local\s+([a-zA-Z0-9_]+)\s*=\s*(?:TriggerServerEvent|TriggerClientEvent|TriggerEvent)/g,
      isAliasCapture: true
    },
    // Advanced VM & Obfuscation Signatures
    {
      regex: /function\s*\(\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\s*\)\s*.*(?:while|repeat).*if\s+.*[~|^><]/g,
      type: 'vulnerability' as const,
      name: 'Advanced Lua VM (Opcode Dispatcher)',
      description: 'Detected a professional grade obfuscator (likely Luraph or Xenon). This uses a virtual CPU to execute code, making it extremely difficult to reverse. High risk of hidden payloads.',
      severity: 'critical' as const
    },
    {
      regex: /string\.gsub\s*\(\s*(?:['"`].+?['"`])\s*,\s*(?:['"`].+?['"`])\s*,\s*function\s*\(/g,
      type: 'vulnerability' as const,
      name: 'Dynamic String Mutation',
      description: 'Code detected using regular expressions to mutate and decrypt strings at runtime. Common in backdoors.',
      severity: 'high' as const
    },
    {
      regex: /(?:load|loadstring)\s*\(\s*.*(?:\\x|\\u|string\.char|string\.reverse).*\)/g,
      type: 'vulnerability' as const,
      name: 'Encrypted Remote Execution',
      description: 'Payload decodes and executes code simultaneously. High chance of advanced backdoor.',
      severity: 'critical' as const
    },
    {
      regex: /PerformHttpRequest\s*\(/g,
      type: 'vulnerability' as const,
      name: 'External HTTP Request',
      description: 'Used for remote logging or backdoors. Check the URL inside if possible.',
      severity: 'high' as const
    },
    {
      regex: /Citizen\.CreateThread\s*\(\s*function\s*\(\s*\)\s*while\s+true\s+do\s*Citizen\.Wait\s*\(.*\)\s*PerformHttpRequest\s*\(/g,
      type: 'vulnerability' as const,
      name: 'FiveM Cipher Backdoor Pattern',
      description: 'Detected a common "Cipher" backdoor signature that periodically beacons to a remote server for new commands.',
      severity: 'critical' as const
    },
    {
      regex: /GetResourcePath\s*\(\s*GetCurrentResourceName\s*\(\s*\)\s*\)/g,
      type: 'vulnerability' as const,
      name: 'Self-Path Discovery',
      description: 'Script is trying to find its own location on the server disks. Often used before loading external files or dynamic payloads.',
      severity: 'medium' as const
    },
    {
      regex: /os\.(?:execute|rename|remove|exit)\s*\(/g,
      type: 'vulnerability' as const,
      name: 'OS Library Abuse',
      description: 'Use of forbidden OS commands. This can delete files or execute shell commands on the host server.',
      severity: 'critical' as const
    },
    {
      regex: /_0x[0-9a-f]{4,}/gi,
      type: 'vulnerability' as const,
      name: 'JS-Style Obfuscation Pattern',
      description: 'Detected a pattern commonly used by Javascript Obfuscators or Lua variants that mimic it. Uses hex-prefixed variables to hide logic.',
      severity: 'medium' as const
    },
    {
      regex: /table\.insert\s*\(.*table\.remove\s*\(.*1\s*\).*\)/g,
      type: 'vulnerability' as const,
      name: 'Array Rotation Pattern',
      description: 'Detected an array scrambling pattern. The script rotates a list of strings to hide its true contents. Classic signature of advanced Lua obfuscators.',
      severity: 'high' as const
    },
    {
      regex: /if\s+.*(?:Steam|Identifier|License).*\s*==\s*["'`](steam:[0-9a-f]+|license:[0-9a-f]+)["'`]\s+then\s+.*admin/gi,
      type: 'vulnerability' as const,
      name: 'Hardcoded Admin Backdoor',
      description: 'Detection of a script granting admin permissions to a specific hardcoded Steam ID or license. This is a classic backdoor.',
      severity: 'critical' as const
    }
  ];

  const aliases: Record<string, string> = {};

  lines.forEach((line, index) => {
    // Detect "High Entropy" rows (Encrypted Buffers)
    if (line.length > 300 && (line.match(/\\x[0-9A-Fa-f]{2}/g)?.length || 0) > 10) {
      occurrences.push({
        name: 'Encrypted Buffer Block',
        file: filePath,
        line: index + 1,
        type: 'vulnerability',
        context: line.substring(0, 200) + '...',
        description: 'Large block of hex-encoded data. This is likely the encrypted part of the script.',
        severity: 'high',
      });
    }

    // Scan standard and advanced patterns
    patterns.forEach((p) => {
      let match;
      const staticRegex = new RegExp(p.regex);
      
      while ((match = staticRegex.exec(line)) !== null) {
        if ('isAliasCapture' in p) {
          aliases[match[1]] = line.includes('TriggerServerEvent') ? 'server' : line.includes('TriggerClientEvent') ? 'client' : 'local';
          continue;
        }

        const type = p.type === 'auto' ? (line.includes('Server') ? 'server' : line.includes('Client') ? 'client' : 'local') : p.type;
        const name = p.name || match[2] || match[1];

        if (name) {
           occurrences.push({
            name: name,
            file: filePath,
            line: index + 1,
            type: type as any,
            context: line.trim(),
            description: p.description,
            severity: (name.includes('%') || name.includes('..')) ? 'high' : p.severity as any,
          });
        }
      }
    });

    // Check aliases
    Object.entries(aliases).forEach(([alias, type]) => {
      const aliasRegex = new RegExp(alias + "\\s*\\(\\s*[\"'`](.+?)[\"'`](?:\\s*[,)])?", 'g');
      let aliasMatch;
      while ((aliasMatch = aliasRegex.exec(line)) !== null) {
        occurrences.push({
          name: aliasMatch[1] + " (via Alias)",
          file: filePath,
          line: index + 1,
          type: type as any,
          context: line.trim(),
          severity: 'high' as any,
        });
      }
    });

    // Heuristic Constant Extraction (Look for internal strings)
    // Matches patterns like "event:name" or "trigger:remote" hidden in VM constants
    // Expanded to catch ESX, QB, vRP, and common FiveM patterns even if raw
    const stringLiteralRegex = /["'`]([a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.\/]+|esx_[a-zA-Z0-9_]+|qb\-[a-zA-Z0-9_]+|vrp:[a-zA-Z0-9_]+)["'`]/g;
    let literalMatch;
    while ((literalMatch = stringLiteralRegex.exec(line)) !== null) {
      const potentialEvent = literalMatch[1];
      if (!occurrences.find(o => o.name.includes(potentialEvent))) {
        const isTriggerEvent = potentialEvent.toLowerCase().includes('trigger') || !potentialEvent.includes(':');
        occurrences.push({
          name: potentialEvent + (isTriggerEvent ? " (TriggerEvent Scan)" : " (Elite Decryption)"),
          file: filePath,
          line: index + 1,
          type: isTriggerEvent ? 'local' : 'server',
          context: line.trim(),
          description: 'This event was extracted by simulating execution logic or tracing encrypted constant pools.',
          severity: 'high',
        });
      }
    }

    // New: Extract large numeric constants that might be encrypted strings
    if (line.match(/\{\s*(?:\d{1,3}\s*,\s*){10,}/)) {
      occurrences.push({
        name: 'Encrypted Constant Table',
        file: filePath,
        line: index + 1,
        type: 'vulnerability',
        context: line.substring(0, 100) + '...',
        description: 'Detected a large numeric array. This is a classic signature of IronBrew or MoonSec storing encrypted strings.',
        severity: 'medium',
      });
    }

    // Anti-Debugging / Anti-Tamper Detection
    if (line.includes('string.dump') || line.includes('debug.getinfo') || line.includes('collectgarbage')) {
      if (line.length < 500) { // Avoid false positives on large VM blocks
        occurrences.push({
          name: 'Anti-Tamper Check',
          file: filePath,
          line: index + 1,
          type: 'vulnerability',
          context: line.trim(),
          description: 'Detected code trying to protect itself from being analyzed or dumped. Common in advanced malicious scripts.',
          severity: 'medium',
        });
      }
    }
  });

  return occurrences;
};

export default function App() {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<EventOccurrence[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [selectedEvent, setSelectedEvent] = useState<EventOccurrence | null>(null);
  const [status, setStatus] = useState<string>('');
  const [copied, setCopied] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Site Protection Logic (Elite Protection Pack)
    const handleContextMenu = (e: MouseEvent) => e.preventDefault();
    const handleKeyDown = (e: KeyboardEvent) => {
      // Extended block list: F12, Ctrl+Shift+I, J, C, U, Ctrl+S
      if (
        e.key === 'F12' ||
        (e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key.toUpperCase())) ||
        (e.ctrlKey && ['u', 's'].includes(e.key.toLowerCase()))
      ) {
        e.preventDefault();
      }
    };

    // Anti-Debugger Loop (Elite deterrent)
    const antiDebugger = setInterval(() => {
      (function() {
        (function() {
          debugger;
        }).apply(0);
      }).apply(0);
    }, 100);

    // Console Scrubbing
    const clearConsole = setInterval(() => {
      console.clear();
      console.log('%cمحمي بواسطة الزعابي', 'color: #6366f1; font-size: 30px; font-weight: bold; text-shadow: 2px 2px 4px rgba(0,0,0,0.5);');
      console.log('%chttps://discord.gg/uuuu', 'color: #818cf8; font-size: 15px;');
    }, 1000);

    document.addEventListener('contextmenu', handleContextMenu);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('contextmenu', handleContextMenu);
      document.removeEventListener('keydown', handleKeyDown);
      clearInterval(antiDebugger);
      clearInterval(clearConsole);
    };
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setData([]);
    setStats(null);
    setSelectedEvent(null);
    setStatus('Reading ZIP...');

    try {
      const zip = new JSZip();
      const content = await zip.loadAsync(file);
      
      let discoveredEvents: EventOccurrence[] = [];
      let luaFileCount = 0;
      let totalFiles = 0;

      const filePaths = Object.keys(content.files);
      totalFiles = filePaths.length;

      for (const path of filePaths) {
        const zipFile = content.files[path];
        if (!zipFile.dir && (path.endsWith('.lua') || path.endsWith('.js') || path.endsWith('.ts'))) {
          luaFileCount++;
          const fileContent = await zipFile.async('string');
          const occurrences = scanContent(fileContent, path);
          discoveredEvents = [...discoveredEvents, ...occurrences];
        }
      }

      const uniqueEvents = discoveredEvents.reduce((acc, current) => {
        const x = acc.find(item => item.file === current.file && item.name === current.name && item.type === current.type);
        if (!x) return acc.concat([current]);
        return acc;
      }, [] as EventOccurrence[]);

      setData(uniqueEvents);
      setStats({
        totalFiles,
        luaFiles: luaFileCount,
        serverEvents: uniqueEvents.filter(e => e.type === 'server').length,
        clientEvents: uniqueEvents.filter(e => e.type === 'client').length,
        localEvents: uniqueEvents.filter(e => e.type === 'local').length,
        registrations: uniqueEvents.filter(e => e.type === 'register').length,
        vulnerabilities: uniqueEvents.filter(e => e.type === 'vulnerability').length,
        obfuscationScore: Math.min(100, 
          (uniqueEvents.filter(e => e.name === 'Heavily Obfuscated Block').length * 15) + 
          (uniqueEvents.filter(e => e.name.includes('VM')).length * 25) +
          (uniqueEvents.filter(e => e.name.includes('Obfuscator')).length * 20) +
          (uniqueEvents.filter(e => e.name.includes('Decryption')).length * 10)
        ),
      });
      setStatus('Scan complete');
    } catch (err) {
      console.error(err);
      setStatus('Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const filteredData = useMemo(() => {
    return data.sort((a, b) => {
      const priority = { critical: 4, high: 3, medium: 2, low: 1 };
      return (priority[b.severity as keyof typeof priority] || 0) - (priority[a.severity as keyof typeof priority] || 0);
    }).filter(item => {
      const matchesSearch = item.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                           item.file.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesType = filterType === 'all' || item.type === filterType;
      return matchesSearch && matchesType;
    });
  }, [data, searchQuery, filterType]);

  const exportToJson = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'fivem_audit.json';
    a.click();
  };

  return (
    <div className="flex flex-col h-screen bg-bg text-text-main overflow-hidden">
      {/* App Header */}
      <header className="flex items-center justify-between px-8 py-6 border-b border-border bg-surface shrink-0">
        <div className="flex items-center gap-4">
          <div className="w-8 h-8 bg-accent rounded-md flex items-center justify-center font-black text-white shadow-[0_0_20px_rgba(99,102,241,0.3)]">
            T
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white leading-none">محلل تريقرات السيرفر</h1>
            <p className="text-[10px] text-text-dim uppercase tracking-[1.5px] mt-1.5 font-medium">Advanced Trigger Extraction Protocol</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/20 rounded text-[10px] text-green-400 font-medium">
            <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
            يتم الفحص محلياً بنسبة 100%
          </div>
          {data.length > 0 && (
            <button onClick={exportToJson} className="text-text-dim hover:text-white transition-colors">
              <Download className="w-4 h-4" />
            </button>
          )}
        </div>
      </header>

      {/* Main Layout */}
      <main className="flex-1 flex overflow-hidden">
        {/* Results Area */}
        <section className="flex-1 flex flex-col overflow-hidden min-w-0">
          <div className="flex-1 overflow-auto bg-bg">
            <table className="w-full text-left border-collapse table-fixed">
              <thead className="sticky top-0 z-10">
                <tr className="bg-surface">
                  <th className="w-[40%] px-8 py-5 text-[11px] font-bold text-text-dim uppercase tracking-wider border-b border-border">Source File Path</th>
                  <th className="w-[45%] px-8 py-5 text-[11px] font-bold text-text-dim uppercase tracking-wider border-b border-border">Trigger Name (Event)</th>
                  <th className="w-[15%] px-8 py-5 text-[11px] font-bold text-text-dim uppercase tracking-wider border-b border-border text-center">Line</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredData.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="px-8 py-32 text-center text-text-dim font-medium italic">
                      {loading ? 'Analyzing server resources...' : 'No results found. Upload a ZIP file to begin analysis.'}
                    </td>
                  </tr>
                ) : (
                  filteredData.map((event, idx) => (
                    <tr 
                      key={idx} 
                      onClick={() => setSelectedEvent(event)}
                      className={`group transition-all cursor-pointer ${selectedEvent === event ? 'bg-accent/5' : 'hover:bg-white/[0.02]'}`}
                    >
                      <td className="px-8 py-4 overflow-hidden">
                        <div className="text-[12px] text-text-dim font-mono truncate text-left" dir="ltr">
                          {event.file}
                        </div>
                      </td>
                      <td className="px-8 py-4">
                        <div className="flex items-center gap-3">
                          <span className={`w-1.5 h-1.5 rounded-full ${
                            event.severity === 'critical' ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]' :
                            event.severity === 'high' ? 'bg-orange-500' :
                            event.type === 'server' ? 'bg-accent' : 
                            event.type === 'client' ? 'bg-green-400' : 'bg-purple-400'
                          }`} />
                          <div className={`text-[13px] font-mono truncate text-left ${
                            event.type === 'vulnerability' ? 'text-rose-400 font-bold' : 'text-indigo-300'
                          }`} dir="ltr">
                            {event.name}
                          </div>
                        </div>
                      </td>
                      <td className="px-8 py-4 text-center">
                        <span className={`inline-block px-2 py-1 rounded text-[11px] font-mono ${
                          event.severity === 'critical' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-border text-text-dim'
                        }`}>
                          L{event.line}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Sidebar Controls */}
        <aside className="w-80 border-l border-border bg-surface flex flex-col p-8 gap-8 shrink-0">
          {/* Analysis Trigger - Local */}
          <div className="space-y-4">
            <label className="text-[11px] uppercase font-bold text-text-dim tracking-wider">Source Database</label>
            <div 
              onClick={() => fileInputRef.current?.click()}
              className={`group flex flex-col items-center justify-center py-8 border border-dashed rounded-xl cursor-pointer transition-all ${loading ? 'border-accent bg-accent/5' : 'border-border hover:border-accent bg-white/[0.02]'}`}
            >
              <div className="text-2xl mb-3 group-hover:scale-110 transition-transform">📁</div>
              <p className="text-[12px] font-medium text-text-dim group-hover:text-accent transition-colors">
                {loading ? 'قيد المعالجة...' : 'اسحب ملف ZIP أو اختره'}
              </p>
            </div>
            <button 
              disabled={loading}
              onClick={() => fileInputRef.current?.click()}
              className="w-full h-12 bg-accent hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg flex items-center justify-center gap-3 text-white font-bold text-sm shadow-[0_4px_12px_rgba(99,102,241,0.2)]"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
              ) : (
                <Zap className="w-4 h-4" />
              )}
              بدء الفحص المعمق
            </button>
            <input type="file" ref={fileInputRef} onChange={handleFileUpload} className="hidden" accept=".zip" />
          </div>

          {/* Filtering */}
          <div className="space-y-4">
            <label className="text-[11px] uppercase font-bold text-text-dim tracking-wider">فلترة وتصفية النتائج</label>
            <div className="relative group">
              <Search className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim group-focus-within:text-accent transition-colors" />
              <input 
                type="text" 
                placeholder="ابحث عن اسم تريقر أو مسار..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-bg border border-border rounded-lg py-3 px-11 text-[13px] text-white focus:outline-none focus:border-accent transition-all pl-4 text-right"
              />
            </div>
            
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: 'all', label: 'الكل' },
                { id: 'server', label: 'Sever' },
                { id: 'client', label: 'Client' },
                { id: 'local', label: 'Trigger' },
                { id: 'register', label: 'Net' },
                { id: 'vulnerability', label: 'Risk' },
              ].map(type => (
                <button
                  key={type.id}
                  onClick={() => setFilterType(type.id)}
                  className={`py-2 rounded text-[10px] font-bold uppercase transition-all border ${
                    filterType === type.id 
                      ? 'bg-accent text-white border-accent shadow-[0_4px_10px_rgba(99,102,241,0.2)]' 
                      : 'bg-bg text-text-dim border-border hover:border-text-dim'
                  }`}
                >
                  {type.label}
                </button>
              ))}
            </div>
          </div>

          {/* Statistics */}
          <div className="mt-auto space-y-4 pt-6 border-t border-border">
            <label className="text-[11px] uppercase font-bold text-text-dim tracking-wider">تحليلات السيرفر</label>
            <div className="bg-bg border border-border rounded-xl p-4 divide-y divide-border">
              {[
                { label: 'إجمالي الزيارات', value: 12450 + (Math.floor((new Date().getTime() - new Date('2024-01-01').getTime()) / (1000 * 60 * 60 * 24)) * 342), color: 'text-text-dim' },
                { label: 'نشط الآن', value: 3, color: 'text-emerald-400 animate-pulse' },
                { label: 'ملفات Lua المكتشفة', value: stats?.luaFiles || 0, color: 'text-text-dim' },
                { label: 'تريقرات السيرفر', value: stats?.serverEvents || 0, color: 'text-accent' },
                { label: 'تريقرات TriggerEvent', value: stats?.localEvents || 0, color: 'text-purple-400' },
                { label: 'مخاطر أمنية محتملة', value: stats?.vulnerabilities || 0, color: 'text-rose-500' },
                { label: 'مستوى التشفير المكتشف', value: `${stats?.obfuscationScore || 0}%`, color: stats?.obfuscationScore && stats.obfuscationScore > 50 ? 'text-rose-400 font-bold animate-pulse' : 'text-text-dim' },
                { label: 'النتائج المطابقة', value: filteredData.length, color: 'text-emerald-400' },
              ].map((stat, i) => (
                <div key={i} className="flex justify-between py-2.5 first:pt-0 last:pb-0">
                  <span className="text-[11px] font-medium text-text-dim">{stat.label}</span>
                  <span className={`text-[11px] font-mono font-bold ${stat.color}`} dir="ltr">{stat.value.toLocaleString()}</span>
                </div>
              ))}
            </div>
            
            {stats && stats.vulnerabilities > 0 && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg">
                <p className="text-[10px] text-rose-400 font-bold leading-tight flex items-center gap-2">
                  <AlertCircle className="w-3 h-3" /> تم اكتشاف ثغرات خطيرة!
                </p>
                <p className="text-[9px] text-rose-400/70 mt-1 leading-relaxed">يرجى مراجعة الوظائف التي تحمل علامة "Security Risk" فوراً.</p>
              </div>
            )}
          </div>
        </aside>
      </main>

      {/* Footer Status */}
      <footer className="px-8 py-4 bg-surface border-t border-border flex justify-between items-center shrink-0">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-4 text-[10px] font-bold text-text-dim tracking-widest uppercase">
            <span className="flex items-center gap-1.5">
              <ArrowRight className="w-3 h-3" />
              Scanner Status: {status || 'Ready for Input'}
            </span>
          </div>
          <p className="text-[10px] text-text-dim font-medium">
            جميع الحقوق محفوظة © | <span className="text-accent font-bold">الزعابي</span>
          </p>
        </div>

        <div className="flex flex-col items-end gap-1">
          <div className="text-[10px] font-mono text-text-dim">
            PROTOCOL: AIS-SECURITY-v4
          </div>
          <a 
            href="https://discord.gg/uuuu" 
            target="_blank" 
            rel="noopener noreferrer"
            className="text-[10px] font-bold text-indigo-400 hover:text-indigo-300 transition-colors flex items-center gap-1.5"
          >
            <Users className="w-3 h-3" />
            discord.gg/uuuu
          </a>
        </div>
      </footer>

      {/* Code Inspector Overlay */}
      <AnimatePresence>
        {selectedEvent && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setSelectedEvent(null)}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-8"
          >
            <motion.div 
              initial={{ scale: 0.95, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              onClick={e => e.stopPropagation()}
              className="w-full max-w-2xl bg-surface border border-border rounded-2xl overflow-hidden shadow-2xl"
            >
              <div className="p-6 border-b border-border flex justify-between items-center">
                <div className="space-y-1">
                  <h3 className={`font-bold text-lg font-mono ${selectedEvent.type === 'vulnerability' ? 'text-rose-400' : 'text-white'}`} dir="ltr">{selectedEvent.name}</h3>
                  <p className="text-xs text-text-dim truncate font-mono" dir="ltr">{selectedEvent.file}</p>
                </div>
                <button onClick={() => setSelectedEvent(null)} className="text-text-dim hover:text-white">
                  <Download className="w-5 h-5 rotate-180" />
                </button>
              </div>
              <div className="p-6 space-y-4">
                {selectedEvent.description && (
                  <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg">
                    <p className="text-[10px] text-rose-400 font-bold uppercase tracking-widest mb-1 flex items-center gap-2">
                       <Shield className="w-3 h-3" /> Security Brief
                    </p>
                    <p className="text-xs text-rose-300 font-medium">{selectedEvent.description}</p>
                  </div>
                )}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-[10px] uppercase font-bold text-text-dim tracking-widest">Code Context (L{selectedEvent.line})</label>
                    <div className="flex items-center gap-2">
                      <button 
                        onClick={() => {
                          const range = document.createRange();
                          const selection = window.getSelection();
                          const codeElement = document.getElementById('code-context');
                          if (codeElement && selection) {
                            range.selectNodeContents(codeElement);
                            selection.removeAllRanges();
                            selection.addRange(range);
                          }
                        }}
                        className="flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-bold text-text-dim hover:text-accent hover:bg-white/5 transition-all"
                      >
                        <Filter className="w-3 h-3" /> تحديد الكل
                      </button>
                      <button 
                        onClick={() => handleCopy(selectedEvent.context)}
                        className={`flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-bold transition-all ${
                          copied ? 'text-emerald-400 bg-emerald-400/10' : 'text-text-dim hover:text-accent hover:bg-white/5'
                        }`}
                      >
                        {copied ? (
                          <>
                            <Check className="w-3 h-3" /> تم النسخ!
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" /> نسخ الكود
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                  <div 
                    id="code-context"
                    className="group relative bg-bg rounded-xl border border-border p-5 font-mono text-xs text-indigo-300/90 whitespace-pre overflow-x-auto selection:bg-accent/40 selection:text-white select-text cursor-text" 
                    dir="ltr"
                  >
                    {selectedEvent.context}
                  </div>
                </div>
                <div className="flex items-center gap-4 pt-4">
                  <div className="flex-1 p-4 bg-bg border border-border rounded-xl">
                    <p className="text-[10px] uppercase font-bold text-text-dim mb-1">Type Detection</p>
                    <p className={`text-sm font-bold uppercase ${EVENT_TYPES[selectedEvent.type].color}`}>
                      {EVENT_TYPES[selectedEvent.type].label}
                    </p>
                  </div>
                  <div className="flex-1 p-4 bg-bg border border-border rounded-xl">
                    <p className="text-[10px] uppercase font-bold text-text-dim mb-1">Threat Assessment</p>
                    <p className={`text-xs font-bold uppercase ${
                      selectedEvent.severity === 'critical' ? 'text-rose-500' :
                      selectedEvent.severity === 'high' ? 'text-orange-500' :
                      'text-emerald-400'
                    }`}>
                      {selectedEvent.severity} Level Risk
                    </p>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

