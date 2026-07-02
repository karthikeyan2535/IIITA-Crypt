import { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { API_BASE } from '../api.js';

// Agent Gamma: Thinking-state pipeline stages with icons
const STAGES = [
  { key: 'search',   label: 'Routing & Searching...', icon: '🔍' },
  { key: 'decrypt',  label: 'CP-ABE Decrypting Chunks...', icon: '🔓' },
  { key: 'generate', label: 'Synthesizing Response...', icon: '🧠' },
];

// Helper: derive branch from UPPERCASE attribute array
const getBranch = (attrs) => ['IT', 'ECE', 'IT-BUSINESS'].find(b => attrs.includes(b)) || null;
const getYear   = (attrs) => {
  const y = attrs.find(a => a.startsWith('YEAR-'));
  return y ? y.split('-')[1] : null;
};
const getHostel = (attrs) => attrs.find(a => a.startsWith('HOSTEL-')) || null;

export default function Chat({ user, onLogout, onTokenRefresh }) {
  const [messages, setMessages]       = useState([]);
  const [input, setInput]             = useState('');
  const [retrievalStage, setStage]    = useState(null);
  const messagesEndRef                = useRef(null);

  const scrollToBottom = () => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });

  // Fetch chat history on mount
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        let currentToken = user.token;
        let res = await fetch(`${API_BASE}/api/chat/history`, {
          headers: { Authorization: `Bearer ${currentToken}` }
        });

        if (res.status === 401 && user.refreshToken) {
          const refreshRes = await fetch(`${API_BASE}/api/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: user.refreshToken })
          });
          if (refreshRes.ok) {
            const data = await refreshRes.json();
            onTokenRefresh(data.token);
            currentToken = data.token;
            res = await fetch(`${API_BASE}/api/chat/history`, {
              headers: { Authorization: `Bearer ${currentToken}` }
            });
          } else {
            onLogout();
            return;
          }
        }

        if (res.ok) {
          const data = await res.json();
          if (data.messages?.length > 0) {
            setMessages(data.messages);
          } else {
            setMessages([{
              _id: 'welcome',
              sender: 'bot',
              text: `Welcome to **IIITA-Crypt** 🔐\n\nYou are authenticated as **${user.role}** (${user.email}).\n\nYour security clearance attributes:\n\`${user.attributes.join(' | ')}\`\n\nAsk me anything — your access is enforced at the cryptographic layer.`
            }]);
          }
        }
      } catch (_) { /* ignore */ }
    };
    fetchHistory();
  }, [user.token, user.role, user.attributes, user.email]);

  useEffect(() => { scrollToBottom(); }, [messages, retrievalStage]);

  const handleSend = async (e) => {
    e.preventDefault();
    if (!input.trim() || retrievalStage) return;

    const userQuery = input;
    const tempId = Date.now();
    setMessages(prev => [...prev, { _id: tempId, sender: 'user', text: userQuery }]);
    setInput('');

    try {
      // Stage 1 — Search animation
      setStage('search');
      await new Promise(r => setTimeout(r, 600));

      // Stage 2 — Decrypt animation (during actual API call)
      setStage('decrypt');
      let currentToken = user.token;
      let response = await fetch(`${API_BASE}/api/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${currentToken}`
        },
        body: JSON.stringify({ query: userQuery })
      });

      if (response.status === 401 && user.refreshToken) {
         const refreshRes = await fetch(`${API_BASE}/api/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: user.refreshToken })
         });
         if (refreshRes.ok) {
            const data = await refreshRes.json();
            onTokenRefresh(data.token);
            currentToken = data.token;
            response = await fetch(`${API_BASE}/api/chat`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${currentToken}` },
              body: JSON.stringify({ query: userQuery })
            });
         }
      }

      if (response.status === 401 || response.status === 403) {
        setStage(null);
        onLogout();
        return;
      }

      const data = await response.json();

      // Stage 3 — Synthesis animation
      setStage('generate');
      await new Promise(r => setTimeout(r, 500));
      setStage(null);

      const botText = data.response || '⚠️ No relevant documents found within your access scope.';
      const policies = data.sources?.length > 0
        ? [...new Set(data.sources.map(s => s.policy || 'PUBLIC'))]
        : [];
      const types = data.sources?.length > 0
        ? [...new Set(data.sources.map(s => s.type))]
        : [];

      setMessages(prev => [...prev, {
        _id: tempId + 1,
        sender: 'bot',
        text: botText,
        policies,
        types,
      }]);
    } catch (_) {
      setStage(null);
      setMessages(prev => [...prev, {
        _id: Date.now(),
        sender: 'bot',
        text: '⚠️ Network error. Please check that the backend is running on port 3000.'
      }]);
    }
  };

  // ── Role-Adaptive Sidebar ──────────────────────────────────────────────────
  const renderWidgets = () => {
    const attrs = user.attributes || [];
    const isHoD = attrs.some(a => a.startsWith('HOD-'));
    const hodDept = attrs.find(a => a.startsWith('HOD-'))?.replace('HOD-', '') || '';

    if (user.role === 'Dean') {
      return (
        <>
          <WidgetCard title="🏛️ Dean Override">
            <p className="text-xs font-bold" style={{color:'#A00000'}}>FULL ACCESS ACTIVE</p>
            <p className="text-xs text-gray-500 mt-1">Global access to all institutional records.</p>
          </WidgetCard>
          <WidgetCard title="📊 Institute Overview">
            <InfoRow label="Students" value="1,200+" />
            <InfoRow label="Faculty"  value="85+" />
            <InfoRow label="Departments" value="3" />
          </WidgetCard>
          <WidgetCard title="🔍 Try Asking">
            <p className="text-xs text-gray-400 italic">"What is the department budget?"</p>
            <p className="text-xs text-gray-400 italic mt-1">"MCM scholarship quotas"</p>
            <p className="text-xs text-gray-400 italic mt-1">"Faculty performance review criteria"</p>
            <p className="text-xs text-gray-400 italic mt-1">"Branch change policy"</p>
          </WidgetCard>
        </>
      );
    }

    if (user.role === 'Warden') {
      const hostel = attrs.find(a => a.startsWith('HOSTEL-WARDEN-'))?.replace('HOSTEL-WARDEN-', '') || 'Hostel';
      return (
        <>
          <WidgetCard title="🏠 Warden Panel">
            <InfoRow label="Assigned" value={hostel} />
            <InfoRow label="Status" value="Active" />
          </WidgetCard>
          <WidgetCard title="🔍 Try Asking">
            <p className="text-xs text-gray-400 italic">"{hostel} hostel rules"</p>
            <p className="text-xs text-gray-400 italic mt-1">"Curfew violation log"</p>
            <p className="text-xs text-gray-400 italic mt-1">"{hostel} mess menu"</p>
            <p className="text-xs text-gray-400 italic mt-1">"Hostel leave application process"</p>
          </WidgetCard>
        </>
      );
    }

    if (user.role === 'Faculty') {
      const dept = attrs.find(a => ['IT','ECE','MGMT'].includes(a)) || '';
      return (
        <>
          <WidgetCard title="👨‍🏫 Faculty Panel">
            <InfoRow label="Role" value={isHoD ? `HoD — ${hodDept}` : 'Faculty'} />
            {dept && <InfoRow label="Department" value={dept} />}
          </WidgetCard>
          <WidgetCard title="🔍 Try Asking">
            <p className="text-xs text-gray-400 italic">"What is my salary?"</p>
            <p className="text-xs text-gray-400 italic mt-1">"Research grant application process"</p>
            <p className="text-xs text-gray-400 italic mt-1">"Teaching load norms"</p>
            <p className="text-xs text-gray-400 italic mt-1">"Conference travel grant policy"</p>
          </WidgetCard>
        </>
      );
    }

    // Student
    const branch = ['IT','ECE','IT-BUSINESS'].find(b => attrs.includes(b)) || null;
    const year   = attrs.find(a => a.startsWith('YEAR-'))?.split('-')[1] || null;
    return (
      <>
        <WidgetCard title="🎓 Academic Profile">
          {branch && <InfoRow label="Branch" value={branch} />}
          {year   && <InfoRow label="Year"   value={`Year ${year}`} />}
          <InfoRow label="Status" value="Enrolled" />
        </WidgetCard>
        <WidgetCard title="💼 Placement">
          <p className="text-xs text-gray-500">Season 2025-26 open.</p>
          <p className="text-xs text-gray-400 mt-1 italic">Try: "Show me placement opportunities"</p>
        </WidgetCard>
        <WidgetCard title="🍽️ Mess">
          <p className="text-xs text-gray-500">Ask for today&apos;s hostel mess menu!</p>
          <p className="text-xs text-gray-400 mt-1 italic">Try: "BH-1 mess menu"</p>
        </WidgetCard>
        <WidgetCard title="🔍 More Queries">
          <p className="text-xs text-gray-400 italic">"What is my CGPA?"</p>
          <p className="text-xs text-gray-400 italic mt-1">"What are my backlogs?"</p>
          <p className="text-xs text-gray-400 italic mt-1">"What is my fee status?"</p>
          <p className="text-xs text-gray-400 italic mt-1">"Grade appeal process"</p>
        </WidgetCard>
      </>
    );
  };

  const currentStage = STAGES.find(s => s.key === retrievalStage);

  return (
    <div className="flex w-full max-w-6xl h-[92vh] bg-white rounded-2xl shadow-2xl overflow-hidden border border-gray-200">

      {/* ── Sidebar ── */}
      <aside className="w-64 flex flex-col gap-0 shrink-0 border-r border-gray-200 bg-gray-50">
        {/* Sidebar Header */}
        <div className="px-5 py-5 border-b border-gray-200">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-extrabold text-lg" style={{color:'#A00000'}}>IIITA-Crypt</span>
          </div>
          <span className="inline-block px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border" style={{color:'#23495C', borderColor:'#23495C', backgroundColor:'#f0f4f6'}}>
            {user.role}
          </span>
          <p className="text-xs text-gray-400 mt-2 truncate">{user.email}</p>
        </div>

        {/* Widgets */}
        <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
          {renderWidgets()}
        </div>

        {/* Security Clearance */}
        <div className="px-4 py-3 border-t border-gray-200 bg-white">
          <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-1">Security Attributes</p>
          <div className="flex flex-wrap gap-1">
            {(user.attributes || []).map(a => (
              <span key={a} className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded font-mono">{a}</span>
            ))}
          </div>
        </div>

        {/* Logout */}
        <button
          id="logout-btn"
          onClick={onLogout}
          className="w-full py-3 text-sm font-semibold text-gray-500 hover:text-red-700 hover:bg-red-50 transition-colors border-t border-gray-200"
        >
          ← Sign Out
        </button>
      </aside>

      {/* ── Main Chat ── */}
      <main className="flex-grow flex flex-col bg-penrose">

        {/* Header */}
        <header className="px-6 py-3 bg-white/95 backdrop-blur-sm border-b border-gray-200 flex items-center gap-3 shrink-0">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-sm font-semibold text-gray-600">Secure RAG Session Active</span>
          <span className="ml-auto text-xs text-gray-400 font-mono">CP-ABE · MSK Persistent · Floor 0.7</span>
        </header>

        {/* Messages */}
        <div className="flex-grow p-5 overflow-y-auto flex flex-col gap-4">
          {messages.map((msg, idx) => (
            <MessageBubble key={msg._id || idx} msg={msg} />
          ))}

          {/* Agent Gamma: Thinking Animation */}
          {retrievalStage && currentStage && (
            <div className="self-start flex items-center gap-3 px-4 py-3 bg-white border border-gray-200 rounded-2xl rounded-bl-sm shadow-sm max-w-xs">
              <div>
                <p className="text-xs font-bold uppercase tracking-wider" style={{color:'#23495C'}}>{currentStage.label}</p>
                <div className="flex gap-1 mt-1">
                  {[0,1,2].map(i => (
                    <div key={i} className="w-1.5 h-1.5 rounded-full bg-gray-400 animate-bounce" style={{animationDelay:`${i*0.15}s`}} />
                  ))}
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <form onSubmit={handleSend} className="p-4 bg-white/95 backdrop-blur-sm border-t border-gray-200 flex gap-3 shrink-0">
          <input
            id="chat-input"
            type="text"
            className="flex-grow p-3 bg-gray-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 transition-all text-sm"
            placeholder={retrievalStage ? currentStage?.label : `Ask the secure knowledge base...`}
            value={input}
            onChange={e => setInput(e.target.value)}
            disabled={!!retrievalStage}
          />
          <button
            id="chat-send"
            type="submit"
            className="text-white font-bold py-3 px-5 rounded-xl transition-all disabled:opacity-50 hover:opacity-90 active:scale-95 text-sm"
            style={{backgroundColor:'#A00000'}}
            disabled={!!retrievalStage || !input.trim()}
          >
            Send
          </button>
        </form>
      </main>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function MessageBubble({ msg }) {
  const isUser = msg.sender === 'user';
  return (
    <div className={`flex flex-col max-w-[80%] ${isUser ? 'self-end items-end' : 'self-start items-start'}`}>
      <div
        className={`px-4 py-3 rounded-2xl shadow-sm text-sm leading-relaxed ${
          isUser
            ? 'text-white rounded-br-sm'
            : 'bg-white text-gray-800 border border-gray-200 rounded-bl-sm'
        }`}
        style={isUser ? {backgroundColor:'#23495C'} : {}}
      >
        <div className="markdown-body">
          <ReactMarkdown>{msg.text}</ReactMarkdown>
        </div>
      </div>


    </div>
  );
}

function WidgetCard({ title, children }) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-3 shadow-sm">
      <p className="text-xs font-bold uppercase tracking-wider mb-2" style={{color:'#A00000'}}>{title}</p>
      {children}
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="flex justify-between text-xs py-0.5">
      <span className="text-gray-400">{label}</span>
      <span className="font-semibold text-gray-700">{value}</span>
    </div>
  );
}