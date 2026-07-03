async function test() {
  const BASE = 'http://localhost:3000/api';

  const login = async (email, password) => {
    const r = await fetch(`${BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return r.json();
  };

  const chat = async (tok, q) => {
    const r = await fetch(`${BASE}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tok}` },
      body: JSON.stringify({ query: q })
    });
    const d = await r.json();
    const fail = !d.response || d.response.includes('No relevant records') || d.response.includes('Access Restricted');
    const snippet = (d.response || '').replace(/\n/g,' ').substring(0, 80);
    return { ok: !fail, snippet, sources: d.sources?.length || 0 };
  };

  let failCount = 0;
  const show = (label, res) => {
    const icon = res.ok ? '✅' : '❌';
    if (!res.ok) failCount++;
    console.log(`${icon} ${label.padEnd(25)} | sources=${res.sources.toString().padStart(2)} | ${res.snippet}`);
  };

  // ── Student (Aarav - BH-1) ───────────────────────────────────────────────
  const s = await login('iit2023001@iiita.ac.in', 'Aarav@2023');
  const sTok = s.token;
  console.log('\n=== STUDENT: Aarav Sharma (BH-1, iit2023001) ===');
  
  // 1. Personal & Academic
  show('my cgpa',             await chat(sTok, 'what is my cgpa?'));
  show('backlogs',            await chat(sTok, 'do I have any active backlogs?'));
  show('fee status',          await chat(sTok, 'what is my fee status?'));
  show('guardian',            await chat(sTok, 'who is my guardian and their contact?'));
  show('scholarship',         await chat(sTok, 'am I receiving any scholarships?'));
  show('hostel address',      await chat(sTok, 'what is my room number / hostel address?'));
  
  // 2. General Academic & Policy
  show('attendance policy',   await chat(sTok, 'what is the 75 percent attendance policy?'));
  show('exam weightage',      await chat(sTok, 'how are c1 c2 and c3 exams weighted?'));
  show('sem registration',    await chat(sTok, 'what is the procedure for semester registration?'));
  show('grade appeal',        await chat(sTok, 'how do i appeal my grade?'));
  show('fap rules',           await chat(sTok, 'what are the rules for the flexible academic program?'));
  show('plagiarism',          await chat(sTok, 'what is the academic integrity and plagiarism policy?'));
  show('it courses',          await chat(sTok, 'what IT courses are offered?'));
  show('phd rules',           await chat(sTok, 'phd course work rules'));
  show('ece lab',             await chat(sTok, 'what are the ece department labs?'));
  
  // 3. Campus Life & Residential
  show('mess lunch',          await chat(sTok, 'whats for lunch today in my mess?'));
  show('hostel rules',        await chat(sTok, 'what are the hostel rules?'));
  
  // 4. Placements & Internships
  show('placement portal',    await chat(sTok, 'what companies are coming for placements?'));
  show('cdc intern',          await chat(sTok, 'guidelines for cdc internship?'));
  
  // 5. Staff Directory (Public)
  show('who is dean',         await chat(sTok, 'who is the dean of academic affairs?'));
  show('warden gh1',          await chat(sTok, 'who is the warden for gh-1?'));
  show('kavita teach',        await chat(sTok, 'which dept does dr kavita joshi teach in?'));
  show('who teaches it',      await chat(sTok, 'who teaches it?'));

  // ── Student 2 (Sanya - IT-Management) ────────────────────────────────────
  const sanya = await login('itm2023078@iiita.ac.in', 'Sanya@2023');
  const sanyaTok = sanya.token;
  console.log('\n=== STUDENT: Sanya Kapoor (IT-BUSINESS) ===');
  show('mgmt thesis',         await chat(sanyaTok, 'management thesis guidelines'));

  // ── Faculty (sk.singh) ───────────────────────────────────────────────────
  const f = await login('sk.singh@iiita.ac.in', 'Singh@IIITA');
  const fTok = f.token;
  console.log('\n=== FACULTY: Dr. S.K. Singh (IT Dept) ===');
  
  // 6. Faculty-Specific
  show('my salary',           await chat(fTok, 'what is my current salary grade?'));
  show('research grant',      await chat(fTok, 'how do i apply for an institute research grant?'));
  show('travel grant',        await chat(fTok, 'policy for conference travel grants?'));
  show('teaching load',       await chat(fTok, 'what are the standard teaching load norms?'));
  show('who is dean',         await chat(fTok, 'who is the dean?'));

  // ── Dean (dean.acad) ─────────────────────────────────────────────────────
  const d = await login('dean.acad@iiita.ac.in', 'Dean@IIITA');
  const dTok = d.token;
  console.log('\n=== DEAN: Prof. Abhay Kumar ===');
  
  // 7. Administrative
  show('list students',       await chat(dTok, 'list all students in the college'));
  show('list faculty',        await chat(dTok, 'list all faculty'));
  show('fee defaulters',      await chat(dTok, 'show me all fee defaulters'));
  show('aarav cgpa',          await chat(dTok, 'what is aaravs cgpa?'));
  show('curfew log',          await chat(dTok, 'show me the curfew violation log'));
  show('branch change',       await chat(dTok, 'what are the branch change rules?'));
  show('perf review',         await chat(dTok, 'faculty performance review process?'));
  
  // ── Warden (warden.bh1) ──────────────────────────────────────────────────
  const w = await login('warden.bh1@iiita.ac.in', 'Warden@BH1');
  const wTok = w.token;
  console.log('\n=== WARDEN: Mr. Suresh Pandey (BH-1) ===');
  show('curfew log',          await chat(wTok, 'show me the curfew violation log'));
  show('mess today',          await chat(wTok, 'whats for lunch today'));
  show('hostel rules',        await chat(wTok, 'hostel rules'));
  
  console.log('\nTotal Failures:', failCount);
}

test().catch(console.error);
