/**
 * HERNÍ LOGIKA (běží v prohlížeči)
 * ================================
 * Načte zašifrovaný levels.json a postupně odemyká úrovně.
 * Nikde nedrží odpovědi — ověření = úspěšné AES-GCM dešifrování.
 */

const state = {
  data: null,
  index: 0,           // index aktuální otázky
  current: null,      // obsah aktuální otázky {prompt, image, hints, type, options, isLast}
  hintsShown: 0,      // kolik nápověd je odhaleno na AKTUÁLNÍ otázce
  selected: [],       // zvolené možnosti u abcd/combo/poradi
  // Měření kvízu (jedna část).
  part: { startTime: null, seconds: null, mistakes: 0, hints: 0 }
};

// ---- SKÓRE ----
const SCORE_BASE = 10000;       // základní balík bodů
const SCORE_PER_SECOND = 5;     // přísnější penalizace za sekundu (kvíz = rychlé odpovědi)
const SCORE_PER_MISTAKE = 100;  // penalizace za špatnou odpověď
const SCORE_PER_HINT = 150;     // penalizace za zobrazenou nápovědu (jen poprvé)

function partResult(part) {
  let seconds = part.seconds;
  if (seconds === null) {
    seconds = part.startTime ? Math.floor((Date.now() - part.startTime) / 1000) : 0;
  }
  const hints = part.hints || 0;
  const raw = SCORE_BASE - seconds * SCORE_PER_SECOND
            - part.mistakes * SCORE_PER_MISTAKE
            - hints * SCORE_PER_HINT;
  return { score: Math.max(0, raw), seconds, mistakes: part.mistakes, hints };
}

function lockPart() {
  if (state.part.seconds === null) {
    state.part.seconds = state.part.startTime ? Math.floor((Date.now() - state.part.startTime) / 1000) : 0;
  }
}

function formatTime(totalSeconds) {
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

// Slovní rank podle skóre (max 10000).
function rankFor(total) {
  if (total >= 9500) return { title: "Hacker", note: "Tohle už hraničí s magií!" };
  if (total >= 8500) return { title: "Nejlepší kámoš/ka", note: "Znáš je líp než oni sebe!" };
  if (total >= 7000) return { title: "Svatební expert", note: "Skvělý výkon!" };
  if (total >= 5500) return { title: "Dobrý známý", note: "Velmi pěkné!" };
  if (total >= 4000) return { title: "Sympatický host", note: "Pěkná práce!" };
  if (total >= 2000) return { title: "Vzdálený bratranec", note: "Dobrý začátek!" };
  return { title: "Host z plus jedna", note: "Hlavně že tě to bavilo!" };
}

// Celkový rozpis kvízu + rank.
function totalScoreHtml() {
  const r = partResult(state.part);
  const rank = rankFor(r.score);
  return (
    '<div class="scorebox">' +
    '<div class="score-points">' + r.score.toLocaleString("cs-CZ") + ' bodů</div>' +
    '<div class="score-detail">Čas ' + formatTime(r.seconds) +
    ' &nbsp;·&nbsp; Chyby ' + r.mistakes +
    ' &nbsp;·&nbsp; Nápovědy ' + r.hints + '</div>' +
    '<div class="score-divider"></div>' +
    '<div class="score-rank">' + rank.title + '</div>' +
    '<div class="score-detail">' + rank.note + '</div>' +
    '</div>'
  );
}

// ---- UKLÁDÁNÍ POSTUPU (localStorage) ----
// Ukládáme JEN už dešifrovaný obsah dosažené úrovně, NIKDY odpovědi.
// Kdo hru nehrál, v úložišti nic použitelného nenajde.
// Postup je podepsaný checksumem — ruční úpravy se poznají (a okomentují 🕵️).

const SAVE_KEY = "svatba_kviz_v1";

// Jednoduchý podpis dat (djb2 + sůl). Není to kryptografická ochrana — kdo si
// přečte tenhle kód, obejde ji. Ale o tom to celé je, ne? 😉
function saveChecksum(str) {
  let h = 5381;
  const salted = str + "|jr-2026-kviz";
  for (let i = 0; i < salted.length; i++) {
    h = ((h << 5) + h + salted.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}

function saveProgress() {
  try {
    const payload = {
      index: state.index,
      current: state.current,
      hintsShown: state.hintsShown,
      part: state.part
    };
    const body = JSON.stringify(payload);
    localStorage.setItem(SAVE_KEY, JSON.stringify({ d: payload, c: saveChecksum(body) }));
  } catch (e) {
    // localStorage může být vypnutý (privátní režim) — hra funguje dál, jen bez uložení
  }
}

function loadProgress() {
  try {
    const raw = localStorage.getItem(SAVE_KEY);
    if (!raw) return null;
    const wrap = JSON.parse(raw);
    if (!wrap || !wrap.d || !wrap.c) {
      clearProgress();
      return null;
    }
    if (saveChecksum(JSON.stringify(wrap.d)) !== wrap.c) {
      state._tampered = true;
      clearProgress();
      return null;
    }
    const s = wrap.d;
    if (!s || !s.current || typeof s.index !== "number") return null;
    if (!s.part) {
      clearProgress();
      return null;
    }
    return s;
  } catch (e) {
    return null;
  }
}

function clearProgress() {
  try { localStorage.removeItem(SAVE_KEY); } catch (e) {}
}

// ---- KRYPTO ----

function normalize(str) {
  return str
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

// Sjednotí odpověď na kanonický řetězec pro klíč (musí přesně odpovídat generátoru).
// combo: položky seřadit (pořadí nehraje roli). poradi: pořadí zachovat.
function answerKey(answer, type) {
  if (Array.isArray(answer)) {
    const items = answer.map((a) => normalize(String(a)));
    if (type === "poradi") return items.join("|");
    return items.sort().join("|");
  }
  return normalize(String(answer));
}

async function sha256hex(str) {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function deriveKey(answer, salt, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(answer),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

/**
 * Zkusí dešifrovat blok zadanou odpovědí.
 * Vrací objekt při úspěchu, null při špatné odpovědi.
 */
async function tryDecrypt(answer, block) {
  try {
    const salt = fromB64(block.salt);
    const iv = fromB64(block.iv);
    const data = fromB64(block.data);
    const key = await deriveKey(answerKey(answer, state.current && state.current.type), salt, state.data.meta.iterations);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return JSON.parse(new TextDecoder().decode(plain));
  } catch (e) {
    return null; // špatná odpověď = dešifrování selže
  }
}

// ---- ZVUKY (Web Audio API, bez souborů) ----
let audioCtx = null;
function ensureAudio() {
  if (!audioCtx) {
    try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); }
    catch (e) { audioCtx = null; }
  }
  return audioCtx;
}
// Zahraje sekvenci tónů. notes = [{f: frekvence, t: délka v s}, ...]
function playTones(notes) {
  const ctx = ensureAudio();
  if (!ctx) return;
  let when = ctx.currentTime;
  for (const n of notes) {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = n.f;
    gain.gain.setValueAtTime(0.0001, when);
    gain.gain.exponentialRampToValueAtTime(0.25, when + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, when + n.t);
    osc.connect(gain).connect(ctx.destination);
    osc.start(when);
    osc.stop(when + n.t);
    when += n.t;
  }
}
function soundCorrect() { playTones([{ f: 660, t: 0.12 }, { f: 880, t: 0.18 }]); }
function soundWrong()   { playTones([{ f: 220, t: 0.18 }]); }
function soundFinale()  { playTones([{ f: 523, t: 0.15 }, { f: 659, t: 0.15 }, { f: 784, t: 0.15 }, { f: 1047, t: 0.3 }]); }

// ---- KONFETY (canvas, bez knihovny) ----
function launchConfetti(durationMs = 2500) {
  const canvas = document.createElement("canvas");
  canvas.style.cssText = "position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:100;";
  document.body.appendChild(canvas);
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  function resize() { canvas.width = innerWidth * dpr; canvas.height = innerHeight * dpr; }
  resize();
  const colors = ["#b8924e", "#cdab6e", "#9a7838", "#6f8a5b", "#f3ece2", "#e3c889"];
  const N = 140;
  const parts = Array.from({ length: N }, () => ({
    x: Math.random() * canvas.width,
    y: -Math.random() * canvas.height * 0.4,
    r: (4 + Math.random() * 6) * dpr,
    c: colors[(Math.random() * colors.length) | 0],
    vx: (-1 + Math.random() * 2) * dpr,
    vy: (2 + Math.random() * 3) * dpr,
    rot: Math.random() * Math.PI,
    vr: -0.1 + Math.random() * 0.2
  }));
  const start = performance.now();
  function frame(now) {
    const elapsed = now - start;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of parts) {
      p.x += p.vx; p.y += p.vy; p.rot += p.vr;
      ctx.save();
      ctx.translate(p.x, p.y);
      ctx.rotate(p.rot);
      ctx.fillStyle = p.c;
      ctx.fillRect(-p.r / 2, -p.r / 2, p.r, p.r * 0.6);
      ctx.restore();
    }
    if (elapsed < durationMs) {
      requestAnimationFrame(frame);
    } else {
      // dojezd: necháme propadnout dolů, pak odstraníme
      if (parts.some(p => p.y < canvas.height + 20)) requestAnimationFrame(frame);
      else canvas.remove();
    }
  }
  requestAnimationFrame(frame);
}

// ---- UI ----

const $ = (id) => document.getElementById(id);

function renderLevel(content) {
  state.current = content;
  $("success-box").classList.add("hidden");
  $("answer").value = "";
  $("answer").disabled = false;
  $("submit-btn").disabled = false;
  $("error").textContent = "";

  $("prompt").innerHTML = content.prompt;

  // --- TYP OTÁZKY ---
  renderInput(content);

  // --- NÁPOVĚDY ---
  // hintsShown se nastaví před voláním renderLevel (0 pro novou úroveň,
  // nebo obnovená hodnota po refreshi). Vykreslíme stav tlačítka i boxu.
  renderHints();

  const imgEl = $("level-image");
  if (content.image) {
    imgEl.src = content.image;
    imgEl.classList.remove("hidden");
  } else {
    imgEl.classList.add("hidden");
  }

  const num = state.index + 1;
  const total = state.data.kviz.blocks.length + 1;
  $("level-label").textContent = `Otázka ${num} / ${total}`;

  // progress lišta
  $("progress-fill").style.width = (num / total * 100) + "%";

  // plynulý fade karty při každé nové úrovni
  const card = document.querySelector("#game .card");
  if (card) {
    card.classList.remove("card-fade");
    void card.offsetWidth; // restart animace
    card.classList.add("card-fade");
  }

  $("answer").focus();
}

// Vykreslí vstup podle typu otázky.
function renderInput(content) {
  const type = content.type || "text";
  const field = document.querySelector("#game .field");
  const input = $("answer");
  const opts = $("options");
  state.selected = [];
  opts.innerHTML = "";
  opts.classList.remove("ordering");

  if (type === "abcd" || type === "combo" || type === "ano_ne") {
    field.classList.add("hidden");
    opts.classList.remove("hidden");
    const list = type === "ano_ne" ? ["Ano", "Ne"] : (content.options || []);
    const single = (type === "abcd" || type === "ano_ne");
    list.forEach((label) => {
      const btn = document.createElement("button");
      btn.className = "opt";
      btn.textContent = label;
      btn.addEventListener("click", () => {
        if (single) {
          state.selected = [label];
          opts.querySelectorAll(".opt").forEach((b) => b.classList.remove("selected"));
          btn.classList.add("selected");
        } else {
          const i = state.selected.indexOf(label);
          if (i >= 0) { state.selected.splice(i, 1); btn.classList.remove("selected"); }
          else { state.selected.push(label); btn.classList.add("selected"); }
        }
      });
      opts.appendChild(btn);
    });
  } else if (type === "poradi") {
    // řazení: klik přidá položku do pořadí (s číslem), další klik ji vyjme
    field.classList.add("hidden");
    opts.classList.remove("hidden");
    opts.classList.add("ordering");
    const list = content.options || [];
    const render = () => {
      opts.querySelectorAll(".opt").forEach((b) => {
        const pos = state.selected.indexOf(b.dataset.label);
        if (pos >= 0) { b.classList.add("selected"); b.dataset.pos = (pos + 1); }
        else { b.classList.remove("selected"); b.dataset.pos = ""; }
        b.textContent = (pos >= 0 ? (pos + 1) + ". " : "") + b.dataset.label;
      });
    };
    list.forEach((label) => {
      const btn = document.createElement("button");
      btn.className = "opt";
      btn.dataset.label = label;
      btn.textContent = label;
      btn.addEventListener("click", () => {
        const i = state.selected.indexOf(label);
        if (i >= 0) state.selected.splice(i, 1);
        else state.selected.push(label);
        render();
      });
      opts.appendChild(btn);
    });
  } else {
    // text / cislo / datum
    field.classList.remove("hidden");
    opts.classList.add("hidden");
    input.value = "";
    if (type === "datum") {
      input.type = "date";
      input.inputMode = "text";
    } else {
      input.type = "text";
      input.inputMode = (type === "cislo") ? "numeric" : "text";
    }
  }
}

// Sebere odpověď podle typu: string nebo pole.
function collectAnswer() {
  const type = (state.current && state.current.type) || "text";
  if (type === "abcd" || type === "ano_ne") return state.selected[0] || "";
  if (type === "combo" || type === "poradi") return state.selected.slice();
  return $("answer").value;
}

// Vykreslí tlačítko nápovědy a box s už odhalenými nápovědami podle stavu.
function renderHints() {
  const hints = (state.current && state.current.hints) || [];
  const btn = $("hint-btn");
  const box = $("hint-box");

  // box: ukaž odhalené nápovědy
  if (state.hintsShown > 0) {
    box.innerHTML = hints
      .slice(0, state.hintsShown)
      .map((h) => '<div class="hint-item">' + h + "</div>")
      .join("");
    box.classList.remove("hidden");
  } else {
    box.innerHTML = "";
    box.classList.add("hidden");
  }

  // tlačítko: zobraz jen pokud zbývá nějaká nenápověda
  if (hints.length > 0 && state.hintsShown < hints.length) {
    const remaining = hints.length - state.hintsShown;
    btn.textContent = state.hintsShown === 0
      ? "💡 Nápověda (−" + SCORE_PER_HINT + " b.)"
      : "💡 Další nápověda (−" + SCORE_PER_HINT + " b.) · zbývá " + remaining;
    btn.classList.remove("hidden");
  } else {
    btn.classList.add("hidden");
  }
}

// Odhalí další nápovědu. Penalizuje jen poprvé (nová nápověda = nový odečet).
function showHint() {
  const hints = (state.current && state.current.hints) || [];
  if (state.hintsShown >= hints.length) return;

  const penalty = SCORE_PER_HINT;
  if (!confirm("Zobrazit nápovědu? Odečte ti to " + penalty + " bodů.")) return;

  state.hintsShown += 1;
  state.part.hints += 1; // penalizace (jen za nové odhalení)
  saveProgress();
  renderHints();
}

function showSuccess(text, opts = {}) {
  $("error").textContent = "";
  $("success-text").innerHTML = text;
  $("success-box").classList.remove("hidden");
  $("answer").disabled = true;
  $("submit-btn").disabled = true;
  // skryj tlačítko nápovědy (úroveň je vyřešená)
  $("hint-btn").classList.add("hidden");
  // běžná mezi-úroveň: tlačítko Pokračovat na další šifru
  $("continue-btn").classList.remove("hidden");
}

// Samostatná finální obrazovka kvízu.
function showFinale(celebrate = true) {
  $("error").textContent = "";
  $("game").classList.add("hidden");
  $("intro").classList.add("hidden");
  $("finale").classList.remove("hidden");

  const actions = $("finale-actions");
  actions.innerHTML = "";

  $("finale-text").innerHTML = "🎉 Dokončil/a jsi celý kvíz!";
  $("finale-text").style.color = "var(--accent-deep)";
  $("finale-score").innerHTML = totalScoreHtml();

  const share = makeShareButton();
  actions.appendChild(share);

  const restart = document.createElement("button");
  restart.className = "btn-quit";
  restart.textContent = "↺ Hrát znovu";
  restart.addEventListener("click", restartGame);
  actions.appendChild(restart);

  // easter egg jen pro vysoké skóre (8500+)
  const r = partResult(state.part);
  if (r.score >= 8500) {
    maybeShowEgg();
  }

  // oslava: konfety + fanfára (ne při obnově po refreshi)
  if (celebrate) {
    launchConfetti();
    soundFinale();
  }
}

// ---- EASTER EGG ----
// Vejce ani zpráva nejsou v HTML. Vejce se vytvoří dynamicky jen při skóre 17000+.
// Klíč k dešifrování se odvozuje z otisků posledních odpovědí obou větví —
// v kódu žádný klíč není, vejce odemkne jen ten, kdo hru skutečně dohrál.

function maybeShowEgg() {
  if (!state.data || !state.data.egg) return;
  if (document.getElementById("egg")) return; // už tam je

  const egg = document.createElement("div");
  egg.id = "egg";
  egg.textContent = "🥚";
  egg.title = "";
  egg.style.cssText =
    "position:fixed;bottom:14px;right:14px;font-size:26px;cursor:pointer;" +
    "z-index:60;opacity:.55;transition:opacity .2s,transform .2s;user-select:none;";
  egg.addEventListener("mouseenter", () => { egg.style.opacity = "1"; egg.style.transform = "scale(1.15)"; });
  egg.addEventListener("mouseleave", () => { egg.style.opacity = ".55"; egg.style.transform = "scale(1)"; });
  egg.addEventListener("click", async () => {
    const fk = state.part.fk;
    if (!fk) return;
    const eggKey = await sha256hex(fk);
    const msg = await tryDecrypt(eggKey, state.data.egg);
    if (!msg) return;
    showSecretMessage("Tajné vejce", msg.message);
    egg.remove();
  });
  document.body.appendChild(egg);
}

function showSecretMessage(title, text) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML =
    '<div class="modal-box">' +
    '<div class="modal-title"></div>' +
    '<div class="modal-text"></div>' +
    '<button class="btn-primary">Zavřít</button>' +
    '</div>';
  document.body.appendChild(overlay);
  overlay.querySelector(".modal-title").textContent = title;
  overlay.querySelector(".modal-text").textContent = text;
  overlay.querySelector("button").addEventListener("click", () => overlay.remove());
  launchConfetti(1800);
}

// ---- HACKERSKÁ VÝZVA (konzole) ----
// Globální funkce pro zvědavce: svatba('odpověď'). Odměna je zašifrovaná
// v levels.json — odpověď ani zpráva nejsou čitelné v žádném souboru na webu.
async function svatba(odpoved) {
  if (!state.data || !state.data.hacker) return "Hra ještě není načtená.";
  const msg = await tryDecrypt(String(odpoved || ""), state.data.hacker);
  if (!msg) {
    console.log("%c❌ Blízko, ale ne. Zkus to znovu.", "color:#b56a52;font-size:13px;");
    return "Špatně.";
  }
  console.log("%c✅ White Hat potvrzen.", "color:#6f8a5b;font-size:14px;font-weight:bold;");
  showSecretMessage("🎩 White Hat", msg.message);
  return "Gratuluju!";
}

// ---- KONZOLOVÝ POZDRAV ----
function consoleGreeting() {
  try {
    const gold = "color:#b8924e;";
    console.log(
      "%c✦ ✧ ✦\n%cJitka ♥ Radomír%c\n18. 7. 2026 · Nový Dvůr, Lhotka",
      gold + "font-size:14px;",
      gold + "font-size:26px;font-family:Georgia,serif;",
      "color:#8a7d6c;font-size:12px;"
    );
    console.log("%cVidíme tě 👀 Když už jsi tady…", "font-size:13px;");
    if (state.data && state.data.hackerHint) {
      console.log(
        "%c🔐 Výzva pro zvědavé: dekóduj  %c" + state.data.hackerHint + "%c\n   Nápověda: Caesar by to posunul o 13 a pak zabalil do base64.\n   Až to rozlouskneš, zavolej: svatba('výsledek')\n   (Tuhle výzvu kdykoli zopakuješ příkazem napoveda() )",
        "color:#6f8a5b;font-size:13px;",
        "color:#6f8a5b;font-size:13px;font-weight:bold;font-family:monospace;",
        "color:#6f8a5b;font-size:12px;"
      );
    }
    console.log(
      "%cP.S. Odpovědi jsou šifrované (AES-256-GCM, PBKDF2-SHA256, 250 000 iterací). V kódu je nenajdeš. 😉",
      "color:#999;font-size:11px;"
    );
  } catch (e) { /* konzole není kritická */ }
}

// Kdo otevře konzoli až po načtení, zopakuje si výzvu příkazem napoveda()
function napoveda() {
  consoleGreeting();
  return "🔎 Výzva vypsána výše.";
}

function buildShareText() {
  const r = partResult(state.part);
  const rankTitle = rankFor(r.score).title;
  return `Ve svatebním kvízu Jíti a Ráďi jsem získal/a ${r.score.toLocaleString("cs-CZ")} bodů — ${rankTitle}! Zahraj si taky: ${GAME_URL}`;
}

function makeShareButton() {
  const btn = document.createElement("button");
  btn.className = "btn-go";
  btn.textContent = "📤 Pochlubit se skóre";
  btn.addEventListener("click", async () => {
    const text = buildShareText();
    try {
      if (navigator.share) {
        await navigator.share({ title: "Svatební kvíz", text, url: GAME_URL });
      } else {
        await navigator.clipboard.writeText(text);
        btn.textContent = "✓ Zkopírováno do schránky";
        setTimeout(() => { btn.textContent = "📤 Pochlubit se skóre"; }, 2000);
      }
    } catch (e) {
      // uživatel sdílení zrušil — nic neděláme
    }
  });
  return btn;
}

async function handleSubmit() {
  const answer = collectAnswer();
  // validace: prázdná odpověď (text i výběr)
  const empty = Array.isArray(answer) ? answer.length === 0 : !String(answer).trim();
  if (empty) return;

  $("submit-btn").disabled = true;
  $("error").textContent = "Ověřuji…";

  const branch = state.data.kviz;
  const nextIndex = state.index; // blocks[index] je zamčen odpovědí otázky index

  // Je tohle poslední otázka? Pak odpověď odemyká finalBlock.
  const isLastLevel = state.index === branch.blocks.length;

  if (isLastLevel) {
    const finale = await tryDecrypt(answer, branch.finalBlock);
    if (!finale) {
      state.part.mistakes += 1;
      saveProgress();
      soundWrong();
      $("error").textContent = "❌ Špatná odpověď, zkus to znovu.";
      $("submit-btn").disabled = false;
      return;
    }
    // otisk správné poslední odpovědi (hash) — slouží k odvození klíče vejce
    state.part.fk = await sha256hex(
      answerKey(answer, state.current && state.current.type)
    );
    lockPart();
    state.current.finaleState = "done";
    saveProgress();
    showFinale();
    return;
  }

  // Běžná otázka: odemkni další blok
  const next = await tryDecrypt(answer, branch.blocks[nextIndex]);
  if (!next) {
    state.part.mistakes += 1;
    saveProgress();
    soundWrong();
    $("error").textContent = "❌ Špatná odpověď, zkus to znovu.";
    $("submit-btn").disabled = false;
    return;
  }

  // Ulož odemčený obsah a ukaž success z právě vyřešené otázky
  state._pendingNext = next;
  soundCorrect();
  showSuccess(next.prevSuccess, {});
}

function goNext() {
  const next = state._pendingNext;
  state._pendingNext = null;
  state.index += 1;
  state.hintsShown = 0; // nová úroveň → skryté nápovědy
  renderLevel({
    prompt: next.prompt,
    image: next.image,
    hints: next.hints || [],
    type: next.type || "text",
    options: next.options || null,
    isLast: next.isLast
  });
  saveProgress();
}

function startQuiz() {
  state.index = 0;
  state.hintsShown = 0;
  state.part = { startTime: Date.now(), seconds: null, mistakes: 0, hints: 0 };
  const start = state.data.kviz.start;
  renderLevel(start);
  saveProgress();
}

function endGame() {
  clearProgress();
  const html = '<div class="end">Děkujeme za hru! 💛<br>Tuhle záložku můžeš zavřít.</div>';
  $("intro").classList.add("hidden");
  $("finale").classList.add("hidden");
  $("game").classList.remove("hidden");
  $("game").innerHTML = html;
}

function restartGame() {
  if (!confirm("Opravdu začít kvíz znovu? Tvůj postup se ztratí a vrátíš se na úvod.")) return;
  restartToIntro();
}

// Úplný reset: zpět na úvodní obrazovku
function restartToIntro() {
  clearProgress();
  state._pendingNext = null;
  state.index = 0;
  state.hintsShown = 0;
  state.part = { startTime: null, seconds: null, mistakes: 0, hints: 0 };
  $("game").classList.add("hidden");
  $("finale").classList.add("hidden");
  $("intro").classList.remove("hidden");
  $("start-btn").textContent = "Spustit kvíz";
}

// ---- INIT ----

// ---- TMAVÝ REŽIM ----
const THEME_KEY = "svatba_theme";

function loadTheme() {
  try { return localStorage.getItem(THEME_KEY) === "dark" ? "dark" : "light"; }
  catch (e) { return "light"; }
}

function applyTheme(theme) {
  if (theme === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  const btn = $("theme-btn");
  if (btn) btn.textContent = theme === "dark" ? "☀️ Světlý režim" : "🌙 Tmavý režim";
}

function toggleTheme() {
  const next = loadTheme() === "dark" ? "light" : "dark";
  try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
  applyTheme(next);
}

async function init() {
  // úklid uloženého postupu ze starší verze hry
  try { localStorage.removeItem("svatba_sifrovacka_v1"); } catch (e) {}

  try {
    const res = await fetch("levels.json", { cache: "no-store" });
    state.data = await res.json();
  } catch (e) {
    $("prompt").textContent = "Nepodařilo se načíst hru (levels.json).";
    return;
  }

  // pozdrav pro zvědavce v konzoli (+ hackerská výzva)
  consoleGreeting();

  $("submit-btn").addEventListener("click", handleSubmit);
  $("answer").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleSubmit();
  });
  $("continue-btn").addEventListener("click", goNext);
  $("hint-btn").addEventListener("click", showHint);
  $("restart-btn").addEventListener("click", restartGame);
  $("start-btn").addEventListener("click", startGame);

  // pravidla
  $("rules-btn").addEventListener("click", () => {
    $("intro").classList.add("hidden");
    $("rules").classList.remove("hidden");
  });
  $("rules-back").addEventListener("click", () => {
    $("rules").classList.add("hidden");
    $("intro").classList.remove("hidden");
  });

  // tmavý režim
  $("theme-btn").addEventListener("click", toggleTheme);
  applyTheme(loadTheme()); // aplikuj uložené téma a nastav text tlačítka

  // Pokud má hráč rozehráno, uprav text úvodního tlačítka
  if (loadProgress()) {
    $("start-btn").textContent = "Pokračovat v kvízu";
  }

  // ruční úprava uloženého postupu? uznale pokáráme
  if (state._tampered) {
    showSecretMessage(
      "🕵️ Pěkný pokus",
      "Ruční úpravy uloženého postupu detekovány. Respekt za snahu — ale tohle vejce si musíš zasloužit. Začínáš od první otázky. (Mimochodem, koukni do konzole.)"
    );
  }
}

// Přepnutí z úvodní obrazovky do kvízu
function startGame() {
  $("intro").classList.add("hidden");
  $("game").classList.remove("hidden");

  const saved = loadProgress();
  if (saved) {
    state.index = saved.index;
    state.hintsShown = saved.hintsShown || 0;
    if (saved.part) state.part = saved.part;
    renderLevel(saved.current);
    // pokud hráč skončil na finálové obrazovce, obnov ji (bez oslavy)
    if (saved.current.finaleState === "done") {
      showFinale(false);
    }
    return;
  }

  startQuiz();
}

init();
