import { gsap } from 'gsap';
import type { ClientFingerprint } from '../shared/types.js';
import { collectAllStatic } from './collectors/index.js';
import { aggregateBehavioral } from './behavioral/aggregate.js';
import { startKeyboard } from './behavioral/keyboard.js';
import { startMouse } from './behavioral/mouse.js';
import { startScroll } from './behavioral/scroll.js';
import { startTouch } from './behavioral/touch.js';
import { generateSessionId, postCollect } from './session.js';

const COLLECTION_WINDOW_MS = 8000;

function prefersReducedMotion(): boolean {
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

function setStatus(text: string): void {
  const el = document.getElementById('status');
  if (el) el.textContent = text;
}

function setBar(pct: number): void {
  const clamped = Math.min(100, Math.max(0, pct));
  const el = document.getElementById('progress-bar');
  if (el) {
    (el as HTMLElement).style.width = `${clamped}%`;
    el.setAttribute('aria-valuenow', String(Math.round(clamped)));
  }
}

function setRetry(visible: boolean, onClick?: () => void): void {
  const btn = document.getElementById('retry-btn') as HTMLButtonElement | null;
  if (!btn) return;
  btn.classList.toggle('visible', visible);
  if (onClick) {
    btn.onclick = () => {
      btn.classList.remove('visible');
      onClick();
    };
  }
}

async function fetchServerSide(): Promise<unknown> {
  try {
    const res = await fetch('/api/fp/me', { credentials: 'omit' });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function startAuraAnimation(): void {
  if (prefersReducedMotion()) return;
  try {
    gsap.to('.aura-1', { scale: 1.08, opacity: 0.9, duration: 2.4, ease: 'sine.inOut', repeat: -1, yoyo: true });
    gsap.to('.aura-2', { scale: 1.18, opacity: 0.75, duration: 3.6, ease: 'sine.inOut', repeat: -1, yoyo: true });
    const rings = ['.ring-1', '.ring-2', '.ring-3'];
    rings.forEach((sel, i) => {
      gsap.set(sel, { scale: 0.95, opacity: 0.6 });
      gsap.to(sel, { scale: 1.35, opacity: 0, duration: 3.2, ease: 'power1.out', repeat: -1, delay: i * 1.05 });
    });
  } catch (err) {
    console.error('[solo] aura animation failed', err);
  }
}

function focusRunning(): void {
  const running = document.getElementById('running');
  const heading = running?.querySelector('h1');
  if (heading) {
    heading.setAttribute('tabindex', '-1');
    (heading as HTMLElement).focus();
  }
}

function transitionToRunning(): Promise<void> {
  const landing = document.getElementById('landing');
  const running = document.getElementById('running');
  if (!landing || !running) return Promise.resolve();

  const swap = (): void => {
    landing.style.display = 'none';
    running.classList.add('visible');
    focusRunning();
  };

  // Respect reduced-motion: no entrance animation, just swap.
  if (prefersReducedMotion()) {
    swap();
    return Promise.resolve();
  }

  return new Promise<void>((resolve) => {
    let done = false;
    const finish = (): void => {
      if (done) return;
      done = true;
      swap();
      resolve();
    };

    // Hard timeout in case the GSAP timeline never fires onComplete
    // (e.g. tab backgrounded, animation throttled, selector missing).
    const fallback = window.setTimeout(finish, 900);

    try {
      const tl = gsap.timeline({
        onComplete: () => {
          window.clearTimeout(fallback);
          finish();
          gsap.from(running, { opacity: 0, y: 12, duration: 0.4, ease: 'power2.out' });
        },
      });
      tl.to('#scan-btn', { scale: 1.06, duration: 0.18, ease: 'power2.out' }, 0);
      tl.to('.aura, .ring', { scale: 1.6, opacity: 0, duration: 0.55, ease: 'power2.out' }, 0.05);
      tl.to('#landing', { opacity: 0, duration: 0.35, ease: 'power2.in' }, 0.15);
    } catch (err) {
      console.error('[solo] transition timeline failed, falling back', err);
      window.clearTimeout(fallback);
      finish();
    }
  });
}

async function sendPayload(payload: ClientFingerprint): Promise<void> {
  setStatus('Envoi au serveur…');
  const result = await postCollect(payload);
  setBar(100);

  if (result.ok && result.data) {
    setStatus('Terminé.');
    setRetry(false);
    const link = document.getElementById('recap-link') as HTMLAnchorElement | null;
    if (link) {
      link.href = result.data.recapUrl;
      link.textContent = 'Voir le recap';
      link.style.visibility = 'visible';
    }
    setTimeout(() => {
      window.location.href = result.data!.recapUrl;
    }, 800);
  } else {
    setStatus(`Échec de l'envoi (${result.reason}). Tu peux réessayer.`);
    setRetry(true, () => {
      setStatus('Nouvelle tentative…');
      void sendPayload(payload);
    });
  }
}

async function runCollection(): Promise<void> {
  const sessionId = generateSessionId();
  (window as Window & { __soloSessionId?: string }).__soloSessionId = sessionId;
  const startedAt = performance.now();

  startMouse();
  startKeyboard();
  startScroll();
  startTouch();

  setStatus('Snapshot statique en cours…');
  setBar(15);
  const [serverSide, staticSnap] = await Promise.all([fetchServerSide(), collectAllStatic()]);
  setBar(60);

  const preview = document.getElementById('server-preview');
  if (preview) {
    preview.textContent = JSON.stringify(serverSide ?? { error: 'unavailable' }, null, 2);
  }

  setStatus('Collecte comportementale… bouge ta souris, scrolle, tape quelque chose.');
  const remaining = Math.max(0, COLLECTION_WINDOW_MS - (performance.now() - startedAt));
  await new Promise<void>((r) => setTimeout(r, remaining));
  setBar(90);

  const behavioral = aggregateBehavioral(startedAt);
  const payload: ClientFingerprint = {
    sessionId,
    collectedAt: new Date().toISOString(),
    durationMs: performance.now() - startedAt,
    ...staticSnap,
    behavioral,
  };

  await sendPayload(payload);
}

function openConsent(onAccept: () => void, onDecline: () => void): void {
  const modal = document.getElementById('consent');
  const accept = document.getElementById('consent-accept') as HTMLButtonElement | null;
  const decline = document.getElementById('consent-decline') as HTMLButtonElement | null;
  if (!modal || !accept || !decline) {
    // No modal in DOM — fail open to the accept path so the lab still works.
    onAccept();
    return;
  }
  modal.classList.add('visible');
  accept.focus();

  const close = (): void => {
    modal.classList.remove('visible');
    accept.onclick = null;
    decline.onclick = null;
  };
  accept.onclick = () => {
    close();
    onAccept();
  };
  decline.onclick = () => {
    close();
    onDecline();
  };
}

function init(): void {
  const btn = document.getElementById('scan-btn') as HTMLButtonElement | null;

  const start = (): void => {
    runCollection().catch((err) => {
      console.error('[solo] run failed', err);
      setStatus('Erreur — voir console.');
    });
  };

  if (!btn) {
    console.warn('[solo] #scan-btn not found — auto-running collection');
    start();
    return;
  }

  btn.addEventListener('click', () => {
    openConsent(
      async () => {
        btn.disabled = true;
        try {
          await transitionToRunning();
          start();
        } catch (err) {
          console.error('[solo] run failed', err);
          setStatus('Erreur — voir console.');
        }
      },
      () => {
        // Declined: keep the landing usable.
        btn.disabled = false;
      },
    );
  });

  // Aura animation is purely cosmetic — never let it block the click handler.
  try {
    startAuraAnimation();
  } catch (err) {
    console.error('[solo] startAuraAnimation threw', err);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init, { once: true });
} else {
  init();
}
