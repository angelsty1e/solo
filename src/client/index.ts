/*
 * Copyright 2026 angelsty1e
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
  // Une nouvelle tentative repart d'un bouton réactivé (l'anti-double-clic de
  // sendPayload a pu le laisser désactivé sur l'essai précédent).
  btn.disabled = false;
  if (onClick) {
    btn.onclick = () => {
      btn.classList.remove('visible');
      onClick();
    };
  }
}

// Le conteneur #wait-controls (compte à rebours, « Terminer maintenant »,
// « Rester ici ») est réutilisé à plusieurs étapes : on le vide et on l'affiche
// proprement à chaque usage pour ne jamais empiler d'anciens contrôles.
function getWaitControls(): HTMLElement | null {
  return document.getElementById('wait-controls');
}

function showWaitControls(): HTMLElement | null {
  const host = getWaitControls();
  if (!host) return null;
  host.replaceChildren();
  host.hidden = false;
  return host;
}

function clearWaitControls(): void {
  const host = getWaitControls();
  if (!host) return;
  host.replaceChildren();
  host.hidden = true;
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

// Compte à rebours de redirection ANNULABLE : on n'arrache plus la page sous les
// pieds de l'utilisateur. Il voit « Redirection dans N… » + un bouton pour rester,
// et le lien « Voir le recap » reste disponible quoi qu'il arrive.
function startRedirectCountdown(recapUrl: string): void {
  const host = showWaitControls();
  if (!host) {
    // Pas de zone de contrôle : on respecte la main de l'utilisateur en ne
    // forçant aucune redirection — le lien recap (déjà visible) suffit.
    return;
  }

  const SECONDS = 3;
  let remaining = SECONDS;
  let timer = 0;

  const msg = document.createElement('span');
  msg.id = 'redirect-msg';
  msg.setAttribute('role', 'status');
  msg.setAttribute('aria-live', 'polite');
  msg.style.marginRight = '12px';

  const stay = document.createElement('button');
  stay.type = 'button';
  stay.className = 'inline-btn';
  stay.id = 'redirect-stay';
  stay.textContent = 'Rester ici';

  const cancel = (): void => {
    if (timer) window.clearInterval(timer);
    timer = 0;
    clearWaitControls();
  };

  stay.onclick = cancel;

  const render = (): void => {
    msg.textContent = `Redirection vers le recap dans ${remaining}…`;
  };
  render();
  host.append(msg, stay);

  timer = window.setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      cancel();
      window.location.href = recapUrl;
      return;
    }
    render();
  }, 1000);
}

// Flag d'anti-double-soumission au niveau module : jamais deux POST /collect
// concurrents, même si l'utilisateur spamme « Réessayer ».
let sending = false;

async function sendPayload(payload: ClientFingerprint): Promise<void> {
  if (sending) return; // Un envoi est déjà en vol — on ignore le doublon.
  sending = true;

  const retryBtn = document.getElementById('retry-btn') as HTMLButtonElement | null;
  if (retryBtn) retryBtn.disabled = true; // Verrouille le retry pendant la tentative.

  setStatus('Envoi au serveur…');
  let result: Awaited<ReturnType<typeof postCollect>>;
  try {
    result = await postCollect(payload);
  } finally {
    sending = false;
  }
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
    startRedirectCountdown(result.data.recapUrl);
  } else {
    setStatus(`Échec de l'envoi (${result.reason}). Tu peux réessayer.`);
    setRetry(true, () => {
      setStatus('Nouvelle tentative…');
      void sendPayload(payload);
    });
  }
}

// Fenêtre comportementale : on attend `durationMs`, mais sans laisser l'écran
// figé. La barre progresse de 60→90 %, un compte à rebours annonce le temps
// restant, et un bouton « Terminer maintenant » permet de conclure plus tôt.
// La promesse se résout sur le timer OU sur le clic, au premier des deux.
function behavioralWindow(durationMs: number): Promise<void> {
  const BAR_START = 60;
  const BAR_END = 90;

  return new Promise<void>((resolve) => {
    const host = showWaitControls();
    const startedAt = performance.now();
    let raf = 0;
    let timer = 0;
    let done = false;

    const countdown = document.createElement('span');
    countdown.id = 'wait-countdown';
    countdown.setAttribute('role', 'status');
    countdown.setAttribute('aria-live', 'polite');
    countdown.style.marginRight = '12px';

    const finishNow = document.createElement('button');
    finishNow.type = 'button';
    finishNow.className = 'inline-btn';
    finishNow.id = 'finish-now-btn';
    finishNow.textContent = 'Terminer maintenant';

    if (host) host.append(countdown, finishNow);

    const finish = (): void => {
      if (done) return;
      done = true;
      if (raf) cancelAnimationFrame(raf);
      if (timer) window.clearTimeout(timer);
      clearWaitControls();
      resolve();
    };

    finishNow.onclick = finish;

    // Garde-fou de fin : résout même si l'animation est gelée (onglet en
    // arrière-plan, rAF throttlé…).
    timer = window.setTimeout(finish, durationMs);

    // Sans animation (prefers-reduced-motion) : pas d'interpolation continue,
    // mais on garde le compte à rebours textuel, mis à jour à la seconde.
    if (prefersReducedMotion() || durationMs <= 0) {
      setBar(BAR_START);
      const tick = (): void => {
        if (done) return;
        const left = Math.max(0, durationMs - (performance.now() - startedAt));
        countdown.textContent = `Encore ${Math.ceil(left / 1000)} s…`;
        if (left > 0) window.setTimeout(tick, 250);
      };
      tick();
      return;
    }

    const loop = (): void => {
      if (done) return;
      const elapsed = performance.now() - startedAt;
      const ratio = Math.min(1, elapsed / durationMs);
      setBar(BAR_START + (BAR_END - BAR_START) * ratio);
      const left = Math.max(0, durationMs - elapsed);
      countdown.textContent = `Encore ${Math.ceil(left / 1000)} s…`;
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
  });
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
  await behavioralWindow(remaining);
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

  // Gate RGPD : on rend l'arrière-plan inerte (clavier + lecteur d'écran) tant
  // que la modale est ouverte, et on restaure le focus sur #scan-btn en sortie.
  const landing = document.getElementById('landing');
  const scanBtn = document.getElementById('scan-btn') as HTMLButtonElement | null;
  const setInert = (on: boolean): void => {
    if (!landing) return;
    if (on) {
      landing.setAttribute('inert', '');
      landing.setAttribute('aria-hidden', 'true'); // Repli si inert non supporté.
    } else {
      landing.removeAttribute('inert');
      landing.removeAttribute('aria-hidden');
    }
  };

  // Focusables réels de la modale, dans l'ordre du DOM (les deux boutons).
  const focusables = (): HTMLElement[] =>
    Array.from(
      modal.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((el) => !el.hasAttribute('disabled'));

  const onKeydown = (e: KeyboardEvent): void => {
    if (e.key === 'Escape') {
      e.preventDefault();
      decline.click(); // Échap = refus (choix le plus protecteur).
      return;
    }
    if (e.key !== 'Tab') return;
    // Focus-trap : Tab/Shift+Tab bouclent entre le premier et le dernier.
    const items = focusables();
    if (items.length === 0) return;
    const first = items[0]!;
    const last = items[items.length - 1]!;
    const active = document.activeElement as HTMLElement | null;
    if (e.shiftKey && (active === first || !modal.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  };

  modal.classList.add('visible');
  setInert(true);
  document.addEventListener('keydown', onKeydown, true);
  accept.focus();

  const close = (): void => {
    modal.classList.remove('visible');
    setInert(false);
    document.removeEventListener('keydown', onKeydown, true);
    accept.onclick = null;
    decline.onclick = null;
    // Restaure le focus sur le déclencheur pour ne pas perdre l'utilisateur clavier.
    scanBtn?.focus();
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

// Échec de la collecte : message orienté action + bouton « Relancer le test »
// qui rejoue runCollection(). On ne renvoie jamais l'utilisateur « voir la console ».
function showCollectionError(): void {
  setStatus("La collecte n'a pas pu aboutir. Vérifie ta connexion, puis relance le test.");
  const host = showWaitControls();
  if (!host) return;
  const retry = document.createElement('button');
  retry.type = 'button';
  retry.className = 'inline-btn';
  retry.id = 'restart-btn';
  retry.textContent = 'Relancer le test';
  retry.onclick = () => {
    clearWaitControls();
    setBar(0);
    void runCollectionGuarded();
  };
  host.append(retry);
}

// Encapsule runCollection avec son garde d'erreur actionnable, réutilisable
// par le clic initial comme par le bouton « Relancer le test ».
function runCollectionGuarded(): Promise<void> {
  return runCollection().catch((err) => {
    console.error('[solo] run failed', err);
    showCollectionError();
  });
}

function init(): void {
  const btn = document.getElementById('scan-btn') as HTMLButtonElement | null;

  if (!btn) {
    console.warn('[solo] #scan-btn not found — auto-running collection');
    void runCollectionGuarded();
    return;
  }

  // Garde-fou bundle KO : le HTML livre #scan-btn désactivé (aria-busy, label
  // « Chargement… ») pour ne rien promettre tant que le JS n'est pas attaché.
  // Maintenant que le handler est en place, on réactive et on restaure le CTA.
  const restoreScanBtn = (): void => {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.setAttribute('aria-label', 'Lancer le test de fingerprinting');
    const title = btn.querySelector('.title');
    if (title) title.textContent = 'Lancer le test';
  };

  btn.addEventListener('click', () => {
    openConsent(
      async () => {
        btn.disabled = true; // Verrouille la gâchette tant que la collecte court.
        try {
          await transitionToRunning();
          await runCollectionGuarded();
        } catch (err) {
          console.error('[solo] run failed', err);
          showCollectionError();
        }
      },
      () => {
        // Refus : on garde le landing utilisable (bouton réactivé).
        btn.disabled = false;
      },
    );
  });

  restoreScanBtn();

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