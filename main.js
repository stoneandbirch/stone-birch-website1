/* main.js — Stone & Birch */

// ─── MENU ───
const menuBtn  = document.getElementById('menuBtn');
const menuOverlay = document.getElementById('menuOverlay');
const mainNav  = document.getElementById('mainNav');
let menuOpen = false;

menuBtn && menuBtn.addEventListener('click', () => {
  menuOpen = !menuOpen;
  menuBtn.classList.toggle('open', menuOpen);
  menuOverlay.classList.toggle('open', menuOpen);
  document.body.style.overflow = menuOpen ? 'hidden' : '';
  updateNavStyle();
});

function closeMenu() {
  if (!menuOpen) return;
  menuOpen = false;
  menuBtn && menuBtn.classList.remove('open');
  menuOverlay && menuOverlay.classList.remove('open');
  document.body.style.overflow = '';
  updateNavStyle();
}

// ─── NAV COLOUR ───
function updateNavStyle() {
  if (!mainNav) return;
  if (menuOpen) {
    mainNav.classList.remove('light','dark','scrolled');
    mainNav.classList.add('dark');
    return;
  }
  const scrolled = window.scrollY > (window.innerHeight * 0.85);
  mainNav.classList.toggle('scrolled', scrolled);
  mainNav.classList.toggle('light', !scrolled);
  mainNav.classList.toggle('dark', scrolled);
}

window.addEventListener('scroll', updateNavStyle, { passive: true });
updateNavStyle();

// ─── HERO SLIDER ───
(function() {
  const slides = document.querySelectorAll('.slide');
  const dots   = document.querySelectorAll('.dot');
  const counter = document.getElementById('slideCounter');
  const progressBar = document.getElementById('progressBar');
  if (!slides.length) return;

  let current = 0;
  let timer;
  const INTERVAL = 5500;

  function goToSlide(n) {
    slides[current].classList.remove('active');
    dots[current] && dots[current].classList.remove('active');
    current = ((n % slides.length) + slides.length) % slides.length;
    slides[current].classList.add('active');
    dots[current] && dots[current].classList.add('active');
    if (counter) {
      counter.textContent =
        String(current + 1).padStart(2, '0') + ' / ' +
        String(slides.length).padStart(2, '0');
    }
    resetProgress();
  }

  function resetProgress() {
    if (!progressBar) return;
    progressBar.style.transition = 'none';
    progressBar.style.width = '0%';
    requestAnimationFrame(() => requestAnimationFrame(() => {
      progressBar.style.transition = `width ${INTERVAL}ms linear`;
      progressBar.style.width = '100%';
    }));
  }

  function startTimer() {
    clearInterval(timer);
    timer = setInterval(() => goToSlide(current + 1), INTERVAL);
  }

  dots.forEach((dot, i) => {
    dot.addEventListener('click', () => { goToSlide(i); startTimer(); });
  });

  // Swipe support
  let touchStartX = 0;
  const heroEl = document.getElementById('hero');
  if (heroEl) {
    heroEl.addEventListener('touchstart', e => { touchStartX = e.touches[0].clientX; }, { passive: true });
    heroEl.addEventListener('touchend', e => {
      const dx = e.changedTouches[0].clientX - touchStartX;
      if (Math.abs(dx) > 50) { goToSlide(current + (dx < 0 ? 1 : -1)); startTimer(); }
    }, { passive: true });
  }

  resetProgress();
  startTimer();
})();
