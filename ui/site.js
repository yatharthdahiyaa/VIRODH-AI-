// Virodh AI website + docs behaviour (no dependencies, no inline scripts: CSP script-src 'self').
(function () {
  "use strict";
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

  // sticky header border + mobile menu
  const header = $(".site-header");
  if (header) {
    const onScroll = () => header.classList.toggle("scrolled", window.scrollY > 8);
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    const btn = $("[data-menu]");
    if (btn)
      btn.addEventListener("click", () => {
        const open = header.classList.toggle("open");
        btn.setAttribute("aria-expanded", String(open));
      });
  }

  // base URL in code samples = this server
  $$("[data-base]").forEach((el) => {
    el.textContent = location.origin;
  });

  // product tabs
  const tabs = $$(".tabs .tab");
  tabs.forEach((t) =>
    t.addEventListener("click", () => {
      tabs.forEach((x) => {
        const on = x === t;
        x.setAttribute("aria-selected", String(on));
        const p = document.getElementById(x.getAttribute("aria-controls"));
        if (p) p.hidden = !on;
      });
    }),
  );

  // code tabs + copy
  $$("[data-codetabs]").forEach((box) => {
    const btns = $$(".code-tab[data-lang]", box);
    btns.forEach((b) =>
      b.addEventListener("click", () => {
        btns.forEach((x) => x.setAttribute("aria-selected", String(x === b)));
        $$("pre[data-lang]", box).forEach((p) => {
          p.hidden = p.dataset.lang !== b.dataset.lang;
        });
      }),
    );
    const copy = $("[data-copy]", box);
    if (copy)
      copy.addEventListener("click", async () => {
        const pre = $$("pre[data-lang]", box).find((p) => !p.hidden) || $("pre", box);
        try {
          await navigator.clipboard.writeText(pre.innerText);
          copy.textContent = "Copied";
        } catch (e) {
          copy.textContent = "Select & copy";
        }
        setTimeout(() => {
          copy.textContent = "Copy";
        }, 1600);
      });
  });

  // hero: reveal the hidden text on hover/focus of the verdict
  const poster = $("[data-reveal]");
  const verdict = $(".verdict");
  if (poster && verdict) {
    const on = () => poster.classList.add("revealed");
    const off = () => poster.classList.remove("revealed");
    verdict.addEventListener("mouseenter", on);
    verdict.addEventListener("mouseleave", off);
    setTimeout(on, 1800);
    setTimeout(off, 4200);
  }

  // live evaluation numbers (never hand-typed)
  const slots = { detect: $('[data-metric="detect"]'), fp: $('[data-metric="fp"]'), adv: $('[data-metric="adv"]') };
  const lead = (s) => String(s || "").split(" ")[0] || "—";
  if (slots.detect || slots.fp || slots.adv) {
    fetch("/api/metrics")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (!j || !j.available || !j.headline) return;
        if (slots.detect) slots.detect.textContent = lead(j.headline["attack detection rate"]);
        if (slots.fp) slots.fp.textContent = lead(j.headline["false positive rate (all benign)"]);
      })
      .catch(() => {});
    fetch("/api/adversarial/metrics")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => {
        if (!j || !j.available || !j.headline) return;
        const k = Object.keys(j.headline).find((x) => x.startsWith("adversarial detection rate"));
        if (k && slots.adv) slots.adv.textContent = lead(j.headline[k]);
      })
      .catch(() => {});
  }

  // docs: highlight the section in view
  const navLinks = $$(".docs-nav a[href^='#']");
  if (navLinks.length && "IntersectionObserver" in window) {
    const byId = new Map(navLinks.map((a) => [a.getAttribute("href").slice(1), a]));
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            navLinks.forEach((a) => a.classList.remove("active"));
            const a = byId.get(e.target.id);
            if (a) a.classList.add("active");
          }
        });
      },
      { rootMargin: "-80px 0px -70% 0px" },
    );
    $$(".doc section[id]").forEach((s) => io.observe(s));
  }
})();
