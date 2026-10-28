// Keeps the dashboard current: the server sends an event when something
// changes, and the page fetches its main section again. Without this script
// the page still works; it just needs reloading by hand.
"use strict";

const main = document.getElementById("main");
const live = document.getElementById("live");
let busy = false;
let again = false;

async function refresh() {
  if (busy) {
    again = true;
    return;
  }
  busy = true;
  try {
    // The query holds the timeline's filter and selected event.
    const res = await fetch("main" + location.search, { cache: "no-store" });
    if (res.ok) {
      // Keep open sections open across the refresh.
      const open = [...main.querySelectorAll("details[open]")].map((d) => d.id).filter(Boolean);
      main.innerHTML = await res.text();
      for (const id of open) {
        const d = document.getElementById(id);
        if (d) d.open = true;
      }
      showPending();
    }
  } finally {
    busy = false;
    if (again) {
      again = false;
      refresh();
    }
  }
}

// The tab's title counts the calls waiting, so they are noticed from
// another tab.
function showPending() {
  const section = main.querySelector("[data-pending]");
  const n = section ? Number(section.dataset.pending) : 0;
  document.title = n > 0 ? `(${n}) waiting · portcullis` : "portcullis";
}

// Choosing a filter or a row changes the address and fetches the main
// section again, rather than loading the whole page. Without this script
// the links load the page.
main.addEventListener("click", async (ev) => {
  const a = ev.target.closest("a[data-nav]");
  if (!a || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
  const to = new URL(a.href);
  if (to.origin !== location.origin || to.pathname !== location.pathname) return;
  ev.preventDefault();
  history.pushState(null, "", to.search || location.pathname);
  await refresh();
  // On a narrow screen the details are below the timeline: bring them up.
  const detail = document.getElementById("detail");
  if (to.searchParams.has("event") && detail && detail.getBoundingClientRect().top > window.innerHeight) {
    detail.scrollIntoView({ block: "start" });
  }
});
window.addEventListener("popstate", refresh);

const events = new EventSource("events");
events.addEventListener("change", refresh);
events.addEventListener("open", () => {
  live.hidden = false;
  live.textContent = "live";
  live.classList.remove("off");
  refresh(); // catch up on anything missed while disconnected
});
events.addEventListener("error", () => {
  live.hidden = false;
  live.textContent = "disconnected";
  live.classList.add("off");
});
showPending();
