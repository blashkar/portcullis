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
    const res = await fetch("main", { cache: "no-store" });
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
