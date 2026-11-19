//! The GUI's pages. Every page reads the daemon API through [`witness_client::Client`]; the
//! blocking client runs on a worker thread so the window never freezes.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dioxus::prelude::*;
use serde_json::{json, Value};
use witness_client::{encode, Client};

use crate::model::{self, ProcNode};
use crate::style::CSS;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Live,
    Search,
    Alerts,
    Timeline,
    Processes,
    Sessions,
    Dashboard,
    Integrity,
    Rules,
}

const PAGES: [(Page, &str); 9] = [
    (Page::Dashboard, "Dashboard"),
    (Page::Live, "Live"),
    (Page::Search, "Search"),
    (Page::Alerts, "Alerts"),
    (Page::Timeline, "Timeline"),
    (Page::Processes, "Processes"),
    (Page::Sessions, "Sessions"),
    (Page::Integrity, "Integrity"),
    (Page::Rules, "Rules"),
];

/// What the Search page is asked to show; other pages set this and switch to Search.
#[derive(Clone, PartialEq, Default)]
struct Query {
    q: String,
    kind: String,
    puid: String,
    ses: String,
    from: Option<u64>,
    to: Option<u64>,
    last_secs: Option<u64>,
}

impl Query {
    fn url(&self, cursor: Option<u64>, limit: usize) -> String {
        let mut u = format!("/v1/events?limit={limit}");
        let mut add = |k: &str, v: &str| {
            if !v.trim().is_empty() {
                u.push_str(&format!("&{k}={}", encode(v.trim())));
            }
        };
        add("q", &self.q);
        add("puid", &self.puid);
        add("ses", &self.ses);
        for k in self.kind.split([',', ' ']).filter(|k| !k.is_empty()) {
            add("kind", k);
        }
        if let Some(v) = self.from {
            add("from", &v.to_string());
        }
        if let Some(v) = self.to {
            add("to", &v.to_string());
        }
        if let Some(v) = self.last_secs {
            add("last_secs", &v.to_string());
        }
        if let Some(c) = cursor {
            add("cursor", &c.to_string());
        }
        u
    }
}

/// Runs a blocking call off the UI thread.
async fn off<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

async fn get(c: &Client, path: String) -> Result<Value, String> {
    let c = c.clone();
    off(move || c.get(&path).map_err(|e| e.to_string()))
        .await
        .unwrap_or_else(|| Err("the request was cancelled".into()))
}

fn events_of(v: &Value) -> Vec<Value> {
    v["events"].as_array().cloned().unwrap_or_default()
}

fn text<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut x = v;
    for p in path {
        x = &x[*p];
    }
    x.as_str().unwrap_or("")
}

/// Down/up (arrow keys or j/k) as +1/-1.
fn key_delta(e: &KeyboardEvent) -> Option<i32> {
    match e.key() {
        Key::ArrowDown => Some(1),
        Key::ArrowUp => Some(-1),
        Key::Character(c) if c == "j" => Some(1),
        Key::Character(c) if c == "k" => Some(-1),
        _ => None,
    }
}

/// `--page <name>` opens that page first (used for screenshots and bookmarks).
fn initial_page() -> Page {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let name = if a == "--page" {
            args.next().unwrap_or_default()
        } else if let Some(n) = a.strip_prefix("--page=") {
            n.to_string()
        } else {
            continue;
        };
        if let Some((p, _)) = PAGES
            .iter()
            .find(|(_, label)| label.eq_ignore_ascii_case(&name))
        {
            return *p;
        }
    }
    Page::Dashboard
}

// ---- shell ----------------------------------------------------------------------------

#[component]
pub fn App() -> Element {
    let client = use_context::<Client>();
    let mut page = use_signal(initial_page);
    let search = use_signal(Query::default);
    // `false` = UTC. Toggling remounts the page so every time is redrawn.
    let mut local = use_signal(|| false);
    use_context_provider(|| page);
    use_context_provider(|| search);

    // Connection indicator: asks the daemon every few seconds.
    let mut up = use_signal(|| None::<Result<Value, String>>);
    let c2 = client.clone();
    use_future(move || {
        let c = c2.clone();
        async move {
            loop {
                up.set(Some(get(&c, "/v1/status".into()).await));
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        }
    });

    rsx! {
        style { "{CSS}" }
        div { class: "app",
            nav { class: "nav",
                div { class: "brand", "Witness" }
                for (p, name) in PAGES {
                    button { class: if page() == p { "on" } else { "" }, onclick: move |_| page.set(p), "{name}" }
                }
                div { class: "spacer" }
                button { title: "Show times in your local time zone", onclick: move |_| {
                    let on = !local();
                    model::set_tz_offset(if on { model::local_offset_secs() } else { 0 });
                    local.set(on);
                }, if local() { "Times: local" } else { "Times: UTC" } }
                div { class: "conn",
                    match &*up.read() {
                        None => rsx! { "connecting…" },
                        Some(Ok(s)) => rsx! {
                            b { "● connected" }
                            br {}
                            "head #{s[\"head_seq\"]} · {s[\"tier\"].as_str().unwrap_or(\"\")}"
                        },
                        Some(Err(e)) => rsx! { b { class: "down", "● offline" } br {} "{e}" },
                    }
                }
            }
            main { class: "main", key: "{local()}",
                match page() {
                    Page::Live => rsx! { LivePage {} },
                    Page::Search => rsx! { SearchPage {} },
                    Page::Alerts => rsx! { AlertsPage {} },
                    Page::Timeline => rsx! { TimelinePage {} },
                    Page::Processes => rsx! { ProcessesPage {} },
                    Page::Sessions => rsx! { SessionsPage {} },
                    Page::Dashboard => rsx! { DashboardPage {} },
                    Page::Integrity => rsx! { IntegrityPage {} },
                    Page::Rules => rsx! { RulesPage {} },
                }
            }
        }
    }
}

// ---- shared pieces ----------------------------------------------------------------------

#[component]
fn EventRow(e: Value, selected: bool, onpick: EventHandler<Value>) -> Element {
    let wall = e["wall_ns"].as_u64().unwrap_or(0);
    let tone = model::tone(&e);
    let desc = model::describe(&e);
    let t = model::fmt_time(wall);
    let kind = text(&e, &["type"]).to_string();
    let e2 = e.clone();
    rsx! {
        div { class: "row {tone}", class: if selected { "sel" }, onclick: move |_| onpick.call(e2.clone()),
            span { class: "t", "{t}" }
            span { class: "k", "{kind}" }
            span { class: "d", title: "{desc}", "{desc}" }
        }
    }
}

/// Shows one event: who, what, the full record, and where to go next.
#[component]
fn Detail(e: Option<Value>) -> Element {
    let client = use_context::<Client>();
    let mut page = use_context::<Signal<Page>>();
    let mut search = use_context::<Signal<Query>>();
    let Some(e) = e else {
        return rsx! { div { class: "detail muted", "Select an event to see it in full." } };
    };
    let seq = e["seq"].as_u64().unwrap_or(0);
    let raw = use_resource(move || {
        let c = client.clone();
        async move {
            let c2 = c.clone();
            off(move || {
                c2.get_text(&format!("/v1/events/{seq}/raw"))
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap_or_else(|| Err("cancelled".into()))
        }
    });
    let a = &e["actor"];
    let puid = text(a, &["puid"]).to_string();
    let ses = a["ses"].as_u64();
    let pretty = serde_json::to_string_pretty(&e).unwrap_or_default();
    let exe = text(a, &["exe"]).to_string();
    let user = text(a, &["user"]).to_string();
    let comm = text(a, &["comm"]).to_string();
    let when = model::fmt_time(e["wall_ns"].as_u64().unwrap_or(0));
    let kind = text(&e, &["type"]).to_string();
    let hash = text(&e, &["h"]).to_string();
    let pid = a["pid"].to_string();
    let puid2 = puid.clone();
    rsx! {
        div { class: "detail",
            h3 { "Event #{seq}" }
            dl { class: "kv",
                dt { "time (UTC)" } dd { "{when}" }
                dt { "type" } dd { "{kind}" }
                dt { "process" } dd { "{comm} (pid {pid}) {user}" }
                dt { "program" } dd { "{exe}" }
                dt { "process id" } dd { "{puid}" }
                dt { "chain hash" } dd { "{hash}" }
            }
            div { class: "actions",
                if !puid.is_empty() {
                    button { class: "btn", onclick: move |_| {
                        search.set(Query { puid: puid2.clone(), ..Query::default() });
                        page.set(Page::Search);
                    }, "Everything this process did" }
                }
                if let Some(s) = ses {
                    button { class: "btn", onclick: move |_| {
                        search.set(Query { ses: s.to_string(), ..Query::default() });
                        page.set(Page::Search);
                    }, "Whole session {s}" }
                }
            }
            h3 { "Record" }
            pre { class: "json", "{pretty}" }
            h3 { "Exact stored line" }
            match &*raw.read() {
                None => rsx! { span { class: "muted", "loading…" } },
                Some(Ok(t)) => rsx! { pre { class: "json", "{t}" } },
                Some(Err(e)) => rsx! { span { class: "muted", "{e}" } },
            }
        }
    }
}

#[component]
fn Failure(msg: String) -> Element {
    rsx! { div { class: "error", "{msg}" } }
}

// ---- live -------------------------------------------------------------------------------

#[derive(Default)]
struct Feed {
    buf: Vec<Value>,
    error: Option<String>,
    cursor: Option<u64>,
}

#[component]
fn LivePage() -> Element {
    let client = use_context::<Client>();
    let mut rows = use_signal(Vec::<Value>::new);
    let mut paused = use_signal(|| false);
    let mut filter = use_signal(String::new);
    let mut picked = use_signal(|| None::<Value>);
    let mut err = use_signal(|| None::<String>);
    let mut wrap = use_signal(|| false);

    let feed = use_hook(|| {
        let feed = Arc::new(Mutex::new(Feed::default()));
        let (f, c) = (feed.clone(), client.clone());
        std::thread::spawn(move || loop {
            let since = f.lock().ok().and_then(|g| g.cursor);
            let path = match since {
                Some(s) => format!("/v1/stream?since_seq={s}"),
                None => "/v1/stream".to_string(),
            };
            let f2 = f.clone();
            let r = c.stream(&path, |v| {
                if v["heartbeat"].is_null() {
                    if let Ok(mut g) = f2.lock() {
                        g.cursor = v["seq"].as_u64().or(g.cursor);
                        g.error = None;
                        g.buf.push(v);
                    }
                }
                true
            });
            if let (Err(e), Ok(mut g)) = (r, f.lock()) {
                g.error = Some(e.to_string());
            }
            std::thread::sleep(Duration::from_secs(2));
        });
        feed
    });

    use_future(move || {
        let feed = feed.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(400)).await;
                if paused() {
                    continue;
                }
                let (new, e) = match feed.lock() {
                    Ok(mut g) => (std::mem::take(&mut g.buf), g.error.clone()),
                    Err(_) => (Vec::new(), None),
                };
                err.set(e);
                if !new.is_empty() {
                    let mut r = rows.write();
                    r.extend(new);
                    let over = r.len().saturating_sub(3000);
                    r.drain(..over);
                }
            }
        }
    });

    let f = filter().to_lowercase();
    let shown: Vec<Value> = rows
        .read()
        .iter()
        .rev()
        .filter(|e| {
            f.is_empty()
                || model::describe(e).to_lowercase().contains(&f)
                || text(e, &["type"]).contains(&f)
        })
        .take(600)
        .cloned()
        .collect();
    let n = rows.read().len();
    let nav = shown.clone();
    rsx! {
        div { class: "bar",
            h2 { "Live" }
            input { placeholder: "filter what is shown…", value: "{filter}", oninput: move |e| filter.set(e.value()) }
            button { class: "btn", onclick: move |_| paused.set(!paused()), if paused() { "▶ Resume" } else { "⏸ Pause" } }
            button { class: "btn", onclick: move |_| rows.write().clear(), "Clear" }
            label { class: "muted", input { r#type: "checkbox", checked: wrap(), onchange: move |e| wrap.set(e.checked()) } " wrap long lines" }
            span { class: "muted", "{n} received" }
        }
        if let Some(e) = err() { Failure { msg: format!("stream interrupted, retrying: {e}") } }
        div { class: "split",
            div { class: if wrap() { "list wrap" } else { "list" }, tabindex: "0",
                onkeydown: move |e| if let Some(d) = key_delta(&e) { e.prevent_default(); picked.set(model::step(&nav, picked().as_ref(), d)); },
                if shown.is_empty() { div { class: "empty", "Waiting for activity…" } }
                for e in shown {
                    EventRow { key: "{e[\"seq\"]}", e: e.clone(), selected: picked().as_ref().is_some_and(|p| p["seq"] == e["seq"]), onpick: move |v| picked.set(Some(v)) }
                }
            }
            Detail { e: picked() }
        }
    }
}

// ---- search -----------------------------------------------------------------------------

#[component]
fn SearchPage() -> Element {
    let client = use_context::<Client>();
    let mut applied = use_context::<Signal<Query>>();
    let mut draft = use_signal(|| applied.cloned());
    let mut picked = use_signal(|| None::<Value>);
    let mut extra = use_signal(Vec::<Value>::new);
    let mut cursor = use_signal(|| None::<u64>);
    let mut exported = use_signal(|| None::<String>);
    let mut wrap = use_signal(|| false);
    let mut fmt = use_signal(|| "ndjson".to_string());

    let c = client.clone();
    let res = use_resource(move || {
        let (c, q) = (c.clone(), applied());
        async move {
            let r = get(&c, q.url(None, 200)).await;
            if let Ok(v) = &r {
                cursor.set(v["next_cursor"].as_u64());
                extra.set(Vec::new());
            }
            r
        }
    });
    let c = client.clone();
    let more = move |_| {
        let (c, q, cur) = (c.clone(), applied(), cursor());
        spawn(async move {
            if let Ok(v) = get(&c, q.url(cur, 200)).await {
                cursor.set(v["next_cursor"].as_u64());
                extra.write().extend(events_of(&v));
            }
        });
    };
    let c = client.clone();
    let export = move |_| {
        let (c, q, f) = (c.clone(), applied(), fmt());
        spawn(async move {
            let url = if f == "bundle" {
                "/v1/export?format=bundle".to_string()
            } else {
                format!("{}&format={f}&max=50000", q.url(None, 1000))
            };
            let out = off(move || c.get_bytes(&url).map_err(|e| e.to_string())).await;
            exported.set(Some(match out {
                Some(Ok(body)) => {
                    let ext = if f == "bundle" { "tar" } else { f.as_str() };
                    let name = format!(
                        "witness-export-{}.{ext}",
                        model::fmt_time(now_ns()).replace([' ', ':'], "-"),
                    );
                    let dir = std::env::var_os("HOME")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_default()
                        .join("Downloads");
                    let path = if dir.is_dir() {
                        dir.join(&name)
                    } else {
                        std::path::PathBuf::from(&name)
                    };
                    match std::fs::write(&path, body) {
                        Ok(()) => format!("saved {}", path.display()),
                        Err(e) => format!("could not save: {e}"),
                    }
                }
                Some(Err(e)) => format!("export failed: {e}"),
                None => "export cancelled".into(),
            }));
        });
    };

    rsx! {
        div { class: "bar",
            h2 { "Search" }
            input { placeholder: "text: command, path, name…", value: "{draft().q}", style: "min-width:260px",
                oninput: move |e| draft.write().q = e.value(),
                onkeydown: move |e| if e.key() == Key::Enter { applied.set(draft()) } }
            datalist { id: "kinds", for k in model::KINDS { option { value: "{k}" } } }
            input { list: "kinds", placeholder: "kind: start typing…", value: "{draft().kind}", oninput: move |e| draft.write().kind = e.value(),
                onkeydown: move |e| if e.key() == Key::Enter { applied.set(draft()) } }
            select { onchange: move |e| { let s = e.value().parse::<u64>().ok(); let mut d = draft.write(); d.last_secs = s; d.from = None; d.to = None; },
                option { value: "", "any time" }
                option { value: "900", "last 15 min" } option { value: "3600", "last hour" }
                option { value: "86400", "last 24 h" } option { value: "604800", "last 7 days" }
            }
            button { class: "btn primary", onclick: move |_| applied.set(draft()), "Search" }
            select { onchange: move |e| fmt.set(e.value()), option { value: "ndjson", "ndjson" } option { value: "json", "json" } option { value: "csv", "csv" } option { value: "bundle", "incident bundle (tar)" } }
            button { class: "btn", onclick: export, "Export results" }
            label { class: "muted", input { r#type: "checkbox", checked: wrap(), onchange: move |e| wrap.set(e.checked()) } " wrap long lines" }
        }
        if let Some(m) = exported() { div { class: "conn", "{m}" } }
        {
            let (puid, ses) = (applied().puid, applied().ses);
            rsx! {
                if !puid.is_empty() { div { class: "conn", "Showing process {puid}" } }
                if !ses.is_empty() { div { class: "conn", "Showing session {ses}" } }
            }
        }
        match &*res.read() {
            None => rsx! { div { class: "empty", "searching…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(v)) => {
                let mut all = events_of(v);
                all.extend(extra.read().iter().cloned());
                let nav = all.clone();
                rsx! {
                    div { class: "split",
                        div { class: if wrap() { "list wrap" } else { "list" }, tabindex: "0",
                            onkeydown: move |e| if let Some(d) = key_delta(&e) { e.prevent_default(); picked.set(model::step(&nav, picked().as_ref(), d)); },
                            if all.is_empty() { div { class: "empty", "Nothing matches." } }
                            for e in all {
                                EventRow { key: "{e[\"seq\"]}", e: e.clone(), selected: picked().as_ref().is_some_and(|p| p["seq"] == e["seq"]), onpick: move |v| picked.set(Some(v)) }
                            }
                            if cursor().is_some() { div { class: "empty", button { class: "btn", onclick: more.clone(), "Load older" } } }
                        }
                        Detail { e: picked() }
                    }
                }
            }
        }
    }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// ---- alerts -----------------------------------------------------------------------------

#[component]
fn AlertsPage() -> Element {
    let client = use_context::<Client>();
    let mut tick = use_signal(|| 0u32);
    let mut picked = use_signal(|| None::<Value>);
    let mut note = use_signal(String::new);
    let c = client.clone();
    let res = use_resource(move || {
        let c = c.clone();
        let _ = tick();
        async move { get(&c, "/v1/alerts?limit=300".into()).await }
    });
    let c = client.clone();
    let triage = move |status: &'static str| {
        let (c, a, n) = (c.clone(), picked(), note());
        spawn(async move {
            if let Some(a) = a {
                let seq = a["seq"].as_u64().unwrap_or(0);
                let body = json!({"status": status, "note": n});
                let _ = off(move || c.post(&format!("/v1/alerts/{seq}/triage"), &body)).await;
                tokio::time::sleep(Duration::from_millis(900)).await;
                tick += 1;
            }
        });
    };
    rsx! {
        div { class: "bar", h2 { "Alerts" } button { class: "btn", onclick: move |_| tick += 1, "Refresh" } }
        match &*res.read() {
            None => rsx! { div { class: "empty", "loading…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(v)) => {
                let list = events_of(v);
                rsx! {
                    div { class: "split",
                        div { class: "list",
                            if list.is_empty() { div { class: "empty", "No alerts. Rules are watching." } }
                            for a in list {
                                {
                                    let sev = text(&a, &["data", "severity"]).to_string();
                                    let st = text(&a, &["triage", "status"]).to_string();
                                    let tone = if sev == "critical" || sev == "high" { "bad" } else if sev == "medium" { "warn" } else { "note" };
                                    let a2 = a.clone();
                                    let when = model::fmt_time(a["wall_ns"].as_u64().unwrap_or(0));
                                    let title = text(&a, &["data", "title"]).to_string();
                                    rsx! {
                                        div { key: "{a[\"seq\"]}", class: "row", onclick: move |_| { picked.set(Some(a2.clone())); note.set(String::new()); },
                                            span { class: "t", "{when}" }
                                            span { span { class: "pill {tone}", "{sev}" } " " span { class: "muted", "{st}" } }
                                            span { class: "d", "{title}" }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "detail",
                            match picked() {
                                None => rsx! { span { class: "muted", "Select an alert." } },
                                Some(a) => {
                                    let rule = text(&a, &["data", "rule_id"]).to_string();
                                    let title = text(&a, &["data", "title"]).to_string();
                                    let detail = serde_json::to_string_pretty(&a["data"]["detail"]).unwrap_or_default();
                                    let seqs: Vec<u64> = a["data"]["trigger_seqs"].as_array().map(|x| x.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
                                    let (t1, t2, t3) = (triage.clone(), triage.clone(), triage.clone());
                                    rsx! {
                                        h3 { "{title}" }
                                        dl { class: "kv", dt { "rule" } dd { "{rule}" } dt { "alert #" } dd { "{a[\"seq\"]}" } }
                                        pre { class: "json", "{detail}" }
                                        h3 { "Events that triggered it" }
                                        for s in seqs { TriggerEvent { seq: s } }
                                        h3 { "Triage" }
                                        input { placeholder: "note (optional)", value: "{note}", oninput: move |e| note.set(e.value()), style: "width:100%" }
                                        div { class: "actions",
                                            button { class: "btn", onclick: move |_| t1("acknowledged"), "Acknowledge" }
                                            button { class: "btn", onclick: move |_| t2("false_positive"), "False positive" }
                                            button { class: "btn", onclick: move |_| t3("new"), "Reopen" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn TriggerEvent(seq: u64) -> Element {
    let client = use_context::<Client>();
    let res = use_resource(move || {
        let c = client.clone();
        async move { get(&c, format!("/v1/events/{seq}")).await }
    });
    let state = res.read();
    match &*state {
        Some(Ok(e)) => {
            let d = model::describe(e);
            let t = model::fmt_time(e["wall_ns"].as_u64().unwrap_or(0));
            rsx! { div { class: "muted", "#{seq} {t} " span { style: "color:var(--text)", "{d}" } } }
        }
        Some(Err(e)) => rsx! { div { class: "muted", "#{seq}: {e}" } },
        None => rsx! { div { class: "muted", "#{seq} …" } },
    }
}

// ---- timeline ---------------------------------------------------------------------------

#[component]
fn TimelinePage() -> Element {
    let client = use_context::<Client>();
    let mut page = use_context::<Signal<Page>>();
    let mut search = use_context::<Signal<Query>>();
    let mut span_secs = use_signal(|| 3600u64);
    let res = use_resource(move || {
        let (c, s) = (client.clone(), span_secs());
        async move {
            let to = now_ns();
            let from = to - s * 1_000_000_000;
            get(&c, format!("/v1/timeline?from={from}&to={to}&buckets=90")).await
        }
    });
    rsx! {
        div { class: "bar",
            h2 { "Timeline" }
            select { onchange: move |e| span_secs.set(e.value().parse().unwrap_or(3600)),
                option { value: "900", "15 minutes" } option { value: "3600", selected: true, "1 hour" }
                option { value: "21600", "6 hours" } option { value: "86400", "24 hours" } option { value: "604800", "7 days" }
            }
        }
        match &*res.read() {
            None => rsx! { div { class: "empty", "loading…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(v)) => {
                let n = v["buckets"].as_u64().unwrap_or(0) as usize;
                let (from, step) = (v["from"].as_u64().unwrap_or(0), v["step_ns"].as_u64().unwrap_or(1));
                let mut total = vec![0u64; n];
                let mut kinds: Vec<(String, u64)> = Vec::new();
                if let Some(m) = v["series"].as_object() {
                    for (k, arr) in m {
                        let a: Vec<u64> = arr.as_array().map(|x| x.iter().map(|y| y.as_u64().unwrap_or(0)).collect()).unwrap_or_default();
                        for (i, c) in a.iter().enumerate() {
                            if let Some(t) = total.get_mut(i) { *t += c; }
                        }
                        kinds.push((k.clone(), a.iter().sum()));
                    }
                }
                kinds.sort_by_key(|k| std::cmp::Reverse(k.1));
                let bars = model::scale_bars(&total);
                let (lo, hi) = (model::fmt_time(from), model::fmt_time(from + step * n as u64));
                rsx! {
                    div { class: "page",
                        div { class: "chart",
                            for (i, h) in bars.iter().enumerate() {
                                div { key: "{i}", class: "bar1", style: "height:{h}%", title: "{total[i]} events",
                                    onclick: move |_| {
                                        let a = from + step * i as u64;
                                        search.set(Query { from: Some(a), to: Some(a + step), ..Query::default() });
                                        page.set(Page::Search);
                                    } }
                            }
                        }
                        div { class: "axis", span { "{lo}" } span { "click a bar to see its events" } span { "{hi}" } }
                        h3 { style: "padding:0 14px", "By kind" }
                        table {
                            for (k, c) in kinds {
                                tr { class: "click", key: "{k}", onclick: { let k = k.clone(); move |_| {
                                        search.set(Query { kind: k.clone(), from: Some(from), to: Some(from + step * n as u64), ..Query::default() });
                                        page.set(Page::Search);
                                    } },
                                    td { "{k}" } td { "{c}" } }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---- processes --------------------------------------------------------------------------

#[component]
fn TreeNode(n: ProcNode, depth: u32) -> Element {
    let mut open = use_signal(|| depth < 2);
    let mut page = use_context::<Signal<Page>>();
    let mut search = use_context::<Signal<Query>>();
    let exited = n.exited.is_some();
    let kids = n.children.len();
    let puid = n.puid.clone();
    let arrow = if kids == 0 {
        "·"
    } else if open() {
        "▾"
    } else {
        "▸"
    };
    let when = model::fmt_time(n.started);
    rsx! {
        div { class: "node", class: if exited { "exited" },
            span { onclick: move |_| open.set(!open()), style: "display:inline-block;width:14px", "{arrow}" }
            span { onclick: move |_| { search.set(Query { puid: puid.clone(), ..Query::default() }); page.set(Page::Search); },
                title: "{n.puid}",
                "{n.pid} " b { "{n.comm}" } " {n.cmd}" span { class: "muted", "  {n.user} {when}" }
                if kids > 0 && !open() { span { class: "muted", "  (+{kids})" } }
            }
        }
        if open() && kids > 0 {
            div { class: "kids",
                for c in n.children.iter().cloned() { TreeNode { key: "{c.puid}", n: c, depth: depth + 1 } }
            }
        }
    }
}

#[component]
fn ProcessesPage() -> Element {
    let client = use_context::<Client>();
    let mut tick = use_signal(|| 0u32);
    let res = use_resource(move || {
        let c = client.clone();
        let _ = tick();
        async move {
            let r = get(
                &c,
                "/v1/events?kind=proc_exec&kind=proc_exit&limit=1000".into(),
            )
            .await?;
            Ok::<Vec<ProcNode>, String>(model::process_forest(&events_of(&r)))
        }
    });
    rsx! {
        div { class: "bar", h2 { "Process tree" } button { class: "btn", onclick: move |_| tick += 1, "Refresh" }
            span { class: "muted", "the most recent 1000 process events; click a process for everything it did" } }
        match &*res.read() {
            None => rsx! { div { class: "empty", "loading…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(f)) => rsx! {
                div { class: "page tree",
                    if f.is_empty() { div { class: "empty", "No process events yet." } }
                    for n in f.iter().rev().cloned() { TreeNode { key: "{n.puid}", n: n, depth: 0 } }
                }
            },
        }
    }
}

// ---- sessions ---------------------------------------------------------------------------

#[component]
fn SessionsPage() -> Element {
    let client = use_context::<Client>();
    let mut page = use_context::<Signal<Page>>();
    let mut search = use_context::<Signal<Query>>();
    let res = use_resource(move || {
        let c = client.clone();
        async move {
            let r = get(&c, "/v1/events?limit=1000".into()).await?;
            Ok::<_, String>(model::sessions(&events_of(&r)))
        }
    });
    rsx! {
        div { class: "bar", h2 { "Sessions" } span { class: "muted", "from the most recent 1000 events" } }
        match &*res.read() {
            None => rsx! { div { class: "empty", "loading…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(rows)) => rsx! {
                div { class: "page",
                    table {
                        tr { th { "session" } th { "user" } th { "first seen" } th { "last seen" } th { "events" } th { "commands" } }
                        for r in rows.iter().cloned() {
                            tr { class: "click", key: "{r.ses}", onclick: move |_| { search.set(Query { ses: r.ses.to_string(), ..Query::default() }); page.set(Page::Search); },
                                td { "{r.ses}" } td { "{r.user}" } td { "{model::fmt_time(r.first)}" } td { "{model::fmt_time(r.last)}" }
                                td { "{r.events}" } td { "{r.commands}" } }
                        }
                    }
                }
            },
        }
    }
}

// ---- dashboard --------------------------------------------------------------------------

#[component]
fn DashboardPage() -> Element {
    let client = use_context::<Client>();
    let mut page = use_context::<Signal<Page>>();
    let mut tick = use_signal(|| 0u32);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            tick += 1;
        }
    });
    let res = use_resource(move || {
        let c = client.clone();
        let _ = tick();
        async move { get(&c, "/v1/dashboard".into()).await }
    });
    rsx! {
        div { class: "bar", h2 { "Dashboard" } span { class: "muted", "last 15 minutes, refreshed every 5 s" } }
        match &*res.read() {
            None => rsx! { div { class: "empty", "loading…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(d)) => {
                let rate = d["events_per_sec"].as_f64().unwrap_or(0.0);
                let alerts = d["recent_alerts"].as_array().cloned().unwrap_or_default();
                let kinds: Vec<(String, u64)> = d["by_kind"].as_array().map(|a| a.iter().map(|k| (text(k, &["kind"]).to_string(), k["count"].as_u64().unwrap_or(0))).collect()).unwrap_or_default();
                let bars = model::scale_bars(&kinds.iter().map(|k| k.1).collect::<Vec<_>>());
                // Latest status per source.
                let mut health: Vec<(String, String, String)> = Vec::new();
                for h in d["source_health"].as_array().into_iter().flatten() {
                    let s = text(h, &["data", "source"]).to_string();
                    if !health.iter().any(|x| x.0 == s) {
                        health.push((s, text(h, &["data", "status"]).to_string(), text(h, &["data", "reason"]).to_string()));
                    }
                }
                health.sort();
                rsx! {
                    div { class: "page",
                        div { class: "cards",
                            div { class: "card", div { class: "n", "{rate:.1}" } div { class: "l", "events / second" } }
                            div { class: "card", div { class: "n", "{d[\"head_seq\"]}" } div { class: "l", "records in the chain" } }
                            div { class: "card", div { class: "n", "{alerts.len()}" } div { class: "l", "recent alerts" } }
                            div { class: "card", div { class: "n", "{d[\"uptime_secs\"]} s" } div { class: "l", "daemon uptime" } }
                        }
                        h3 { style: "padding:0 14px", "Capture sources" }
                        table {
                            for (s, st, why) in health {
                                tr { key: "{s}", td { "{s}" } td { span { class: if st == "active" { "pill ok" } else { "pill warn" }, "{st}" } } td { class: "muted", "{why}" } }
                            }
                        }
                        h3 { style: "padding:0 14px", "Busiest event kinds" }
                        table {
                            for (i, (k, c)) in kinds.iter().take(12).enumerate() {
                                tr { key: "{k}", td { "{k}" } td { "{c}" } td { style: "width:50%", div { style: "height:8px;background:var(--accent);border-radius:4px;width:{bars[i]}%" } } }
                            }
                        }
                        h3 { style: "padding:0 14px", "Latest alerts" }
                        table {
                            if alerts.is_empty() { tr { td { class: "muted", "none" } } }
                            for a in alerts { tr { class: "click", key: "{a[\"seq\"]}", onclick: move |_| page.set(Page::Alerts),
                                td { "{model::fmt_time(a[\"wall_ns\"].as_u64().unwrap_or(0))}" } td { "{text(&a, &[\"data\", \"severity\"])}" } td { "{text(&a, &[\"data\", \"title\"])}" } } }
                        }
                    }
                }
            }
        }
    }
}

// ---- integrity --------------------------------------------------------------------------

#[component]
fn IntegrityPage() -> Element {
    let client = use_context::<Client>();
    let mut tick = use_signal(|| 0u32);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            tick += 1;
        }
    });
    let c = client.clone();
    let res = use_resource(move || {
        let c = c.clone();
        let _ = tick();
        async move { get(&c, "/v1/integrity".into()).await }
    });
    let start = move |_| {
        let c = client.clone();
        spawn(async move {
            let _ = off(move || c.post("/v1/integrity/verify", &json!({}))).await;
            tick += 1;
        });
    };
    rsx! {
        div { class: "bar", h2 { "Integrity" } button { class: "btn primary", onclick: start, "Verify the whole chain now" } }
        match &*res.read() {
            None => rsx! { div { class: "empty", "loading…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(v)) => {
                let state = text(v, &["state"]).to_string();
                let (cls, msg) = match state.as_str() {
                    "ok" => ("ok", "The hash chain is intact."),
                    "broken" => ("bad", "THE CHAIN IS BROKEN: evidence was modified, removed or reordered."),
                    "running" => ("note", "Verifying…"),
                    "error" => ("bad", "Verification could not run."),
                    _ => ("note", "Not verified since the daemon started."),
                };
                rsx! {
                    div { class: "page", style: "padding:14px",
                        p { span { class: "pill {cls}", "{msg}" } }
                        if state == "ok" || state == "broken" {
                            dl { class: "kv",
                                dt { "records" } dd { "{v[\"records\"]}" }
                                dt { "segments" } dd { "{v[\"segments\"]}" }
                                dt { "head" } dd { "#{v[\"head_seq\"]}  {text(v, &[\"head_hash\"])}" }
                                dt { "seals" } dd { "{v[\"seals\"]}" }
                                dt { "anchors checked" } dd { "{v[\"anchors_checked\"]}" }
                                dt { "seal MACs" } dd { if v["macs_checked"] == true { "verified" } else { "not checked (needs the admin-held key: witness verify --key)" } }
                                if v["partial_start"] == true { dt { "history" } dd { "starts after pruned or archived segments" } }
                                if !v["broken"].is_null() { dt { "problem" } dd { "{v[\"broken\"]}" } }
                            }
                        }
                        if state == "error" { p { "{text(v, &[\"detail\"])}" } }
                        p { class: "muted", "This checks the chain as stored on this machine. Someone with root can rewrite history and the chain with it; compare the head against an anchor recorded elsewhere (witness anchor)." }
                    }
                }
            }
        }
    }
}

// ---- rules ------------------------------------------------------------------------------

#[component]
fn RulesPage() -> Element {
    let client = use_context::<Client>();
    let mut tick = use_signal(|| 0u32);
    let mut draft = use_signal(|| {
        "id: my.rule\ntitle: My rule\nseverity: low\nevent: proc_exec\nmatch:\n  all:\n    - { field: data.exe, op: endswith, value: /example }\n".to_string()
    });
    let mut verdict = use_signal(|| None::<String>);
    let c = client.clone();
    let res = use_resource(move || {
        let c = c.clone();
        let _ = tick();
        async move { get(&c, "/v1/rules".into()).await }
    });
    let c = client.clone();
    let validate = move |_| {
        let (c, y) = (c.clone(), draft());
        spawn(async move {
            let r = off(move || {
                c.post("/v1/rules/validate", &json!({"yaml": y}))
                    .map_err(|e| e.to_string())
            })
            .await;
            verdict.set(Some(match r {
                Some(Ok(v)) if v["ok"] == true => "The rule compiles.".into(),
                Some(Ok(v)) => v["errors"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|e| format!("line {}: {}", e["line"], text(e, &["message"])))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default(),
                Some(Err(e)) => e,
                None => "cancelled".into(),
            }));
        });
    };
    let c = client.clone();
    let save = move |_| {
        let (c, y) = (c.clone(), draft());
        spawn(async move {
            let id = y
                .lines()
                .find_map(|l| l.strip_prefix("id:"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let r = off(move || {
                c.put(&format!("/v1/rules/{}", encode(&id)), &json!({"yaml": y}))
                    .map_err(|e| e.to_string())
            })
            .await;
            verdict.set(Some(match r {
                Some(Ok(_)) => "Saved. The daemon reloads rules within a few seconds.".into(),
                Some(Err(e)) => e,
                None => "cancelled".into(),
            }));
            tokio::time::sleep(Duration::from_secs(1)).await;
            tick += 1;
        });
    };
    rsx! {
        div { class: "bar", h2 { "Rules" } button { class: "btn", onclick: move |_| tick += 1, "Refresh" } }
        match &*res.read() {
            None => rsx! { div { class: "empty", "loading…" } },
            Some(Err(e)) => rsx! { Failure { msg: e.clone() } },
            Some(Ok(v)) => {
                let rules = v["rules"].as_array().cloned().unwrap_or_default();
                let errors = v["errors"].as_array().cloned().unwrap_or_default();
                rsx! {
                    div { class: "page",
                        for e in errors { Failure { msg: format!("rejected: {}", e.as_str().unwrap_or("")) } }
                        table {
                            tr { th { "id" } th { "title" } th { "severity" } th { "state" } th { "" } }
                            for r in rules {
                                {
                                    let id = text(&r, &["id"]).to_string();
                                    let on = r["enabled"] == true;
                                    let (c, id2) = (client.clone(), id.clone());
                                    rsx! { tr { key: "{id}", td { "{id}" } td { "{text(&r, &[\"title\"])}" } td { "{text(&r, &[\"severity\"])}" }
                                        td { span { class: if on { "pill ok" } else { "pill warn" }, if on { "enabled" } else { "disabled" } } }
                                        td { button { class: "btn", onclick: move |_| {
                                            let (c, id, act) = (c.clone(), id2.clone(), if on { "disable" } else { "enable" });
                                            spawn(async move {
                                                let _ = off(move || c.post(&format!("/v1/rules/{}/{act}", encode(&id)), &json!({}))).await;
                                                tokio::time::sleep(Duration::from_millis(500)).await;
                                                tick += 1;
                                            });
                                        }, if on { "Disable" } else { "Enable" } } } } }
                                }
                            }
                        }
                        h3 { style: "padding:0 14px", "Write or edit a rule" }
                        div { style: "padding:0 14px",
                            textarea { value: "{draft}", oninput: move |e| draft.set(e.value()) }
                            div { class: "actions",
                                button { class: "btn", onclick: validate, "Validate" }
                                button { class: "btn primary", onclick: save, "Save (needs admin)" }
                            }
                            if let Some(m) = verdict() { pre { class: "json", "{m}" } }
                        }
                    }
                }
            }
        }
    }
}
