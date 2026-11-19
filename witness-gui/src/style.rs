//! The GUI's stylesheet. Colours are tokens on `:root`; dark mode follows the OS.

pub const CSS: &str = r#"
:root {
  --bg: #f6f7f9; --panel: #ffffff; --line: #dde1e7; --text: #1b2330; --muted: #667085;
  --accent: #2557d6; --accent-bg: #e8eefc; --bad: #c62828; --bad-bg: #fdeaea;
  --warn: #a15c00; --warn-bg: #fff3dc; --ok: #1b7f3b; --ok-bg: #e6f5ea; --note: #35607a;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12161d; --panel: #1a2029; --line: #2b3441; --text: #e4e8ef; --muted: #8b95a5;
    --accent: #7ba3ff; --accent-bg: #1f2c4a; --bad: #ff8a80; --bad-bg: #3a1f22;
    --warn: #f2b45a; --warn-bg: #3a2c12; --ok: #6fd18b; --ok-bg: #16301f; --note: #8fb8d4;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; background: var(--bg); color: var(--text);
  font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
.app { display: grid; grid-template-columns: 188px 1fr; height: 100vh; }
.nav { background: var(--panel); border-right: 1px solid var(--line); padding: 14px 10px; display: flex; flex-direction: column; gap: 2px; }
.brand { font-weight: 700; font-size: 15px; padding: 2px 8px 12px; letter-spacing: .02em; }
.nav button { all: unset; cursor: pointer; padding: 7px 10px; border-radius: 6px; color: var(--muted); }
.nav button:hover { background: var(--bg); color: var(--text); }
.nav button.on { background: var(--accent-bg); color: var(--accent); font-weight: 600; }
.nav .spacer { flex: 1; }
.conn { font-size: 11px; padding: 6px 10px; color: var(--muted); }
.conn b { color: var(--ok); } .conn b.down { color: var(--bad); }
.main { display: flex; flex-direction: column; min-width: 0; height: 100vh; }
.bar { display: flex; gap: 8px; padding: 10px 14px; border-bottom: 1px solid var(--line); background: var(--panel); align-items: center; flex-wrap: wrap; }
.bar h2 { margin: 0 12px 0 0; font-size: 15px; }
input, select, button.btn { font: inherit; padding: 5px 9px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--text); }
input:focus, select:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
button.btn { cursor: pointer; } button.btn:hover { border-color: var(--accent); }
button.btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.split { display: grid; grid-template-columns: 1fr minmax(320px, 38%); flex: 1; min-height: 0; }
.list { overflow: auto; min-width: 0; }
.detail { overflow: auto; border-left: 1px solid var(--line); background: var(--panel); padding: 12px 14px; }
.row { display: grid; grid-template-columns: 176px 150px 1fr; gap: 14px; padding: 3px 14px; border-bottom: 1px solid var(--line); cursor: pointer; align-items: baseline; }
.row:hover { background: var(--accent-bg); } .row.sel { background: var(--accent-bg); box-shadow: inset 3px 0 var(--accent); }
.row .t { color: var(--muted); font-family: var(--mono); font-size: 12px; white-space: nowrap; }
.row .k { font-family: var(--mono); font-size: 12px; color: var(--note); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.row .d { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.row.bad .d { color: var(--bad); font-weight: 600; } .row.warn .d { color: var(--warn); } .row.faint .d { color: var(--muted); }
.row.strong .d { font-weight: 600; } .row.note .d { color: var(--note); }
.list:focus { outline: none; }
.wrap .row { align-items: start; }
.wrap .row .d, .wrap .row .k { white-space: normal; overflow: visible; word-break: break-word; }
.empty { padding: 40px; text-align: center; color: var(--muted); }
.error { margin: 14px; padding: 10px 12px; background: var(--bad-bg); color: var(--bad); border-radius: 6px; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.pill.bad { background: var(--bad-bg); color: var(--bad); } .pill.warn { background: var(--warn-bg); color: var(--warn); }
.pill.ok { background: var(--ok-bg); color: var(--ok); } .pill.note { background: var(--accent-bg); color: var(--accent); }
.kv { display: grid; grid-template-columns: 110px 1fr; gap: 3px 10px; margin: 8px 0; }
.kv dt { color: var(--muted); } .kv dd { margin: 0; font-family: var(--mono); font-size: 12px; word-break: break-all; }
pre.json { background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 10px; overflow: auto; font: 12px/1.45 var(--mono); max-height: 46vh; }
h3 { margin: 16px 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; padding: 14px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.card .n { font-size: 26px; font-weight: 700; } .card .l { color: var(--muted); }
.page { overflow: auto; flex: 1; padding-bottom: 20px; }
.chart { display: flex; align-items: flex-end; gap: 2px; height: 160px; padding: 8px 14px 0; }
.chart .bar1 { flex: 1; background: var(--accent); min-height: 1px; border-radius: 2px 2px 0 0; opacity: .85; }
.chart .bar1:hover { opacity: 1; }
.axis { display: flex; justify-content: space-between; padding: 4px 14px; color: var(--muted); font-size: 11px; font-family: var(--mono); }
.tree { padding: 8px 14px; font-family: var(--mono); font-size: 12px; }
.tree .node { padding: 1px 0; white-space: nowrap; } .tree .node:hover { background: var(--accent-bg); cursor: pointer; }
.tree .kids { margin-left: 16px; border-left: 1px solid var(--line); padding-left: 8px; }
.tree .exited { color: var(--muted); opacity: .75; }
table { border-collapse: collapse; width: 100%; } th { text-align: left; color: var(--muted); font-weight: 600; padding: 6px 14px; border-bottom: 1px solid var(--line); }
td { padding: 5px 14px; border-bottom: 1px solid var(--line); } tr.click:hover { background: var(--accent-bg); cursor: pointer; }
.actions { display: flex; gap: 6px; margin: 10px 0; flex-wrap: wrap; }
textarea { width: 100%; min-height: 220px; font: 12px/1.45 var(--mono); background: var(--bg); color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 8px; }
.muted { color: var(--muted); }
"#;
