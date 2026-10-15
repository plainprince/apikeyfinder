//! Interactive info reader — ratatui TUI for browsing findings.
//!
//! Layout: header (totals) · left: collapsible tree — STATS (expanded) ·
//! bad/trivial (collapsed by default) → detectors → findings ·
//! right: details pane (stats views, category/detector summaries, findings) ·
//! footer (key bindings). `Enter`/`Space` opens and closes any category,
//! so the hundreds of trivial findings never flood the list.
//! `e` exports the selection as a text file; a left click in the details
//! pane copies that line (the value row copies the full secret). `m` toggles
//! mouse capture on/off — leave it off to use the terminal's own selection.
//! Opened by `findings_viewer` with no command.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{stdout, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};
use unicode_width::UnicodeWidthStr;

use super::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Filter {
    All,
    Bad,
    Trivial,
}

impl Filter {
    fn includes(self, c: Cat) -> bool {
        match self {
            Filter::All => true,
            Filter::Bad => c == Cat::Bad,
            Filter::Trivial => c == Cat::Trivial,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::Bad => "bad",
            Filter::Trivial => "trivial",
        }
    }

    fn next(self) -> Self {
        match self {
            Filter::All => Filter::Bad,
            Filter::Bad => Filter::Trivial,
            Filter::Trivial => Filter::All,
        }
    }
}

/// Collapsible nodes of the tree. Keyed per category so the same detector
/// name appearing under several severities (e.g. Algolia) stays independent.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Node {
    Stats,
    Category(Cat),
    Detector(Cat, String),
}

/// The stats category: one entry per sub-view shown underneath STATS.
const STAT_ITEMS: &[(&str, &str)] = &[
    ("overview", "totals across every detector"),
    ("by detector", "findings per detector, biggest first"),
    ("most duplicated keys", "the same secret seen again and again"),
    ("bad keys", "everything not designed to be public"),
    ("trivial keys", "browser-shipping keys, listed for completeness"),
];

/// One navigable line in the left pane.
#[derive(Debug)]
pub enum Row {
    /// Collapsible tree node: `bool` = expanded.
    Node(Node, usize, bool),
    /// A stats sub-view (index into STAT_ITEMS); only visible when STATS is open.
    Stat(usize),
    Finding(usize),
}

impl Row {
    fn node(&self) -> Option<Node> {
        match self {
            Row::Node(n, _, _) => Some(n.clone()),
            _ => None,
        }
    }
}

pub fn build_rows(findings: &[&Finding], state: &AppState) -> Vec<Row> {
    let mut rows = Vec::new();

    // STATS category first — always present, expanded by default.
    let stats_open = state.is_expanded(&Node::Stats);
    rows.push(Row::Node(
        Node::Stats,
        STAT_ITEMS.len(),
        stats_open,
    ));
    if stats_open {
        for i in 0..STAT_ITEMS.len() {
            rows.push(Row::Stat(i));
        }
    }

    for cat in [Cat::Bad, Cat::Trivial] {
        if !state.filter.includes(cat) {
            continue;
        }
        let idxs: Vec<usize> = findings
            .iter()
            .enumerate()
            .filter(|(_, f)| category(f) == cat)
            .map(|(i, _)| i)
            .collect();
        if idxs.is_empty() {
            continue;
        }
        let cat_node = Node::Category(cat);
        let cat_open = state.is_expanded(&cat_node);
        rows.push(Row::Node(cat_node.clone(), idxs.len(), cat_open));
        if !cat_open {
            continue;
        }
        // group by detector: biggest groups first, then alphabetical
        let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for i in idxs {
            groups.entry(findings[i].DetectorName.clone()).or_default().push(i);
        }
        let mut groups: Vec<(String, Vec<usize>)> = groups.into_iter().collect();
        groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        for (det, mut members) in groups {
            members.sort_by(|a, b| findings[*a].value().cmp(findings[*b].value()));
            let det_node = Node::Detector(cat, det);
            let det_open = state.is_expanded(&det_node);
            rows.push(Row::Node(det_node, members.len(), det_open));
            if det_open {
                rows.extend(members.into_iter().map(Row::Finding));
            }
        }
    }
    rows
}

pub struct AppState {
    pub sel: usize,
    pub filter: Filter,
    expanded: HashSet<Node>,
    list: ListState,
    /// transient footer message (export / copy feedback)
    pub status: Option<String>,
    /// mouse capture currently enabled (see `m`)
    pub mouse: bool,
    /// first visible row of the details pane (wheel-scrolled)
    pub detail_offset: usize,
    /// wrapped details rows for the current selection (rebuilt every draw)
    pub detail_rows: Vec<DetLine>,
    /// inner areas of the two panes, kept for mouse hit-testing
    pub detail_area: Rect,
    pub list_area: Rect,
}

impl AppState {
    /// STATS open, all finding categories collapsed — the initial screen is
    /// the stats + one line per bucket, never thousands of findings.
    pub fn new() -> Self {
        let mut expanded = HashSet::new();
        expanded.insert(Node::Stats);
        AppState {
            sel: 0,
            filter: Filter::All,
            expanded,
            list: ListState::default(),
            status: None,
            mouse: false,
            detail_offset: 0,
            detail_rows: Vec::new(),
            detail_area: Rect::default(),
            list_area: Rect::default(),
        }
    }

    pub fn move_by(&mut self, rows: &[Row], delta: isize) {
        self.detail_offset = 0;
        self.status = None;
        if rows.is_empty() {
            self.sel = 0;
            self.list.select(None);
            return;
        }
        let next = (self.sel as isize + delta).clamp(0, rows.len() as isize - 1);
        self.sel = next as usize;
        self.list.select(Some(self.sel));
    }

    /// Jump to a row by index (mouse click in the findings pane).
    pub fn select_row(&mut self, rows: &[Row], row: usize) {
        if row >= rows.len() {
            return;
        }
        self.sel = row;
        self.detail_offset = 0;
        self.list.select(Some(row));
    }

    pub fn list_offset(&self) -> usize {
        self.list.offset()
    }

    pub fn is_expanded(&self, node: &Node) -> bool {
        self.expanded.contains(node)
    }

    pub fn toggle(&mut self, node: &Node) {
        if !self.expanded.remove(node) {
            self.expanded.insert(node.clone());
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

fn cat_color(c: Cat) -> Color {
    match c {
        Cat::Bad => Color::Red,
        Cat::Trivial => Color::DarkGray,
    }
}

/// Severity rank — lower is worse. Used to color per-detector aggregates
/// with the worst category the detector appears in.
fn cat_rank(c: Cat) -> u8 {
    match c {
        Cat::Bad => 0,
        Cat::Trivial => 1,
    }
}

fn short(s: &str, max: usize) -> String {
    let flat = flatten(s);
    if flat.chars().count() <= max {
        flat
    } else {
        let cut: String = flat.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// Width-aware bar for the details pane (main stats view uses full width).
fn bar_w(count: usize, max: usize, width: usize) -> String {
    if max == 0 || count == 0 {
        return " ".repeat(width);
    }
    let units = ((count as f64 / max as f64) * (width * 8) as f64).round() as usize;
    let full = (units / 8).min(width);
    let rem = units % 8;
    let mut s = "█".repeat(full);
    if rem > 0 && full < width {
        s.push_str(PARTIALS[rem]);
    }
    while s.chars().count() < width {
        s.push(' ');
    }
    s
}

fn row_item(row: &Row, findings: &[&Finding]) -> ListItem<'static> {
    match row {
        Row::Node(node, n, expanded) => {
            let marker = if *expanded { "▾ " } else { "▸ " };
            let (text, style) = match node {
                Node::Stats => (
                    format!("{marker}{:<24} ({n})", "STATS"),
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Node::Category(cat) => (
                    format!("{marker}{:<22} ({n})", cat.label()),
                    Style::default()
                        .fg(cat_color(*cat))
                        .add_modifier(Modifier::BOLD),
                ),
                Node::Detector(_, det) => (
                    format!("   {det} ({n})"),
                    Style::default().fg(Color::Gray),
                ),
            };
            ListItem::new(Line::from(Span::styled(text, style)))
        }
        Row::Stat(i) => ListItem::new(Line::from(Span::styled(
            format!("   {}", STAT_ITEMS[*i].0),
            Style::default().fg(Color::Magenta),
        ))),
        Row::Finding(i) => {
            let f = findings[*i];
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("     {:<30}", short(f.value(), 30)),
                    Style::default().fg(Color::White),
                ),
                Span::styled(short(&f.site(), 22), Style::default().fg(Color::Cyan)),
            ]))
        }
    }
}

fn header_line(findings: &[&Finding], filter: Filter) -> Line<'static> {
    let mut counts = [0usize; 2]; // bad, trivial
    for f in findings {
        match category(f) {
            Cat::Bad => counts[0] += 1,
            Cat::Trivial => counts[1] += 1,
        }
    }
    let mut spans = vec![Span::styled(
        format!(" {} findings ", findings.len()),
        Style::default().add_modifier(Modifier::BOLD),
    )];
    for (cat, n) in [(Cat::Bad, counts[0]), (Cat::Trivial, counts[1])] {
        spans.push(Span::styled(
            format!("· {} {n} ", cat.label()),
            Style::default().fg(cat_color(cat)),
        ));
    }
    spans.push(Span::styled(
        format!("· showing: {}", filter.label()),
        Style::default().fg(Color::Gray),
    ));
    Line::from(spans)
}

fn footer_line(status: Option<&str>, mouse: bool) -> Line<'static> {
    let mouse_key = if mouse { "m mouse:on" } else { "m mouse" };
    let mut spans = Vec::new();
    if let Some(s) = status {
        spans.push(Span::styled(
            format!(" {s} "),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        format!(
            " j/k move · Enter open/close · Tab filter · e export · {mouse_key} · g/G ends · q quit"
        ),
        Style::default().fg(Color::DarkGray),
    ));
    Line::from(spans)
}

fn cat_blurb(c: Cat) -> &'static str {
    match c {
        Cat::Bad => "Verified secret with real access — rotate or revoke now.",
        Cat::Trivial => "Designed to ship to browsers — exposure carries no direct account risk.",
    }
}

// ---------------------------------------------------------------------------
// Stats sub-views (right pane content of the STATS category)
// ---------------------------------------------------------------------------

fn worst_cat(group: &[&Finding]) -> Cat {
    group
        .iter()
        .map(|f| category(f))
        .min_by_key(|c| cat_rank(*c))
        .unwrap_or(Cat::Bad)
}

fn stat_title(name: &str, blurb: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            name.to_string(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            blurb.to_string(),
            Style::default().fg(Color::DarkGray),
        )),
        Line::default(),
    ]
}

fn stat_overview(findings: &[&Finding]) -> Vec<Line<'static>> {
    let dets: BTreeSet<&str> = findings.iter().map(|f| f.DetectorName.as_str()).collect();
    let vals: BTreeMap<&str, usize> = {
        let mut m: BTreeMap<&str, usize> = BTreeMap::new();
        for f in findings {
            *m.entry(f.value()).or_default() += 1;
        }
        m
    };
    let repeats = vals.values().filter(|&&c| c > 1).count();
    let warcs: BTreeSet<String> = findings.iter().filter_map(|f| f.warc()).collect();
    let mut counts = [0usize; 2];
    for f in findings {
        match category(f) {
            Cat::Bad => counts[0] += 1,
            Cat::Trivial => counts[1] += 1,
        }
    }
    let bad_n = counts[0];
    let triv_n = counts[1];
    let bad_dets = findings
        .iter()
        .filter(|f| category(f) == Cat::Bad)
        .map(|f| &f.DetectorName)
        .collect::<BTreeSet<_>>()
        .len();
    let triv_dets = findings
        .iter()
        .filter(|f| category(f) == Cat::Trivial)
        .map(|f| &f.DetectorName)
        .collect::<BTreeSet<_>>()
        .len();

    let dim = Style::default().fg(Color::DarkGray);
    let num = |s: &str| Span::styled(format!("{s:>10}"), Style::default().fg(Color::White));
    let lbl = |s: &str| Span::styled(format!("{:<18} ", s), dim);

    vec![
        Line::from(Span::styled(
            "overview",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        Line::from(vec![lbl("findings"), num(&findings.len().to_string())]),
        Line::from(vec![lbl("detectors"), num(&dets.len().to_string())]),
        Line::from(vec![
            lbl("distinct keys"),
            num(&vals.len().to_string()),
            Span::styled(
                format!("  ({} repeat hits)", findings.len() - vals.len()),
                dim,
            ),
        ]),
        Line::from(vec![
            lbl("keys seen >1×"),
            num(&repeats.to_string()),
            Span::styled(format!("  (of {} distinct)", vals.len()), dim),
        ]),
        Line::from(vec![lbl("source warcs"), num(&warcs.len().to_string())]),
        Line::default(),
        Line::from(vec![
            Span::styled(format!("{:<18} ", "bad"), cat_color(Cat::Bad)),
            Span::styled(
                format!("{bad_n:>10}"),
                Style::default()
                    .fg(cat_color(Cat::Bad))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  across {bad_dets} detectors"), dim),
        ]),
        Line::from(vec![
            Span::styled(format!("{:<18} ", "trivial"), cat_color(Cat::Trivial)),
            Span::styled(format!("{triv_n:>10}"), cat_color(Cat::Trivial)),
            Span::styled(format!("  across {triv_dets} detectors"), dim),
        ]),
    ]
}

fn stat_by_detector(findings: &[&Finding]) -> Vec<Line<'static>> {
    let mut out = stat_title("findings by detector", STAT_ITEMS[1].1);
    let mut groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        groups.entry(&f.DetectorName).or_default().push(*f);
    }
    let mut groups: Vec<(&str, Vec<&Finding>)> = groups.into_iter().collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    let max = groups.first().map(|g| g.1.len()).unwrap_or(1);
    for (det, group) in groups.into_iter().take(15) {
        let n = group.len();
        let pct = n as f64 / findings.len() as f64 * 100.0;
        out.push(Line::from(vec![
            Span::styled(format!("  {:<22}", short(det, 22)), Style::default().fg(Color::White)),
            Span::styled(format!(" {n:>4} "), Style::default().fg(Color::Gray)),
            Span::styled(bar_w(n, max, 12), cat_color(worst_cat(&group))),
            Span::styled(format!(" {pct:>4.1}%"), Style::default().fg(Color::Gray)),
        ]));
    }
    out
}

fn stat_duplicates(findings: &[&Finding]) -> Vec<Line<'static>> {
    let mut out = stat_title("most duplicated keys", STAT_ITEMS[2].1);
    let mut by_value: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_value.entry(f.value()).or_default().push(*f);
    }
    let mut dups: Vec<(&str, Vec<&Finding>)> = by_value
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .collect();
    dups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    if dups.is_empty() {
        out.push(Line::from(Span::styled(
            "  no key appears more than once",
            Style::default().fg(Color::DarkGray),
        )));
        return out;
    }
    for (val, group) in dups.into_iter().take(15) {
        let n = group.len();
        let det = group[0].DetectorName.clone();
        let warcs = group
            .iter()
            .filter_map(|f| f.warc())
            .collect::<BTreeSet<_>>()
            .len();
        out.push(Line::from(vec![
            Span::styled(
                format!("{n:>4}× "),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(short(&det, 20), cat_color(worst_cat(&group))),
            Span::styled(format!("  {}", short(val, 24)), Style::default().fg(Color::Gray)),
            Span::styled(format!("  {warcs} warc(s)"), Style::default().fg(Color::DarkGray)),
        ]));
    }
    out
}

fn stat_bad(findings: &[&Finding], blurb: &str) -> Vec<Line<'static>> {
    let cat = Cat::Bad;
    let mut out = stat_title("bad keys", blurb);
    let group: Vec<&Finding> = findings
        .iter()
        .copied()
        .filter(|f| category(f) == cat)
        .collect();
    if group.is_empty() {
        out.push(Line::from(Span::styled(
            "  nothing bad found",
            Style::default().fg(Color::DarkGray),
        )));
        return out;
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &group {
        *counts.entry(&f.DetectorName).or_default() += 1;
    }
    let mut counts: Vec<(&str, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let max = counts.first().map(|c| c.1).unwrap_or(1);
    for (det, n) in counts {
        out.push(Line::from(vec![
            Span::styled(format!("    {:<24}", short(det, 24)), Style::default().fg(Color::Gray)),
            Span::styled(format!(" {n:>3} "), cat_color(cat)),
            Span::styled(bar_w(n, max, 10), cat_color(cat)),
        ]));
    }
    out
}

fn stat_trivial(findings: &[&Finding]) -> Vec<Line<'static>> {
    let mut out = stat_title("trivial keys", STAT_ITEMS[4].1);
    let group: Vec<&Finding> = findings
        .iter()
        .copied()
        .filter(|f| category(f) == Cat::Trivial)
        .collect();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &group {
        *counts.entry(&f.DetectorName).or_default() += 1;
    }
    let mut counts: Vec<(&str, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let max = counts.first().map(|c| c.1).unwrap_or(1);
    for (det, n) in counts {
        out.push(Line::from(vec![
            Span::styled(format!("  {:<24}", short(det, 24)), Style::default().fg(Color::Gray)),
            Span::styled(format!(" {n:>4} "), Style::default().fg(Color::Gray)),
            Span::styled(bar_w(n, max, 10), cat_color(Cat::Trivial)),
        ]));
    }
    out
}

fn stat_lines(idx: usize, findings: &[&Finding]) -> Vec<Line<'static>> {
    match idx {
        0 => stat_overview(findings),
        1 => stat_by_detector(findings),
        2 => stat_duplicates(findings),
        3 => stat_bad(findings, STAT_ITEMS[3].1),
        4 => stat_trivial(findings),
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Details pane
// ---------------------------------------------------------------------------

fn node_detail(node: &Node, n: usize, findings: &[&Finding]) -> Vec<Line<'static>> {
    let dim = Style::default().fg(Color::DarkGray);
    match node {
        Node::Stats => stat_overview(findings),
        Node::Category(cat) => {
            let mut out = vec![
                Line::from(Span::styled(
                    format!("{} ({n} findings)", cat.label()),
                    Style::default()
                        .fg(cat_color(*cat))
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(cat_blurb(*cat), dim)),
                Line::default(),
            ];
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for f in findings.iter().filter(|f| category(f) == *cat) {
                *counts.entry(&f.DetectorName).or_default() += 1;
            }
            let mut counts: Vec<(&str, usize)> = counts.into_iter().collect();
            counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            let max = counts.first().map(|c| c.1).unwrap_or(1);
            for (det, c) in counts {
                out.push(Line::from(vec![
                    Span::styled(format!("  {:<26}", short(det, 26)), Style::default().fg(Color::Gray)),
                    Span::styled(format!(" {c:>4} "), cat_color(*cat)),
                    Span::styled(bar_w(c, max, 8), cat_color(*cat)),
                ]));
            }
            out.push(Line::default());
            out.push(Line::from(Span::styled(
                "Enter to open detector groups",
                dim,
            )));
            out
        }
        Node::Detector(cat, det) => {
            let group: Vec<&&Finding> = findings
                .iter()
                .filter(|f| &f.DetectorName == det && category(f) == *cat)
                .collect();
            let mut out = vec![Line::from(Span::styled(
                format!("{det} ({n} findings)"),
                Style::default()
                    .fg(cat_color(*cat))
                    .add_modifier(Modifier::BOLD),
            ))];
            if let Some(f) = group.first() {
                out.push(Line::from(Span::styled(cat_blurb(*cat), dim)));
                if !f.DetectorDescription.is_empty() {
                    out.push(Line::default());
                    out.push(Line::from(f.DetectorDescription.clone()));
                }
                let sites: BTreeSet<String> = group.iter().map(|f| f.site()).filter(|s| s != "-").collect();
                let sites: Vec<String> = sites.into_iter().take(4).collect();
                if !sites.is_empty() {
                    out.push(Line::default());
                    out.push(Line::from(Span::styled(
                        format!("sites: {}", sites.join(", ")),
                        Style::default().fg(Color::Cyan),
                    )));
                }
                let annots: BTreeSet<String> = group.iter().filter_map(|f| annot(f)).collect();
                for a in annots.iter().take(4) {
                    out.push(Line::from(Span::styled(short(a, 200), dim)));
                }
            }
            out.push(Line::default());
            out.push(Line::from(Span::styled("Enter to list findings", dim)));
            out
        }
    }
}

/// One line of the details pane: styled spans plus the text a left click
/// copies for it (label-stripped, untruncated for value/snippet rows).
#[derive(Debug, Clone)]
pub struct DetLine {
    spans: Vec<Span<'static>>,
    copy: String,
}

impl DetLine {
    fn new(spans: Vec<Span<'static>>, copy: impl Into<String>) -> Self {
        DetLine { spans, copy: copy.into() }
    }

    /// Plain line — clicking copies exactly what is shown.
    fn plain(line: Line<'static>) -> Self {
        let copy = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>();
        DetLine { spans: line.spans, copy }
    }
}

fn finding_detail(f: &Finding) -> Vec<DetLine> {
    let dim = Style::default().fg(Color::DarkGray);
    let label =
        |s: &str| Span::styled(format!("{s:<9}"), Style::default().add_modifier(Modifier::BOLD));
    let cat = category(f);
    let mut out = vec![DetLine::new(
        vec![Span::styled(
            format!("[{}] {}", cat.label(), f.DetectorName),
            Style::default().fg(cat_color(cat)).add_modifier(Modifier::BOLD),
        )],
        f.DetectorName.clone(),
    )];
    out.push(DetLine::new(Vec::new(), ""));
    // value row: a click gives the full secret, never the truncated display
    out.push(DetLine::new(
        vec![label("value"), Span::raw(short(f.value(), 480))],
        f.value().to_owned(),
    ));
    out.push(DetLine::new(
        vec![
            label("website"),
            match f.url.as_deref() {
                Some(u) => Span::styled(u.to_string(), Style::default().fg(Color::Cyan)),
                None => Span::styled("(not enriched)", dim),
            },
        ],
        f.url.clone().unwrap_or_default(),
    ));
    if let Some(ctx) = &f.context {
        out.push(DetLine::new(Vec::new(), ""));
        out.push(DetLine::new(
            vec![Span::styled(
                "snippet",
                Style::default().add_modifier(Modifier::BOLD),
            )],
            "",
        ));
        out.push(DetLine::new(vec![Span::raw(short(ctx, 4000))], ctx.clone()));
    }
    if let Some(a) = annot(f) {
        out.push(DetLine::new(Vec::new(), ""));
        out.push(DetLine::new(
            vec![label("notes"), Span::raw(short(&a, 400))],
            a.clone(),
        ));
    }
    out.push(DetLine::new(Vec::new(), ""));
    out.push(DetLine::new(
        vec![label("source"), Span::raw(short(&f.location(), 400))],
        f.location(),
    ));
    if let Some(w) = f.warc() {
        out.push(DetLine::new(vec![label("warc"), Span::raw(w.clone())], w));
    }
    if let Some(a) = f.artifact.as_deref() {
        out.push(DetLine::new(
            vec![label("artifact"), Span::raw(short(a, 400))],
            a,
        ));
    }
    if !f.DetectorDescription.is_empty() {
        out.push(DetLine::new(Vec::new(), ""));
        out.push(DetLine::new(
            vec![label("about"), Span::raw(short(&f.DetectorDescription, 400))],
            f.DetectorDescription.clone(),
        ));
    }
    out
}

/// Right-pane content for the current selection.
fn detail_lines(sel: usize, rows: &[Row], findings: &[&Finding]) -> Vec<DetLine> {
    let dim = Style::default().fg(Color::DarkGray);
    match rows.get(sel) {
        None => vec![DetLine::new(vec![Span::styled("no findings", dim)], "")],
        Some(Row::Node(node, n, _)) => node_detail(node, *n, findings)
            .into_iter()
            .map(DetLine::plain)
            .collect(),
        Some(Row::Stat(i)) => stat_lines(*i, findings)
            .into_iter()
            .map(DetLine::plain)
            .collect(),
        Some(Row::Finding(i)) => finding_detail(findings[*i]),
    }
}

/// Greedy word wrap of one details line into rows of at most `width` cells,
/// keeping spans (and therefore colors) intact. Every wrapped row keeps the
/// logical line's copy text, so clicking any part of a long value copies it
/// whole.
fn wrap_det(line: &DetLine, width: usize) -> Vec<DetLine> {
    if width == 0 || line.spans.is_empty() {
        return vec![line.clone()];
    }
    let mut rows: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut used = 0usize;
    for span in &line.spans {
        let style = span.style;
        for piece in span.content.as_ref().split_inclusive(' ') {
            let pw = piece.width();
            if used + pw <= width {
                rows.last_mut().unwrap().push(Span::styled(piece.to_owned(), style));
                used += pw;
            } else if piece.trim().is_empty() {
                // whitespace never starts a line
                rows.push(Vec::new());
                used = 0;
            } else if pw <= width {
                rows.push(Vec::new());
                rows.last_mut().unwrap().push(Span::styled(piece.to_owned(), style));
                used = pw;
            } else {
                // a single "word" longer than the pane: hard-split
                if used > 0 {
                    rows.push(Vec::new());
                    used = 0;
                }
                let mut rest = piece;
                while !rest.is_empty() {
                    let take = take_width(rest, width);
                    if take.is_empty() {
                        break;
                    }
                    rows.last_mut().unwrap().push(Span::styled(take.to_owned(), style));
                    rest = &rest[take.len()..];
                    used = take.width();
                    if !rest.is_empty() {
                        rows.push(Vec::new());
                        used = 0;
                    }
                }
            }
        }
    }
    if rows.len() > 1 && rows.last().is_some_and(|r| r.is_empty()) {
        rows.pop();
    }
    rows.into_iter()
        .map(|spans| DetLine { spans, copy: line.copy.clone() })
        .collect()
}

fn wrap_det_lines(lines: Vec<DetLine>, width: usize) -> Vec<DetLine> {
    lines
        .into_iter()
        .flat_map(|l| wrap_det(&l, width))
        .collect()
}

/// Longest prefix of `s` fitting in `max` cells (always at least one char, so
/// zero-width input can never stall the wrapping loop).
fn take_width(s: &str, max: usize) -> &str {
    let mut w = 0usize;
    for (i, c) in s.char_indices() {
        let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if w + cw > max && i > 0 {
            return &s[..i];
        }
        w += cw;
    }
    s
}

pub fn ui(f: &mut Frame, state: &mut AppState, rows: &[Row], findings: &[&Finding]) {
    let area = f.area();
    let vert =
        Layout::vertical([Constraint::Length(1), Constraint::Min(8), Constraint::Length(1)])
            .split(area);
    f.render_widget(
        Paragraph::new(header_line(findings, state.filter)).block(Block::default()),
        vert[0],
    );
    f.render_widget(
        Paragraph::new(footer_line(state.status.as_deref(), state.mouse)),
        vert[2],
    );

    let mid = Layout::horizontal([Constraint::Percentage(55), Constraint::Min(40)]).split(vert[1]);

    let list_block = Block::default().borders(Borders::ALL).title(" findings ");
    let detail_block = Block::default().borders(Borders::ALL).title(" details ");
    state.list_area = list_block.inner(mid[0]);
    state.detail_area = detail_block.inner(mid[1]);

    // wrap the details for this width — kept in state for click-to-copy and
    // the mouse wheel (one visual row per rendered line, no Paragraph wrap)
    let det = detail_lines(state.sel, rows, findings);
    let det_width = state.detail_area.width.saturating_sub(1) as usize;
    state.detail_rows = wrap_det_lines(det, det_width);
    let visible = state.detail_area.height as usize;
    state.detail_offset = state
        .detail_offset
        .min(state.detail_rows.len().saturating_sub(visible));

    let items: Vec<ListItem> = rows.iter().map(|r| row_item(r, findings)).collect();
    let list = List::new(items)
        .block(list_block)
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, mid[0], &mut state.list);

    let lines: Vec<Line> = state
        .detail_rows
        .iter()
        .map(|d| Line::from(d.spans.clone()))
        .collect();
    let detail = Paragraph::new(lines)
        .block(detail_block)
        .scroll((state.detail_offset.min(u16::MAX as usize) as u16, 0));
    f.render_widget(detail, mid[1]);
}

/// Run the TUI until quit. Requires a real terminal (checked by the caller).
/// `e` writes text exports next to the input (the caller's `…/exports`).
pub fn run(findings: &[&Finding], export_dir: &Path) -> Result<i32> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;

    struct Guard {
        mouse: bool,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
            if self.mouse {
                let _ = execute!(stdout(), DisableMouseCapture);
            }
            let _ = execute!(stdout(), LeaveAlternateScreen);
        }
    }
    let mut guard = Guard { mouse: false };

    let mut terminal = Terminal::new(CrosstermBackend::new(out))?;
    terminal.hide_cursor()?;

    let mut state = AppState::new();
    let mut rows = build_rows(findings, &state);
    state.move_by(&rows, 0);

    loop {
        terminal.draw(|f| ui(f, &mut state, &rows, findings))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('j') | KeyCode::Down => state.move_by(&rows, 1),
                    KeyCode::Char('k') | KeyCode::Up => state.move_by(&rows, -1),
                    KeyCode::Char('g') => state.move_by(&rows, -(rows.len() as isize)),
                    KeyCode::Char('G') => state.move_by(&rows, rows.len() as isize),
                    KeyCode::PageDown => state.move_by(&rows, 10),
                    KeyCode::PageUp => state.move_by(&rows, -10),
                    KeyCode::Char('e') => {
                        state.status = Some(export_action(
                            rows.get(state.sel),
                            export_dir,
                            findings,
                        ));
                    }
                    KeyCode::Char('m') => {
                        state.mouse = !state.mouse;
                        guard.mouse = state.mouse;
                        if state.mouse {
                            execute!(stdout(), EnableMouseCapture)?;
                        } else {
                            execute!(stdout(), DisableMouseCapture)?;
                        }
                        state.status = Some(if state.mouse {
                            "mouse on — click details to copy, wheel scrolls".into()
                        } else {
                            "mouse off — terminal selection works again".into()
                        });
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if let Some(node) = rows.get(state.sel).and_then(Row::node) {
                            state.toggle(&node);
                            rows = build_rows(findings, &state);
                            state.move_by(&rows, 0);
                        }
                    }
                    KeyCode::Tab => {
                        state.filter = state.filter.next();
                        rows = build_rows(findings, &state);
                        state.move_by(&rows, 0);
                    }
                    _ => {}
                }
            }
            Event::Mouse(m) => handle_mouse(&mut state, &rows, m),
            _ => {}
        }
    }
    terminal.show_cursor()?;
    Ok(0)
}

/// Click / wheel handling: list clicks jump the selection, detail clicks copy
/// that line's text, the wheel scrolls whichever pane the pointer is over.
fn handle_mouse(state: &mut AppState, rows: &[Row], m: MouseEvent) {
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let (x, y) = (m.column, m.row);
            if in_area(state.list_area, x, y) {
                let row = state.list_offset() + (y - state.list_area.y) as usize;
                state.select_row(rows, row);
            } else if in_area(state.detail_area, x, y) {
                let idx = state.detail_offset + (y - state.detail_area.y) as usize;
                if let Some(dl) = state.detail_rows.get(idx) {
                    if dl.copy.is_empty() {
                        state.status = Some("nothing to copy".into());
                    } else {
                        let n = dl.copy.chars().count();
                        copy_to_clipboard(&dl.copy);
                        state.status = Some(format!("copied {n} char(s)"));
                    }
                }
            }
        }
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
            let step = if matches!(m.kind, MouseEventKind::ScrollUp) { -3 } else { 3 };
            if in_area(state.detail_area, m.column, m.row) {
                let max_off = state
                    .detail_rows
                    .len()
                    .saturating_sub(state.detail_area.height as usize);
                state.detail_offset =
                    (state.detail_offset as isize + step).clamp(0, max_off as isize) as usize;
            } else if in_area(state.list_area, m.column, m.row) {
                state.move_by(rows, step);
            }
        }
        _ => {}
    }
}

fn in_area(a: Rect, x: u16, y: u16) -> bool {
    x >= a.x && x < a.x.saturating_add(a.width) && y >= a.y && y < a.y.saturating_add(a.height)
}

// ---------------------------------------------------------------------------
// Export (`e`)
// ---------------------------------------------------------------------------

/// Footer status for the current selection: what was exported, or why not.
fn export_action(sel: Option<&Row>, export_dir: &Path, findings: &[&Finding]) -> String {
    let Some(row) = sel else {
        return "nothing selected".into();
    };
    match export_selection(row, export_dir, findings) {
        Ok(Some((path, n))) => format!("exported {n} finding(s) → {}", path.display()),
        Ok(None) => "nothing to export here".into(),
        Err(e) => format!("export failed: {e:#}"),
    }
}

/// Write the selected finding group / detector / category as a text file.
/// Returns Ok(None) for rows that are not exportable (STATS, stat views).
fn export_selection(
    row: &Row,
    dir: &Path,
    findings: &[&Finding],
) -> Result<Option<(PathBuf, usize)>> {
    match row {
        Row::Node(Node::Category(cat), _, _) => {
            let group: Vec<&Finding> = findings
                .iter()
                .copied()
                .filter(|f| category(f) == *cat)
                .collect();
            let path = dir.join(format!("{}.txt", cat.label()));
            write_export(&path, &group)?;
            Ok(Some((path, group.len())))
        }
        Row::Node(Node::Detector(cat, det), _, _) => {
            let group: Vec<&Finding> = findings
                .iter()
                .copied()
                .filter(|f| category(f) == *cat && &f.DetectorName == det)
                .collect();
            let path = dir
                .join(cat.label())
                .join(format!("{}.txt", safe_name(det)));
            write_export(&path, &group)?;
            Ok(Some((path, group.len())))
        }
        Row::Finding(i) => {
            let f = findings[*i];
            let group: Vec<&Finding> = findings
                .iter()
                .copied()
                .filter(|g| g.value() == f.value())
                .collect();
            let path = dir.join(format!(
                "{}-{:016x}.txt",
                safe_name(&f.DetectorName),
                fnv64(f.value().as_bytes())
            ));
            write_export(&path, &group)?;
            Ok(Some((path, group.len())))
        }
        Row::Node(Node::Stats, ..) | Row::Stat(_) => Ok(None),
    }
}

fn write_export(path: &Path, group: &[&Finding]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut out = String::new();
    for (i, f) in group.iter().enumerate() {
        if i > 0 {
            out.push_str("\n---\n\n");
        }
        out.push_str(&export_block(f));
    }
    std::fs::write(path, out).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// One finding as a plain-text record for exported reports.
fn export_block(f: &Finding) -> String {
    let mut s = String::new();
    s.push_str(&format!("detector: {}\n", f.DetectorName));
    s.push_str(&format!("category: {}\n", category(f).label()));
    if f.value().contains('\n') {
        s.push_str(&format!("value:\n{}\n", f.value()));
    } else {
        s.push_str(&format!("value: {}\n", f.value()));
    }
    if let Some(u) = &f.url {
        s.push_str(&format!("website: {u}\n"));
    }
    if let Some(a) = annot(f) {
        s.push_str(&format!("notes: {a}\n"));
    }
    s.push_str(&format!("source: {}\n", f.location()));
    if let Some(w) = f.warc() {
        s.push_str(&format!("warc: {w}\n"));
    }
    if let Some(a) = &f.artifact {
        s.push_str(&format!("artifact: {a}\n"));
    }
    if !f.DetectorDescription.is_empty() {
        s.push_str(&format!("about: {}\n", f.DetectorDescription));
    }
    if let Some(c) = &f.context {
        s.push_str(&format!("\nsnippet: {c}\n"));
    }
    s
}

/// Filesystem-safe piece of a detector/category name.
fn safe_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "unnamed".into()
    } else {
        trimmed.to_owned()
    }
}

/// FNV-1a 64 — tiny, dependency-free, stable export file names.
fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// Clipboard (click-to-copy)
// ---------------------------------------------------------------------------

/// Best-effort copy: OSC 52 reaches the local terminal even over ssh/tmux,
/// then whichever Wayland/X11 clipboard tool is installed takes over.
fn copy_to_clipboard(text: &str) {
    let seq = osc52(text);
    let mut out = stdout();
    let _ = out.write_all(seq.as_bytes());
    let _ = out.flush();

    let owned = text.to_owned();
    std::thread::spawn(move || {
        for (bin, args) in [
            ("wl-copy", Vec::<&str>::new()),
            ("xclip", vec!["-selection", "clipboard"]),
            ("xsel", vec!["--clipboard", "--input"]),
        ] {
            let child = std::process::Command::new(bin)
                .args(&args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            let Ok(mut child) = child else { continue };
            if let Some(mut si) = child.stdin.take() {
                let _ = si.write_all(owned.as_bytes());
            }
            let _ = child.wait();
            break;
        }
    });
}

/// OSC 52 sequence for `text`, wrapped for tmux passthrough when needed.
fn osc52(text: &str) -> String {
    let seq = format!("\x1b]52;c;{}\x07", base64_encode(text.as_bytes()));
    if std::env::var_os("TMUX").is_some() {
        format!("\x1bPtmux;{}\x1b\\", seq.replace('\x1b', "\x1b\x1b"))
    } else {
        seq
    }
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// True when stdout is an interactive terminal (TUI is appropriate).
pub fn stdout_is_tty() -> bool {
    stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(detector: &str, raw: &str, url: Option<&str>) -> Finding {
        let url_json = url
            .map(|u| format!(r#","url":"{u}""#))
            .unwrap_or_default();
        serde_json::from_str(&format!(
            r#"{{"DetectorName":"{detector}","Raw":"{raw}","DetectorDescription":"desc."{url_json}}}"#
        ))
        .unwrap()
    }

    fn two_findings() -> Vec<Finding> {
        let mut algolia = sample("AlgoliaAdminKey", "0b46f6ae", Some("https://www.kbb.com/x"));
        algolia.ExtraData = Some(serde_json::json!({"acl": "addObject,deleteIndex,search"}));
        vec![algolia, sample("NewRelicBrowserKey", "NRBR-abc", None)]
    }

    fn refs(fs: &[Finding]) -> Vec<&Finding> {
        fs.iter().collect()
    }

    fn toggle(rows: &[Row], state: &mut AppState, pred: impl Fn(&Row) -> bool) {
        let node = rows
            .iter()
            .find(|r| pred(r))
            .and_then(Row::node)
            .expect("row to toggle");
        state.toggle(&node);
    }

    #[test]
    fn default_screen_is_collapsed_tree_with_stats_open() {
        let fs = two_findings();
        let r = refs(&fs);
        let state = AppState::new();
        let rows = build_rows(&r, &state);

        // STATS open with its 5 sub-views…
        assert!(matches!(rows[0], Row::Node(Node::Stats, 5, true)));
        assert_eq!(
            rows[1..6]
                .iter()
                .filter(|x| matches!(x, Row::Stat(_)))
                .count(),
            5
        );
        // …finding categories present but collapsed: no detector or finding rows.
        assert!(rows
            .iter()
            .any(|x| matches!(x, Row::Node(Node::Category(Cat::Bad), 1, false))));
        assert!(rows
            .iter()
            .any(|x| matches!(x, Row::Node(Node::Category(Cat::Trivial), 1, false))));
        assert!(!rows.iter().any(|x| matches!(x, Row::Node(Node::Detector(..), _, _))));
        assert!(!rows.iter().any(|x| matches!(x, Row::Finding(_))));
    }

    #[test]
    fn enter_expands_category_then_detector() {
        let fs = two_findings();
        let r = refs(&fs);
        let mut state = AppState::new();

        let rows = build_rows(&r, &state);
        toggle(
            &rows,
            &mut state,
            |x| matches!(x, Row::Node(Node::Category(Cat::Bad), _, _)),
        );

        let rows = build_rows(&r, &state);
        assert!(rows
            .iter()
            .any(|x| matches!(x, Row::Node(Node::Detector(Cat::Bad, d), 1, false) if d == "AlgoliaAdminKey")));
        assert!(!rows.iter().any(|x| matches!(x, Row::Finding(_))));

        toggle(
            &rows,
            &mut state,
            |x| matches!(x, Row::Node(Node::Detector(Cat::Bad, _), _, _)),
        );

        let rows = build_rows(&r, &state);
        assert!(rows.iter().any(|x| matches!(x, Row::Finding(0))));

        // toggling again collapses
        toggle(
            &rows,
            &mut state,
            |x| matches!(x, Row::Node(Node::Detector(Cat::Bad, _), _, _)),
        );
        let rows = build_rows(&r, &state);
        assert!(!rows.iter().any(|x| matches!(x, Row::Finding(_))));
    }

    #[test]
    fn stats_category_toggles() {
        let fs = two_findings();
        let r = refs(&fs);
        let mut state = AppState::new();
        let rows = build_rows(&r, &state);
        toggle(&rows, &mut state, |x| matches!(x, Row::Node(Node::Stats, _, _)));
        let rows = build_rows(&r, &state);
        assert!(rows.iter().all(|x| !matches!(x, Row::Stat(_))));
        assert!(matches!(rows[0], Row::Node(Node::Stats, 5, false)));
    }

    #[test]
    fn filter_cycles_all_bad_trivial() {
        assert_eq!(Filter::All.next(), Filter::Bad);
        assert_eq!(Filter::Bad.next(), Filter::Trivial);
        assert_eq!(Filter::Trivial.next(), Filter::All);
        assert!(Filter::Bad.includes(Cat::Bad));
        assert!(!Filter::Bad.includes(Cat::Trivial));
        assert!(Filter::Trivial.includes(Cat::Trivial));
        assert!(Filter::All.includes(Cat::Bad) && Filter::All.includes(Cat::Trivial));
    }

    #[test]
    fn filter_hides_other_categories() {
        let fs = two_findings();
        let r = refs(&fs);
        let mut state = AppState::new();
        state.filter = Filter::Trivial;
        let rows = build_rows(&r, &state);
        assert!(rows
            .iter()
            .any(|x| matches!(x, Row::Node(Node::Category(Cat::Trivial), _, _))));
        assert!(!rows
            .iter()
            .any(|x| matches!(x, Row::Node(Node::Category(Cat::Bad), _, _))));
    }

    #[test]
    fn state_moves_and_clamps() {
        let fs = two_findings();
        let r = refs(&fs);
        let mut state = AppState::new();
        let rows = build_rows(&r, &state);
        state.move_by(&rows, 1000);
        assert_eq!(state.sel, rows.len() - 1);
        state.move_by(&rows, -1000);
        assert_eq!(state.sel, 0);
    }

    fn text_of(lines: &[DetLine]) -> String {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn stat_views_render_expected_content() {
        let fs = two_findings();
        let r = refs(&fs);
        let state = AppState::new();
        let rows = build_rows(&r, &state);

        let sel = rows.iter().position(|x| matches!(x, Row::Stat(0))).unwrap();
        let t = text_of(&detail_lines(sel, &rows, &r));
        assert!(t.contains("overview"), "{t}");
        assert!(t.contains("findings"), "{t}");
        assert!(t.contains("bad"), "{t}");
        assert!(t.contains("trivial"), "{t}");

        let sel = rows.iter().position(|x| matches!(x, Row::Stat(1))).unwrap();
        let t = text_of(&detail_lines(sel, &rows, &r));
        assert!(t.contains("findings by detector"), "{t}");
        assert!(t.contains("NewRelicBrowserKey"), "{t}");

        let sel = rows.iter().position(|x| matches!(x, Row::Stat(3))).unwrap();
        let t = text_of(&detail_lines(sel, &rows, &r));
        assert!(t.contains("bad keys"), "{t}");
        assert!(t.contains("AlgoliaAdminKey"), "{t}");

        let sel = rows.iter().position(|x| matches!(x, Row::Stat(4))).unwrap();
        let t = text_of(&detail_lines(sel, &rows, &r));
        assert!(t.contains("trivial keys"), "{t}");
        assert!(t.contains("NewRelicBrowserKey"), "{t}");
    }

    #[test]
    fn finding_detail_shows_website_snippet_notes_artifact() {
        let mut f = sample("AlgoliaAdminKey", "0b46f6ae", Some("https://a.example/x"));
        f.context = Some(r#"var key="0b46f6ae";"#.into());
        f.ExtraData = Some(serde_json::json!({"acl": "addObject,search"}));
        f.artifact = Some("results/artifacts/w/chunk-000003-L42.txt".into());
        let r = [&f];
        let det = finding_detail(&f);
        let t = text_of(&det);
        assert!(t.contains("https://a.example/x"), "{t}");
        assert!(t.contains(r#"var key="0b46f6ae";"#), "{t}");
        assert!(t.contains("acl: addObject,search"), "{t}");
        assert!(t.contains("AlgoliaAdminKey"), "{t}");
        assert!(t.contains("results/artifacts/w/chunk-000003-L42.txt"), "{t}");

        // click-to-copy: value row copies the full secret, website the bare URL
        let value = det.iter().find(|l| l.spans.first().is_some_and(|s| s.content.starts_with("value"))).unwrap();
        assert_eq!(value.copy, "0b46f6ae");
        let website = det.iter().find(|l| l.spans.first().is_some_and(|s| s.content.starts_with("website"))).unwrap();
        assert_eq!(website.copy, "https://a.example/x");

        // sanity: row lookup path resolves the same content
        let mut state = AppState::new();
        state.toggle(&Node::Category(Cat::Bad));
        let rows = build_rows(&r, &state);
        let node = rows
            .iter()
            .find(|x| matches!(x, Row::Node(Node::Detector(Cat::Bad, _), _, _)))
            .and_then(Row::node)
            .expect("detector row");
        state.toggle(&node);
        let rows = build_rows(&r, &state);
        let sel = rows.iter().position(|x| matches!(x, Row::Finding(0))).unwrap();
        assert_eq!(
            text_of(&detail_lines(sel, &rows, &r)),
            text_of(&finding_detail(&f))
        );
    }

    #[test]
    fn ui_renders_collapsed_and_expanded() {
        let fs = two_findings();
        let r = refs(&fs);
        let backend = ratatui::backend::TestBackend::new(110, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        let grab = |terminal: &mut Terminal<ratatui::backend::TestBackend>| {
            terminal.draw(|f| ui(f, &mut AppState::new(), &build_rows(&r, &AppState::new()), &r)).unwrap();
            let buf = terminal.backend().buffer();
            let mut text = String::new();
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    text.push_str(buf[(x, y)].symbol());
                }
                text.push('\n');
            }
            text
        };
        let collapsed = grab(&mut terminal);
        assert!(collapsed.contains("STATS"), "missing STATS:\n{collapsed}");
        assert!(collapsed.contains("▸ bad"), "missing bad category:\n{collapsed}");
        assert!(collapsed.contains("▸ trivial"), "missing trivial category:\n{collapsed}");
        assert!(collapsed.contains("q quit"), "missing footer:\n{collapsed}");
        assert!(collapsed.contains("details"), "missing detail pane:\n{collapsed}");
        // default collapsed: no finding values or detectors flood the list
        assert!(!collapsed.contains("kbb.com"), "leak:\n{collapsed}");
        assert!(!collapsed.contains("NewRelicBrowserKey (1)"), "detector open:\n{collapsed}");

        let mut state = AppState::new();
        let mut rows = build_rows(&r, &state);
        for target in [
            Node::Category(Cat::Bad),
            Node::Detector(Cat::Bad, "AlgoliaAdminKey".into()),
            Node::Category(Cat::Trivial),
            Node::Detector(Cat::Trivial, "NewRelicBrowserKey".into()),
        ] {
            if let Some(row) = rows.iter().find(|x| x.node().as_ref() == Some(&target)) {
                let n = row.node().unwrap();
                state.toggle(&n);
                rows = build_rows(&r, &state);
            }
        }
        state.move_by(&rows, 0);
        terminal
            .draw(|f| ui(f, &mut state, &rows, &r))
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut expanded = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                expanded.push_str(buf[(x, y)].symbol());
            }
            expanded.push('\n');
        }
        assert!(expanded.contains("kbb.com"), "missing finding:\n{expanded}");
        assert!(expanded.contains("NewRelicBrowserKey"), "missing detector:\n{expanded}");
        // the draw must have recorded pane geometry + wrapped rows for mouse use
        assert!(!state.detail_rows.is_empty(), "ui must build detail rows");
        assert!(state.detail_area.width > 0 && state.list_area.width > 0);
    }

    #[test]
    fn wrap_keeps_styles_and_full_copy_text() {
        let long = format!("{} {}", "A".repeat(60), "b".repeat(60));
        let line = DetLine::new(vec![Span::raw(long.clone())], long.clone());
        let rows = wrap_det(&line, 40);
        assert!(rows.len() >= 3, "wrapped into {} rows", rows.len());
        let mut joined = String::new();
        for r in &rows {
            let w: usize = r.spans.iter().map(|s| s.content.width()).sum();
            assert!(w <= 40, "row too wide: {w}");
            assert_eq!(r.copy, long, "copy must stay the full text");
            for s in &r.spans {
                joined.push_str(s.content.as_ref());
            }
        }
        assert_eq!(joined, long, "wrapping must not lose characters");

        let short = DetLine::new(vec![Span::raw("hello")], "hello");
        let rows = wrap_det(&short, 40);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].copy, "hello");
    }

    #[test]
    fn take_width_respects_display_width() {
        assert_eq!(take_width("你好世界", 4), "你好");
        assert_eq!(take_width("abc", 10), "abc");
        assert_eq!(take_width("", 5), "");
        // zero-width input can never stall the loop
        assert!(!take_width("abc", 0).is_empty());
    }

    #[test]
    fn export_writes_selected_rows() {
        let dir = tempfile::tempdir().unwrap();
        let fs = two_findings();
        let r = refs(&fs);

        let row = Row::Finding(0);
        let (path, n) = export_selection(&row, dir.path(), &r).unwrap().unwrap();
        assert_eq!(n, 1);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("detector: AlgoliaAdminKey"), "{body}");
        assert!(body.contains("category: bad"), "{body}");
        assert!(body.contains("value: 0b46f6ae"), "{body}");
        assert!(body.contains("website: https://www.kbb.com/x"), "{body}");
        assert!(
            path.file_name().unwrap().to_str().unwrap().starts_with("AlgoliaAdminKey-"),
            "path={path:?}"
        );

        let row = Row::Node(Node::Category(Cat::Trivial), 1, false);
        let (path, n) = export_selection(&row, dir.path(), &r).unwrap().unwrap();
        assert_eq!(n, 1);
        assert_eq!(path, dir.path().join("trivial.txt"));
        assert!(std::fs::read_to_string(&path).unwrap().contains("NewRelicBrowserKey"));

        let row = Row::Node(Node::Detector(Cat::Bad, "AlgoliaAdminKey".into()), 1, false);
        let (path, n) = export_selection(&row, dir.path(), &r).unwrap().unwrap();
        assert_eq!(n, 1);
        assert_eq!(path, dir.path().join("bad").join("AlgoliaAdminKey.txt"));

        // stats rows have nothing to export
        assert!(export_selection(&Row::Stat(0), dir.path(), &r).unwrap().is_none());
        assert!(
            export_selection(&Row::Node(Node::Stats, 5, true), dir.path(), &r)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn export_groups_repeated_secrets_with_separators() {
        let dir = tempfile::tempdir().unwrap();
        let fs = [
            sample("GoogleGeminiAPIKey", "AIza-same", Some("https://a.example/")),
            sample("GoogleGeminiAPIKey", "AIza-same", Some("https://b.example/")),
        ];
        let r = refs(&fs);
        let (path, n) = export_selection(&Row::Finding(0), dir.path(), &r).unwrap().unwrap();
        assert_eq!(n, 2);
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.matches("---").count(), 1, "{body}");
        assert!(body.contains("https://a.example/") && body.contains("https://b.example/"));
    }

    #[test]
    fn clipboard_encoding_helpers() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"hello world"), "aGVsbG8gd29ybGQ=");
        let seq = osc52("hi");
        assert!(
            seq.starts_with("\x1b]52;c;") && seq.ends_with('\x07'),
            "not an OSC 52 sequence: {seq:?}"
        );
        assert!(seq.contains(&base64_encode(b"hi")));
    }

    #[test]
    fn fnv_and_safe_names_are_stable() {
        assert_eq!(fnv64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(safe_name("GoogleGeminiAPIKey"), "GoogleGeminiAPIKey");
        assert_eq!(safe_name("weird/name:v1"), "weird_name_v1");
        assert_eq!(safe_name("___"), "unnamed");
    }

    #[test]
    fn mouse_wheel_and_clicks_navigate() {
        let fs = two_findings();
        let r = refs(&fs);
        let mut state = AppState::new();
        let rows = build_rows(&r, &state);
        // simulate ui() having laid the panes out
        state.list_area = Rect::new(0, 1, 40, 10);
        state.detail_area = Rect::new(45, 1, 50, 10);
        state.detail_rows = (0..30)
            .map(|i| DetLine::new(vec![Span::raw(format!("line {i}"))], format!("line {i}")))
            .collect();

        let wheel = |kind, col, row| MouseEvent {
            kind,
            column: col,
            row,
            modifiers: KeyModifiers::empty(),
        };
        // wheel over the details scrolls the detail pane only
        handle_mouse(&mut state, &rows, wheel(MouseEventKind::ScrollDown, 50, 3));
        assert_eq!(state.detail_offset, 3);
        assert_eq!(state.sel, 0, "detail scroll must not move the selection");
        handle_mouse(&mut state, &rows, wheel(MouseEventKind::ScrollUp, 50, 3));
        assert_eq!(state.detail_offset, 0);
        // wheel over the list moves the selection
        handle_mouse(&mut state, &rows, wheel(MouseEventKind::ScrollDown, 5, 3));
        assert_eq!(state.sel, 3);
        // a click jumps the list to that row
        handle_mouse(
            &mut state,
            &rows,
            wheel(MouseEventKind::Down(MouseButton::Left), 5, 5),
        );
        assert_eq!(state.sel, 4, "list_offset(0) + (row 5 - inner y 1)");
        // clicks outside both panes do nothing
        handle_mouse(
            &mut state,
            &rows,
            wheel(MouseEventKind::Down(MouseButton::Left), 200, 200),
        );
        assert_eq!(state.sel, 4);
    }
}
