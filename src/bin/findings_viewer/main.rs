//! findings_viewer — browse, search, and chart trufflehog findings.jsonl files.
//!
//! Usage: findings_viewer [COMMAND] [OPTIONS]
//!   (none)     interactive ratatui info reader (default; stats text when piped)
//!   stats      overalls + bad-key and trivial-key report
//!   search     find findings by detector / secret value / location / website
//!   dupes      secrets that appear multiple times, most repeated first
//!
//! trufflehog performs the one-and-only verification (config `only_verified`),
//! so this tool never re-checks keys — it only reports what trufflehog found.

mod tui;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Default)]
struct Filesystem {
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: u64,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Default)]
struct SourceData {
    #[serde(default)]
    Filesystem: Option<Filesystem>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Default)]
struct SourceMetadata {
    #[serde(default)]
    Data: Option<SourceData>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct Finding {
    #[serde(default)]
    DetectorName: String,
    #[serde(default)]
    Raw: String,
    #[serde(default)]
    RawV2: String,
    #[serde(default)]
    Redacted: String,
    #[serde(default)]
    DetectorDescription: String,
    #[serde(default)]
    SourceMetadata: Option<SourceMetadata>,
    #[serde(default)]
    ExtraData: Option<serde_json::Value>,
    #[serde(default)]
    SecretParts: Option<serde_json::Value>,
    /// original page URL (WARC-Target-URI), added by pipeline enrichment
    #[serde(default)]
    url: Option<String>,
    /// snippet of the source line the secret was found on, added by enrichment
    #[serde(default)]
    context: Option<String>,
    /// the enclosing WARC record, saved under `paths.artifacts_dir` by the
    /// pipeline and kept as a plain-text file next to this finding
    #[serde(default)]
    artifact: Option<String>,
}

impl Finding {
    fn value(&self) -> &str {
        for v in [&self.Raw, &self.RawV2, &self.Redacted] {
            if !v.is_empty() {
                return v;
            }
        }
        "<unknown>"
    }

    fn location(&self) -> String {
        let fs = self
            .SourceMetadata
            .as_ref()
            .and_then(|m| m.Data.as_ref())
            .and_then(|d| d.Filesystem.as_ref());
        match fs {
            Some(f) if f.line > 0 => format!("{}:{}", f.file, f.line),
            Some(f) => f.file.clone(),
            None => "-".into(),
        }
    }

    /// CommonCrawl chunk paths look like `work/<warc>.chunks/chunk-000042.warc`;
    /// recover the WARC id so reports talk about source files, not chunk names.
    fn warc(&self) -> Option<String> {
        let loc = self.location();
        let dir = loc.rsplit_once("/").map(|(d, _)| d)?;
        let name = dir.strip_suffix(".chunks")?;
        let name = name.rsplit('/').next().unwrap_or(name);
        let name = name
            .strip_suffix(".warc.gz")
            .or_else(|| name.strip_suffix(".warc"))
            .unwrap_or(name);
        Some(name.to_string())
    }

    /// Host of the original page this secret was found on (`-` if unknown).
    fn site(&self) -> String {
        match self.url.as_deref() {
            Some(u) => host_of(u),
            None => "-".to_string(),
        }
    }

    fn extra_str(&self, k: &str) -> Option<&str> {
        self.ExtraData.as_ref()?.get(k)?.as_str()
    }

    fn part_str(&self, k: &str) -> Option<&str> {
        self.SecretParts.as_ref()?.get(k)?.as_str()
    }
}

/// Extract a bare lowercase host from a URL (no scheme/path/port/userinfo).
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split_once(':').map_or(host, |(h, _)| h);
    if host.is_empty() {
        "-".to_string()
    } else {
        host.to_lowercase()
    }
}

/// Risk bucket for a detector — trufflehog verified liveness; this only says
/// what exposure *means*. Two buckets: `Trivial` keys are designed to ship to
/// browsers (Algolia graded per-finding by its ACL), everything else is `Bad`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Cat {
    Bad,
    Trivial,
}

impl Cat {
    fn label(self) -> &'static str {
        match self {
            Cat::Bad => "bad",
            Cat::Trivial => "trivial",
        }
    }
}

fn category(f: &Finding) -> Cat {
    if f.DetectorName == "AlgoliaAdminKey" {
        // only a plain frontend search key is trivial; anything else — or no
        // ACL at all from the verifier — counts as bad
        let Some(acl) = f.extra_str("acl") else {
            return Cat::Bad;
        };
        if acl.split(',').all(|p| matches!(p.trim(), "browse" | "search")) {
            return Cat::Trivial; // plain frontend search key
        }
        return Cat::Bad;
    }
    match f.DetectorName.as_str() {
        // designed to ship to browsers / public web pages
        "NewRelicBrowserKey" | "IPInfo" | "StoryblokAccessToken" | "Disqus"
        | "Geoapify" | "WalkScore" | "IpStack" | "IPGeolocation" | "Ipapi"
        | "LocationIQ" | "OpenWeather" | "Unsplash" | "PubNubPublishKey"
        | "TwelveData" => Cat::Trivial,
        "LaunchDarkly" => {
            // sdk-… keys are client-side SDK keys (public by design);
            // api-/srv-… are server tokens with full API access.
            if f.Raw.starts_with("sdk-") {
                Cat::Trivial
            } else {
                Cat::Bad
            }
        }
        // account / write / billing access, sessions, and anything unknown
        // (JWT, GCP, …) — exposure of any of these is bad
        _ => Cat::Bad,
    }
}

/// Short per-detector annotation (ACLs, scopes, endpoints, key details).
fn annot(f: &Finding) -> Option<String> {
    match f.DetectorName.as_str() {
        "AlgoliaAdminKey" => Some(format!("acl: {}", f.extra_str("acl")?)),
        "Shopify" => {
            let store = f.part_str("store_url").unwrap_or("?");
            let scopes = f
                .extra_str("access_scopes")
                .map(|s| s.split(',').count())
                .unwrap_or(0);
            Some(format!("store {store} — {scopes} access scopes"))
        }
        "LaunchDarkly" => Some(format!(
            "{} token — {:?} (full API access as its member)",
            f.extra_str("token_type").unwrap_or("personal"),
            f.extra_str("token_name").unwrap_or("unnamed")
        )),
        "TelegramBotToken" => Some(format!("@{}", f.extra_str("username")?)),
        "Cloudinary" => {
            let cloud = f.part_str("cloud_name").unwrap_or("?");
            let secret = f.part_str("api_secret")?;
            Some(format!(
                "cloud {cloud} — api_secret {}…",
                &secret[..secret.len().min(6)]
            ))
        }
        "AWSAppSync" => Some(format!("graphql {}", f.extra_str("base_url")?)),
        "Adzuna" => Some(format!("app id {}", f.part_str("id")?)),
        "JWT" => {
            let iss = f.extra_str("iss")?;
            let exp = f.extra_str("exp").unwrap_or("?");
            Some(format!("signed session — iss {iss}, expires {exp}"))
        }
        "PrivateKey" => {
            let detail = pem_detail(&f.Raw).unwrap_or_else(|| "private key".into());
            let cert = f
                .extra_str("certificate_urls")
                .and_then(|u| u.rsplit('=').next())
                .map(|h| {
                    let h = if h.len() > 12 { &h[..12] } else { h };
                    format!(" — cert sha1 {h}… (crt.sh)")
                })
                .unwrap_or_default();
            Some(format!("{detail}{cert}"))
        }
        _ => None,
    }
}

/// Summarize a PEM private key via `openssl pkey -text` (type/curve/bits).
/// Returns None when openssl is unavailable or the key cannot be parsed;
/// encrypted PEMs are detected textually (openssl would prompt for a pass).
fn pem_detail(pem: &str) -> Option<String> {
    if pem.contains("ENCRYPTED") {
        return Some("encrypted (passphrase-protected PEM)".into());
    }
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("openssl")
        .args(["pkey", "-noout", "-text", "-inform", "PEM"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()?
        .write_all(pem.trim().as_bytes())
        .ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let bits = text
        .lines()
        .find_map(|l| l.strip_prefix("Private-Key: ("))
        .and_then(|l| l.split(" bit").next())
        .and_then(|l| l.split(", ").next())
        .map(str::to_owned);
    let curve = text
        .lines()
        .find_map(|l| l.strip_prefix("ASN1 OID: "))
        .map(str::to_owned);
    let rsa = text.lines().any(|l| l.contains("Modulus:"));
    match (bits, curve) {
        (Some(b), Some(c)) => Some(format!("{c} ({b} bit)")),
        (Some(b), None) if rsa => Some(format!("RSA ({b} bit)")),
        (Some(b), None) => Some(format!("{b}-bit key")),
        (None, _) => None,
    }
}

#[derive(Debug, PartialEq)]
enum Cmd {
    Tui,
    Stats,
    Search(Option<String>),
    Dupes,
    Help,
}

#[derive(Debug)]
struct Args {
    cmd: Cmd,
    files: Vec<PathBuf>,
    top: usize,
    detector: Option<String>,
    regex: bool,
    full: bool,
    describe: bool,
}

fn usage() -> String {
    "findings-viewer — browse and chart trufflehog findings
USAGE:
  findings-viewer [stats|search|dupes] [OPTIONS] [query...]

COMMANDS:
  (none)    interactive TUI: category/detector browser with details pane
            (falls back to the stats report when output is piped)
  stats     plain-text overalls, bad keys, trivial keys;
            shows websites and code snippets when enrichment data is present
  search    list findings matching QUERY (substring, or regex with --regex);
            matches detector name, secret value, website, and source location
  dupes     secrets found more than once, most repeated first
  help      show this help

OPTIONS:
  -f, --file <PATH>    findings .jsonl file or directory (repeatable).
                       Default: results/findings.jsonl + results/spill/*.jsonl
  -n, --top <N>        rows in charts and lists [15]
      --detector <S>   only findings whose detector name contains S
      --regex          treat the query as a case-insensitive regex
      --full           do not truncate long secret values
      --describe       print descriptions of matched detectors
  -h, --help           show this help

Note: trufflehog already verified every finding before it was written
(config: scan.only_verified = true) — this tool only reports, never re-checks.
"
    .to_string()
}

fn parse_args(argv: &[String]) -> Result<Args> {
    let mut files = Vec::new();
    let mut positional = Vec::new();
    let mut top = 15usize;
    let mut detector = None;
    let mut regex = false;
    let mut full = false;
    let mut describe = false;
    let mut want_help = false;

    let mut i = 0usize;
    let value_of = |flag: &str, i: &mut usize| -> Result<String> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .with_context(|| format!("flag {flag} requires a value"))
    };

    while i < argv.len() {
        let arg = argv[i].as_str();
        match arg {
            "-h" | "--help" => want_help = true,
            "-f" | "--file" => files.push(PathBuf::from(value_of(arg, &mut i)?)),
            "-n" | "--top" => {
                top = value_of(arg, &mut i)?
                    .parse()
                    .context("--top expects a number")?;
            }
            "--verified" => bail!("--verified was removed: trufflehog verifies every finding before output (scan.only_verified)"),
            "--detector" => detector = Some(value_of(arg, &mut i)?),
            "--regex" => regex = true,
            "--full" => full = true,
            "--describe" => describe = true,
            s if s.starts_with('-') && s.len() > 1 => bail!("unknown flag {s} (try --help)"),
            _ => positional.push(argv[i].clone()),
        }
        i += 1;
    }

    let cmd = if want_help {
        Cmd::Help
    } else {
        match positional.first().map(String::as_str) {
            None => Cmd::Tui,
            Some("stats") => Cmd::Stats,
            Some("dupes") => Cmd::Dupes,
            Some("help") => Cmd::Help,
            Some("search") => {
                let q = if positional.len() > 1 {
                    Some(positional[1..].join(" "))
                } else {
                    None
                };
                Cmd::Search(q)
            }
            Some(other) => bail!(
                "unknown command {other:?} (expected stats, search, or dupes; try --help)"
            ),
        }
    };

    Ok(Args {
        cmd,
        files,
        top,
        detector,
        regex,
        full,
        describe,
    })
}

/// Default inputs: the final output plus any spill files from the run.
fn default_inputs() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("results/findings.jsonl")];
    if let Ok(rd) = std::fs::read_dir("results/spill") {
        let mut spills: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        spills.sort();
        v.extend(spills);
    }
    v
}

/// Expand files/directories into a sorted list of .jsonl files.
fn gather_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        let meta = std::fs::metadata(input)
            .with_context(|| format!("cannot read {}", input.display()))?;
        if meta.is_dir() {
            collect_dir(input, &mut out)?;
        } else {
            out.push(input.clone());
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        bail!("no .jsonl files found under {}", inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "));
    }
    Ok(out)
}

fn collect_dir(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_dir(&path, out)?;
        } else if path.extension().is_some_and(|x| x == "jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

fn load_findings(files: &[PathBuf]) -> Result<(Vec<Finding>, usize)> {
    let mut findings = Vec::new();
    let mut skipped = 0usize;
    for file in files {
        let fh = std::fs::File::open(file)
            .with_context(|| format!("cannot open {}", file.display()))?;
        for line in BufReader::new(fh).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Finding>(&line) {
                Ok(f) => findings.push(f),
                Err(_) => skipped += 1,
            }
        }
    }
    Ok((findings, skipped))
}

fn matches_filters(f: &Finding, args: &Args, query: Option<&str>) -> bool {
    if let Some(d) = &args.detector
        && !f.DetectorName.to_lowercase().contains(&d.to_lowercase())
    {
        return false;
    }
    let Some(query) = query else { return true };
    if query.is_empty() {
        return true;
    }
    let hay = format!(
        "{} {} {} {}",
        f.DetectorName,
        f.value(),
        f.location(),
        f.url.as_deref().unwrap_or("")
    )
    .to_lowercase();
    if args.regex {
        match regex::Regex::new(&format!("(?i){query}")) {
            Ok(re) => re.is_match(&hay),
            Err(e) => {
                eprintln!("warning: invalid regex {query:?}: {e}");
                false
            }
        }
    } else {
        hay.contains(&query.to_lowercase())
    }
}

/// Collapse newlines/tabs (PEM blocks, embedded payloads) so values stay on one line.
fn flatten(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect()
}

fn trunc(s: &str, max: usize) -> String {
    let s = flatten(s);
    if s.chars().count() <= max {
        return s;
    }
    let cut: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

const BAR_WIDTH: usize = 36;
const PARTIALS: [&str; 8] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];

/// Horizontal bar scaled to `max`, with 1/8-block precision.
fn bar(count: u64, max: u64) -> String {
    if count == 0 || max == 0 {
        return String::new();
    }
    let units = count as f64 / max as f64 * BAR_WIDTH as f64;
    let mut full = units.floor() as usize;
    let mut partial = ((units - full as f64) * 8.0).round() as usize;
    if partial >= 8 {
        full += 1;
        partial = 0;
    }
    if full == 0 && partial == 0 {
        partial = 1;
    }
    let full = full.min(BAR_WIDTH);
    format!("{}{}", "█".repeat(full), PARTIALS[partial.min(7)])
}

fn pct(count: usize, total: usize) -> String {
    if total == 0 {
        return "  0.0%".into();
    }
    format!("{:>5.1}%", count as f64 * 100.0 / total as f64)
}

fn histogram<'a>(items: impl Iterator<Item = &'a str>) -> Vec<(String, usize)> {
    let mut map: BTreeMap<String, usize> = BTreeMap::new();
    for k in items {
        *map.entry(k.to_string()).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

fn cmd_stats(findings: &[&Finding], args: &Args) {
    let total = findings.len();
    let detectors = histogram(findings.iter().map(|f| f.DetectorName.as_str()));
    let values = histogram(findings.iter().map(|f| f.value()));
    let repeated = values.iter().filter(|(_, c)| *c > 1).count();
    let warcs: std::collections::BTreeSet<String> =
        findings.iter().filter_map(|f| f.warc()).collect();
    let files: std::collections::BTreeSet<String> =
        findings.iter().map(|f| f.location()).collect();
    let bad: Vec<&&Finding> = findings
        .iter()
        .filter(|f| category(f) == Cat::Bad)
        .collect();
    let triv: Vec<&&Finding> = findings
        .iter()
        .filter(|f| category(f) == Cat::Trivial)
        .collect();
    let bad_dets = histogram(bad.iter().map(|f| f.DetectorName.as_str())).len();
    let triv_dets = histogram(triv.iter().map(|f| f.DetectorName.as_str())).len();

    println!(" overalls");
    println!("   findings         {total}");
    println!("   detectors        {} unique", detectors.len());
    println!(
        "   key values       {} unique ({repeated} seen more than once)",
        values.len()
    );
    if !warcs.is_empty() {
        println!("   source WARCs     {}", warcs.len());
    } else {
        println!("   source files     {}", files.len());
    }
    println!(
        "   bad              {} finding(s) across {bad_dets} detector(s)",
        bad.len()
    );
    println!(
        "   trivial          {} finding(s) across {triv_dets} detector(s)",
        triv.len()
    );

    println!("\n findings by detector (top {})", args.top);
    let width = detectors
        .iter()
        .take(args.top)
        .map(|(d, _)| d.chars().count())
        .max()
        .unwrap_or(0)
        .min(26);
    let max = detectors.first().map(|(_, c)| *c as u64).unwrap_or(0);
    for (name, count) in detectors.iter().take(args.top) {
        println!(
            "   {:<w$} {:>5}  {} {}",
            trunc(name, width),
            count,
            bar(*count as u64, max),
            pct(*count, total),
            w = width,
        );
    }

    let dup_top: Vec<&(String, usize)> = values
        .iter()
        .filter(|(_, c)| *c > 1)
        .take(args.top)
        .collect();
    if !dup_top.is_empty() {
        println!("\n most-duplicated keys (top {})", dup_top.len());
        let dmax = dup_top[0].1 as u64;
        for (value, count) in dup_top {
            let detector = findings
                .iter()
                .find(|f| f.value() == value.as_str())
                .map(|f| f.DetectorName.as_str())
                .unwrap_or("?");
            let warcs: std::collections::BTreeSet<String> = findings
                .iter()
                .filter(|f| f.value() == value.as_str())
                .filter_map(|f| f.warc())
                .collect();
            let where_ = if warcs.is_empty() {
                String::new()
            } else {
                format!("  in {} WARC(s)", warcs.len())
            };
            println!(
                "   {:>4}× {:<24} {}{} {}",
                count,
                trunc(detector, 24),
                trunc(value, 36),
                where_,
                bar(*count as u64, dmax),
            );
        }
    }

    print_bad(&bad, args);
    print_trivial(&triv, args);
}

/// The "bad" bucket — grouped by detector with websites and code snippets.
fn print_bad(bad: &[&&Finding], args: &Args) {
    println!(
        "\n bad keys — {} finding(s), {} detector(s)",
        bad.len(),
        histogram(bad.iter().map(|f| f.DetectorName.as_str())).len()
    );
    let hist = histogram(bad.iter().map(|f| f.DetectorName.as_str()));
    let max = hist.first().map(|(_, c)| *c as u64).unwrap_or(0);
    for (det, count) in hist.iter().take(args.top) {
        let group: Vec<&&Finding> =
            bad.iter().filter(|f| f.DetectorName == *det).copied().collect();
        let mut sites: Vec<String> = group
            .iter()
            .map(|f| f.site())
            .filter(|s| s != "-")
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        sites.sort();
        let sites_s = if sites.is_empty() {
            String::new()
        } else {
            let shown: Vec<&str> = sites.iter().take(2).map(String::as_str).collect();
            format!(
                "  sites: {}{}",
                shown.join(", "),
                if sites.len() > 2 {
                    format!(" +{}", sites.len() - 2)
                } else {
                    String::new()
                }
            )
        };
        println!(
            "   {:<26} {:>4}  {}{}",
            trunc(det, 26),
            count,
            bar(*count as u64, max),
            sites_s
        );
        // distinct annotations (e.g. mixed Algolia ACLs), up to two lines
        let annots: std::collections::BTreeSet<String> =
            group.iter().filter_map(|f| annot(f)).collect();
        let mut shown_annots = 0usize;
        for a in annots.iter().take(2) {
            shown_annots += 1;
            println!("      {a}");
        }
        if annots.len() > shown_annots {
            println!("      … +{} other variant(s)", annots.len() - shown_annots);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut shown = 0usize;
        for f in &group {
            if shown >= 3 {
                break;
            }
            if !seen.insert(f.value()) {
                continue;
            }
            shown += 1;
            let site = f.site();
            let ctx = f.context.as_deref().map(|c| trunc(c, 52)).unwrap_or_default();
            println!(
                "      {:<40} {:<22} {}",
                trunc(f.value(), 40),
                trunc(&site, 22),
                ctx
            );
        }
        if *count > shown {
            println!("      … +{} more finding(s)", count - shown);
        }
    }
    if hist.len() > args.top {
        println!("   … +{} more detector(s)", hist.len() - args.top);
    }
}

/// Keys that are designed to be shipped to browsers / public pages.
fn print_trivial(triv: &[&&Finding], args: &Args) {
    if triv.is_empty() {
        return;
    }
    let hist = histogram(triv.iter().map(|f| f.DetectorName.as_str()));
    println!(
        "\n trivial keys (exposure by design) — {} finding(s), {} detector(s)",
        triv.len(),
        hist.len()
    );
    let max = hist.first().map(|(_, c)| *c as u64).unwrap_or(0);
    for (name, count) in hist.iter().take(args.top) {
        println!(
            "   {:<26} {:>5}  {} {}",
            trunc(name, 26),
            count,
            bar(*count as u64, max),
            pct(*count, triv.len())
        );
    }
    if hist.len() > args.top {
        println!("   … +{} more detector(s)", hist.len() - args.top);
    }
}

fn cmd_search(findings: &[&Finding], args: &Args) -> i32 {
    if findings.is_empty() {
        println!("no findings matched");
        return 1;
    }
    let det_width = findings
        .iter()
        .map(|f| f.DetectorName.chars().count())
        .max()
        .unwrap_or(0)
        .min(30);
    let site_width = findings
        .iter()
        .map(|f| f.site().chars().count())
        .max()
        .unwrap_or(0)
        .clamp(4, 30);
    for f in findings {
        let value = if args.full {
            flatten(f.value())
        } else {
            trunc(f.value(), 48)
        };
        println!(
            " {:<w$}  {:<48}  {:<sw$}  {}",
            f.DetectorName,
            value,
            f.site(),
            f.location(),
            w = det_width,
            sw = site_width,
        );
    }
    println!("\n {} finding(s)", findings.len());

    if args.describe {
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for f in findings {
            if !f.DetectorDescription.is_empty() {
                seen.insert(&f.DetectorName, &f.DetectorDescription);
            }
        }
        println!();
        for (det, desc) in seen {
            println!(" {det}\n   {desc}\n");
        }
    }
    0
}

fn cmd_dupes(findings: &[&Finding], args: &Args) -> i32 {
    let mut by_value: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_value.entry(f.value()).or_default().push(*f);
    }
    let mut groups: Vec<(&str, Vec<&Finding>)> =
        by_value.into_iter().filter(|(_, v)| v.len() > 1).collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));

    if groups.is_empty() {
        println!("no repeated secrets — every key appears exactly once");
        return 0;
    }

    println!(" secrets found more than once (top {})", args.top);
    let max = groups.first().map(|(_, v)| v.len() as u64).unwrap_or(0);
    for (value, group) in groups.iter().take(args.top) {
        let detector = group[0].DetectorName.as_str();
        let warcs: std::collections::BTreeSet<String> =
            group.iter().filter_map(|f| f.warc()).collect();
        let source = if warcs.is_empty() {
            let files: std::collections::BTreeSet<String> =
                group.iter().map(|f| f.location()).collect();
            let mut list: Vec<&str> = files.iter().map(String::as_str).collect();
            list.sort();
            let shown: Vec<&str> = list.iter().take(2).copied().collect();
            format!("in {} file(s): {}{}", list.len(), shown.join(", "),
                if list.len() > 2 { format!(" +{}", list.len() - 2) } else { String::new() })
        } else {
            let mut list: Vec<&str> = warcs.iter().map(String::as_str).collect();
            list.sort();
            let shown: Vec<&str> = list.iter().take(2).copied().collect();
            format!("in {} WARC(s): {}{}", list.len(), shown.join(", "),
                if list.len() > 2 { format!(" +{}", list.len() - 2) } else { String::new() })
        };
        println!(
            " {:>4}× {:<24} {}",
            group.len(),
            trunc(detector, 24),
            trunc(value, 44),
        );
        println!(
            "        {}  {} {}",
            source,
            pct(group.len(), findings.len()),
            bar(group.len() as u64, max),
        );
    }
    let repeated_keys = groups.len();
    let repeated_hits: usize = groups.iter().map(|(_, v)| v.len()).sum();
    println!(
        "\n {repeated_keys} secret(s) appear more than once, covering {repeated_hits} finding(s)"
    );
    0
}

fn run() -> Result<i32> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;

    if matches!(args.cmd, Cmd::Help) {
        print!("{}", usage());
        return Ok(0);
    }

    let inputs = if args.files.is_empty() {
        default_inputs()
    } else {
        args.files.clone()
    };
    let files = match gather_files(&inputs) {
        Ok(f) => f,
        Err(e) if args.files.is_empty() => {
            bail!("{e:#}\n(no input given: looked for results/findings.jsonl and results/spill/*.jsonl — run apikeyfinder first, or pass -f <file>)");
        }
        Err(e) => return Err(e),
    };

    let (all, skipped) = load_findings(&files)?;
    let query = match &args.cmd {
        Cmd::Search(q) => q.as_deref(),
        _ => None,
    };
    let findings: Vec<&Finding> = all
        .iter()
        .filter(|f| matches_filters(f, &args, query))
        .collect();

    if skipped > 0 {
        eprintln!("note: skipped {skipped} unparsable line(s)");
    }

    match &args.cmd {
        Cmd::Tui => {
            if findings.is_empty() {
                bail!("no findings matched the given filters");
            }
            if tui::stdout_is_tty() {
                // `e` in the TUI exports next to the input (results/exports)
                let export_dir = files
                    .first()
                    .and_then(|p| p.parent())
                    .unwrap_or_else(|| Path::new("results"))
                    .join("exports");
                tui::run(&findings, &export_dir)
            } else {
                println!(
                    "input: {} file(s), {} finding(s)",
                    files.len(),
                    findings.len()
                );
                println!();
                cmd_stats(&findings, &args);
                Ok(0)
            }
        }
        Cmd::Stats => {
            println!(
                "input: {} file(s), {} finding(s)",
                files.len(),
                findings.len()
            );
            if findings.is_empty() {
                bail!("no findings matched the given filters");
            }
            println!();
            cmd_stats(&findings, &args);
            Ok(0)
        }
        Cmd::Search(_) => Ok(cmd_search(&findings, &args)),
        Cmd::Dupes => Ok(cmd_dupes(&findings, &args)),
        Cmd::Help => unreachable!(),
    }
}

fn main() {
    // die silently on SIGPIPE like a well-behaved CLI (piping into head, cut, ...)
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL); }
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"work/CC-MAIN-2026-x.warc.gz.chunks/chunk-000003.warc","line":42}}},"DetectorName":"GoogleGeminiAPIKey","Verified":true,"Raw":"AIzaSyA-test-key-123","RawV2":"","Redacted":"AIzaSyA-test…","DetectorDescription":"Google Gemini API key."}"#;

    #[test]
    fn parses_finding_fields() {
        let f: Finding = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(f.DetectorName, "GoogleGeminiAPIKey");
        assert_eq!(f.value(), "AIzaSyA-test-key-123");
        assert_eq!(f.location(), "work/CC-MAIN-2026-x.warc.gz.chunks/chunk-000003.warc:42");
        assert_eq!(f.warc().as_deref(), Some("CC-MAIN-2026-x"));
        assert!(f.url.is_none(), "old findings have no enrichment");
        assert_eq!(f.site(), "-");
        assert!(f.ExtraData.is_none());
    }

    #[test]
    fn parses_enriched_url_and_context() {
        let enriched = r#"{"DetectorName":"BitLyAccessToken","Raw":"abc123","url":"https://Example.COM/path?q=1","context":"…var t=\"abc123\";…"}"#;
        let f: Finding = serde_json::from_str(enriched).unwrap();
        assert_eq!(f.site(), "example.com");
        assert_eq!(f.context.as_deref(), Some("…var t=\"abc123\";…"));
    }

    #[test]
    fn host_of_strips_scheme_path_port_userinfo() {
        assert_eq!(host_of("https://Example.com:443/a/b"), "example.com");
        assert_eq!(host_of("http://user:pw@sub.dom.tld/"), "sub.dom.tld");
        assert_eq!(host_of("example.com/no-scheme"), "example.com");
        assert_eq!(host_of(""), "-");
    }

    #[test]
    fn value_falls_back_to_rawv2_then_redacted() {
        let mut f: Finding = serde_json::from_str(SAMPLE).unwrap();
        f.Raw.clear();
        f.Redacted.clear();
        assert_eq!(f.value(), "<unknown>");
        f.Redacted = "abc…".into();
        assert_eq!(f.value(), "abc…");
        f.RawV2 = "v2".into();
        assert_eq!(f.value(), "v2"); // RawV2 wins over Redacted
    }

    #[test]
    fn bar_scales_and_always_visible() {
        assert_eq!(bar(0, 10), "");
        assert_eq!(bar(10, 10), "█".repeat(BAR_WIDTH));
        let small = bar(1, 1000);
        assert!(!small.is_empty(), "tiny non-zero counts must still show");
        assert!(bar(5, 10).chars().count() <= BAR_WIDTH);
    }

    #[test]
    fn histogram_sorts_by_count_then_name() {
        let v = histogram(["b", "a", "a", "c"].into_iter());
        assert_eq!(v, vec![("a".to_string(), 2), ("b".to_string(), 1), ("c".to_string(), 1)]);
    }

    #[test]
    fn search_and_filter_matching() {
        let f: Finding = serde_json::from_str(SAMPLE).unwrap();
        let mut args = parse_args(&["search".into()]).unwrap();
        assert!(matches_filters(&f, &args, Some("gemini")));
        assert!(matches_filters(&f, &args, Some("AIzaSy")));
        assert!(!matches_filters(&f, &args, Some("newrelic")));
        assert!(matches_filters(&f, &args, None));

        args.detector = Some("GEMINI".into());
        assert!(matches_filters(&f, &args, None));
        args.detector = Some("newrelic".into());
        assert!(!matches_filters(&f, &args, None));

        args.detector = None;
        args.regex = true;
        assert!(matches_filters(&f, &args, Some("key-\\d+")));
        assert!(!matches_filters(&f, &args, Some("^[0-9]+$")));

        args.regex = false;
    }

    #[test]
    fn classifies_by_detector_and_algolia_acl() {
        let mk = |json: &str| serde_json::from_str::<Finding>(json).unwrap();
        let pub_det = mk(r#"{"DetectorName":"NewRelicBrowserKey","Raw":"NRBR-x"}"#);
        assert_eq!(category(&pub_det), Cat::Trivial);
        let crit = mk(r#"{"DetectorName":"PrivateKey","Raw":"-----BEGIN EC PRIVATE KEY-----"}"#);
        assert_eq!(category(&crit), Cat::Bad);
        let jwt = mk(r#"{"DetectorName":"JWT","Raw":"eyJ..."}"#);
        assert_eq!(category(&jwt), Cat::Bad);
        let unknown = mk(r#"{"DetectorName":"SomeFutureDetector","Raw":"x"}"#);
        assert_eq!(category(&unknown), Cat::Bad);
        let ld_sdk = mk(r#"{"DetectorName":"LaunchDarkly","Raw":"sdk-abc"}"#);
        assert_eq!(category(&ld_sdk), Cat::Trivial);
        let ld_api = mk(r#"{"DetectorName":"LaunchDarkly","Raw":"api-abc"}"#);
        assert_eq!(category(&ld_api), Cat::Bad);

        let algolia = |acl: &str| {
            mk(&format!(
                r#"{{"DetectorName":"AlgoliaAdminKey","Raw":"k","ExtraData":{{"acl":"{acl}"}}}}"#
            ))
        };
        assert_eq!(category(&algolia("addObject,search")), Cat::Bad);
        assert_eq!(category(&algolia("browse,listIndexes,search,settings")), Cat::Bad);
        assert_eq!(category(&algolia("browse,search")), Cat::Trivial);
        assert_eq!(category(&algolia("analytics,listIndexes")), Cat::Bad);
        let no_acl = mk(r#"{"DetectorName":"AlgoliaAdminKey","Raw":"k"}"#);
        assert_eq!(category(&no_acl), Cat::Bad);
    }

    #[test]
    fn parses_artifact_field() {
        let with_art = r#"{"DetectorName":"JWT","Raw":"x","artifact":"results/artifacts/w/chunk-000042-L7.txt"}"#;
        let f: Finding = serde_json::from_str(with_art).unwrap();
        assert_eq!(
            f.artifact.as_deref(),
            Some("results/artifacts/w/chunk-000042-L7.txt")
        );
        let old: Finding = serde_json::from_str(SAMPLE).unwrap();
        assert!(old.artifact.is_none(), "old findings have no artifact");
    }

    #[test]
    fn annot_covers_key_detectors() {
        let shopify: Finding = serde_json::from_str(
            r#"{"DetectorName":"Shopify","Raw":"shpat_x","SecretParts":{"store_url":"s.myshopify.com"},"ExtraData":{"access_scopes":"read_products,write_products"}}"#,
        )
        .unwrap();
        let a = annot(&shopify).unwrap();
        assert!(a.contains("s.myshopify.com") && a.contains("2 access scopes"), "{a}");

        let tg: Finding = serde_json::from_str(
            r#"{"DetectorName":"TelegramBotToken","Raw":"1:abc","ExtraData":{"username":"my_bot"}}"#,
        )
        .unwrap();
        assert_eq!(annot(&tg).as_deref(), Some("@my_bot"));

        let plain: Finding = serde_json::from_str(r#"{"DetectorName":"JWT","Raw":"x"}"#).unwrap();
        assert!(annot(&plain).is_none());
    }

    #[test]
    fn pem_detail_detects_encrypted_without_openssl() {
        let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMII...\n-----END ENCRYPTED PRIVATE KEY-----";
        let d = pem_detail(enc).unwrap();
        assert!(d.contains("encrypted"), "{d}");
    }

    #[test]
    fn parses_flags_and_commands() {
        let a = parse_args(&["-f".into(), "x.jsonl".into(), "--top".into(), "5".into()]).unwrap();
        assert_eq!(a.cmd, Cmd::Tui); // no command → interactive TUI
        assert_eq!(a.files, vec![PathBuf::from("x.jsonl")]);
        assert_eq!(a.top, 5);

        let a = parse_args(&["stats".into()]).unwrap();
        assert_eq!(a.cmd, Cmd::Stats);

        let a = parse_args(&["search".into(), "api".into(), "key".into()]).unwrap();
        assert_eq!(a.cmd, Cmd::Search(Some("api key".into())));

        assert!(parse_args(&["--bogus".into()]).is_err());
        assert!(parse_args(&["frobnicate".into()]).is_err());
        assert!(parse_args(&["--top".into()]).is_err());
    }

    #[test]
    fn gathers_jsonl_from_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.jsonl"), "{}\n").unwrap();
        std::fs::write(dir.path().join("b.txt"), "nope\n").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/c.jsonl"), "{}\n").unwrap();
        let files = gather_files(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|p| p.extension().is_some_and(|x| x == "jsonl")));
    }

    #[test]
    fn loads_and_counts_bad_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.jsonl");
        std::fs::write(&p, format!("{SAMPLE}\n\nnot json at all\n")).unwrap();
        let (findings, skipped) = load_findings(&[p]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(skipped, 1);
    }
}
