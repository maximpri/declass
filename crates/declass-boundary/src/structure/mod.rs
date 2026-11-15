// SPDX-License-Identifier: GPL-3.0-or-later
//! The structure of sensitive data, told without its values.
//!
//! Three deterministic views of sensitive content, computed on this machine
//! without any model, so the frontier learns how the data is laid out
//! without an `ask_local` round trip per question:
//!
//! - **Structure view** ([`profile`], [`Profile::render`]): the format, the
//!   number of records, the schema (JSON paths, columns, `.env` keys, XML
//!   element paths, log line templates), inferred types, each field's value
//!   formats as shape masks ([`shape`]: letters as `A`/`a`, digits as `9`,
//!   punctuation kept; date and time layouts as pictures such as
//!   `yyyy-MM-dd HH:mm:ss.SSSSSS`), presence, null and empty counts,
//!   distinct-count buckets, length ranges and anomalies (mixed formats,
//!   embedded delimiters, encoding problems, duplicates). Counts and shapes
//!   only, never a value.
//! - **Synthetic twin** ([`twin`]): the first records of a data file with
//!   every value replaced by a rule-generated fake of the same shape (valid
//!   dates, checksummed card numbers and IBANs, the same nulls, lengths,
//!   quoting and edge cases), deterministic per run seed. A fake depends on
//!   its value's shape and on where the value first occurs, never on the
//!   value itself; a check then proves no known value is in the twin.
//! - **Masked output** ([`masked`]): short output of a command that read
//!   sensitive data, with every value replaced by its shape; small numbers
//!   are shown only within a per-run budget.
//!
//! What counts as a value is decided by the caller's [`Knowledge`]: the
//! engine's vault and detectors, the words of the public files, and the
//! words that occur in values of sensitive data.

pub mod dates;
pub mod masked;
pub mod parse;
pub mod profile;
pub mod shape;
pub mod twin;

pub use profile::{Profile, profile};

use crate::detect::Kind;
use std::path::Path;

/// What the caller knows about sensitive values and public words.
pub trait Knowledge {
    /// Byte ranges of the sensitive values in `text` (known or detected),
    /// with their kind.
    fn values(&self, text: &str) -> Vec<(usize, usize, Kind)>;
    /// Whether the lower-cased word occurs in public content (the task,
    /// public files) or in schema the frontier was shown.
    fn public_word(&self, word: &str) -> bool;
    /// Whether the lower-cased word occurs in a value of sensitive data
    /// (a JSON string, a CSV cell): such a word is a value, not structure.
    fn data_word(&self, word: &str) -> bool;
    /// Whether `text` holds a value the caller knows as sensitive: what a
    /// synthetic twin must never hold. A detected format alone does not
    /// count (a fake card number is detected as a card).
    fn known(&self, _text: &str) -> bool {
        false
    }
}

/// Knowledge of nothing: every word is a value, nothing is detected.
pub struct Nothing;

impl Knowledge for Nothing {
    fn values(&self, _: &str) -> Vec<(usize, usize, Kind)> {
        Vec::new()
    }
    fn public_word(&self, _: &str) -> bool {
        false
    }
    fn data_word(&self, _: &str) -> bool {
        false
    }
}

/// The format of a piece of sensitive content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    Json,
    JsonLines,
    Delimited {
        delimiter: char,
    },
    Env,
    FixedWidth,
    Xml,
    /// Lines, mostly starting with a timestamp or naming a log level.
    Log,
    /// Anything else: described by its line templates.
    Text,
}

impl Format {
    pub fn name(&self) -> String {
        match self {
            Format::Json => "JSON".into(),
            Format::JsonLines => "JSON lines".into(),
            Format::Delimited { delimiter: ',' } => "CSV".into(),
            Format::Delimited { delimiter: '\t' } => "TSV".into(),
            Format::Delimited { delimiter } => format!("text delimited by `{delimiter}`"),
            Format::Env => "KEY=value".into(),
            Format::FixedWidth => "fixed-width columns".into(),
            Format::Xml => "XML".into(),
            Format::Log => "log".into(),
            Format::Text => "text".into(),
        }
    }

    /// Whether the format has records a synthetic twin can be made of.
    pub fn has_records(&self) -> bool {
        !matches!(self, Format::Log | Format::Text)
    }
}

static LOG_START: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)^\s*(?:\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|\[?\d{2}:\d{2}:\d{2}|\[?[a-z]{3} +\d{1,2} \d{2}:\d{2}|\d{10,13}\b|\[?(?:trace|debug|info|warn|warning|error|fatal|critical)\b)",
    )
    .expect("static regex")
});

/// The format of `text`, read from `path`'s extension when given, else
/// from the content.
pub fn detect(text: &str, path: Option<&Path>) -> Format {
    let ext = path
        .and_then(|p| p.extension())
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let name = path
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && parse::json(text.trim_start_matches('\u{feff}')).is_some()
    {
        return Format::Json;
    }
    if parse::json_lines(text).is_some() {
        return Format::JsonLines;
    }
    // A file named as one is read as `KEY=value` when it has an
    // assignment; other text only when most of its lines are assignments.
    let env_name = name.starts_with(".env") || name.ends_with(".env") || ext == "env";
    if (env_name && !parse::assignments(text).is_empty())
        || (matches!(ext.as_str(), "" | "properties" | "cfg") && parse::looks_like_env(text))
    {
        return Format::Env;
    }
    if (ext == "xml" || trimmed.starts_with("<?xml") || trimmed.starts_with('<'))
        && parse::xml(text).is_some()
    {
        return Format::Xml;
    }
    let hint = match ext.as_str() {
        "csv" => Some(','),
        "tsv" | "tab" => Some('\t'),
        "psv" => Some('|'),
        _ => None,
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let loglike = lines.iter().filter(|l| LOG_START.is_match(l)).count();
    let is_log = ext == "log" || (!lines.is_empty() && loglike * 2 >= lines.len());
    if !is_log && let Some(d) = parse::sniff_delimiter(text, hint) {
        return Format::Delimited { delimiter: d };
    }
    if !is_log && parse::fixed_width(text).is_some() {
        return Format::FixedWidth;
    }
    if is_log { Format::Log } else { Format::Text }
}

/// The string values of structured content, trimmed: JSON strings,
/// delimited cells after a header, XML text and attributes, fixed-width
/// cells. The caller treats them as values wherever they appear again (in
/// masked output and line templates), even when every word of one is also
/// a word of the public files (`same-day`, a note of plain words).
pub fn values(text: &str, path: Option<&Path>) -> Vec<String> {
    fn json_values(v: &parse::Json, out: &mut Vec<String>) {
        match v {
            parse::Json::Object { entries, .. } => {
                entries.iter().for_each(|(_, x)| json_values(x, out))
            }
            parse::Json::Array { items, .. } => items.iter().for_each(|x| json_values(x, out)),
            parse::Json::String { value, .. } => out.push(value.trim().to_owned()),
            _ => {}
        }
    }
    let mut out = Vec::new();
    let body = text.trim_start_matches('\u{feff}');
    match detect(body, path) {
        Format::Json => {
            if let Some(v) = parse::json(body) {
                json_values(&v, &mut out);
            }
        }
        Format::JsonLines => {
            for v in parse::json_lines(body).unwrap_or_default() {
                json_values(&v, &mut out);
            }
        }
        Format::Delimited { delimiter } => {
            if let Some(rows) = parse::delimited(body, delimiter) {
                // A first row of names is skipped, header or not: a header's
                // words as values would be masked wherever they appear.
                let skip = usize::from(profile::named_first_row(&rows, &Nothing));
                for r in &rows[skip..] {
                    out.extend(r.cells.iter().map(|c| c.value.trim().to_owned()));
                }
            }
        }
        Format::Xml => {
            if let Some(x) = parse::xml(body) {
                out.extend(x.values.iter().map(|v| v.value.trim().to_owned()));
            }
        }
        Format::FixedWidth => {
            if let Some(cols) = parse::fixed_width(body) {
                for l in body.lines().skip(1) {
                    for c in &cols {
                        out.push(l.get(c.clone()).unwrap_or_default().trim().to_owned());
                    }
                }
            }
        }
        Format::Env | Format::Log | Format::Text => {}
    }
    out.retain(|v| !v.is_empty());
    out
}

/// Words that mean "no value" or a yes/no: never a value on their own.
pub fn marker_word(word: &str) -> bool {
    matches!(
        word.to_lowercase().as_str(),
        "null"
            | "none"
            | "nil"
            | "n/a"
            | "na"
            | "undefined"
            | "nan"
            | "true"
            | "false"
            | "yes"
            | "no"
            | "y"
            | "n"
            | "-"
            | "--"
    )
}

/// Built-in member names of common languages' objects: data keys with
/// these names are worth knowing about (they collide with the language).
pub const SPECIAL_KEYS: &[&str] = &[
    "__proto__",
    "constructor",
    "prototype",
    "toString",
    "valueOf",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__class__",
    "__dict__",
    "__init__",
];

/// Whether a key (a JSON key, a column or element name) is schema that may
/// be shown as written: 1 to 64 characters of letters, digits and simple
/// punctuation, no run of four or more digits (dates, ids), and nothing
/// the caller knows or detects as a sensitive value. Other keys are data
/// (a map keyed by email addresses or customer ids) and shown as `*`.
pub fn schema_key(key: &str, k: &dyn Knowledge) -> bool {
    let n = key.chars().count();
    let mut digits = 0;
    let mut longest = 0;
    for c in key.chars() {
        if c.is_ascii_digit() {
            digits += 1;
            longest = longest.max(digits);
        } else {
            digits = 0;
        }
    }
    (1..=64).contains(&n)
        && key
            .chars()
            .all(|c| c.is_alphanumeric() || " _-.$@#:/()[]".contains(c))
        && longest < 4
        && k.values(key).is_empty()
}

/// The keys of the JSON document `root` that name records rather than
/// fields, by the byte ranges of their names: values, whatever their shape.
/// Objects are read by place: the elements of an array (or the lines of
/// JSON lines) are at one place, and so are the values of one field in each
/// of them, or of every member of a map. A key that several of the objects
/// at its place have is a field, unless they are elements of one member
/// each (records keyed by a name, `[{"mlopez": …}, {"mlopez": …}]`). Any other
/// key (of an object alone at its place, `{"mlopez": 30, "jsmith": null}`;
/// of one object of several, `[{"mlopez": …}, {"jsmith": …}]`) is a value
/// unless the frontier knows it ([`known_key`]); locale codes and
/// environment names count only as the keys of objects that have no other
/// (`{"en": …, "fr": …}`), so a person's initials are not taken for a
/// language. The values under a key that is a value, a locale, an
/// environment or a package's path are at one place, as a map's records.
pub fn record_keys(
    root: &parse::Json,
    k: &dyn Knowledge,
) -> std::collections::HashSet<std::ops::Range<usize>> {
    use parse::Json;
    let mut out = std::collections::HashSet::new();
    // The values at each place, and whether they are elements of arrays.
    let mut places: Vec<(Vec<&Json>, bool)> = vec![(vec![root], false)];
    while let Some((place, elements)) = places.pop() {
        let mut items: Vec<&Json> = Vec::new();
        let mut objects: Vec<&[(parse::Key, Json)]> = Vec::new();
        for v in place {
            match v {
                Json::Array { items: xs, .. } => items.extend(xs),
                Json::Object { entries, .. } => objects.push(entries),
                _ => {}
            }
        }
        if !items.is_empty() {
            places.push((items, true));
        }
        let mut count: std::collections::HashMap<&str, usize> = Default::default();
        for o in &objects {
            let names: std::collections::HashSet<&str> =
                o.iter().map(|(key, _)| key.name.as_str()).collect();
            for n in names {
                *count.entry(n).or_default() += 1;
            }
        }
        let fields = objects.len() >= 2 && (!elements || objects.iter().any(|o| o.len() > 1));
        let locales = count.keys().all(|n| locale(n));
        let environments = count
            .keys()
            .all(|n| ENVIRONMENTS.contains(&n.to_lowercase().as_str()));
        let mut under: std::collections::HashMap<&str, Vec<&Json>> = Default::default();
        for (key, x) in objects.iter().flat_map(|o| o.iter()) {
            let name = key.name.as_str();
            let map_key = locales || environments || package_path(name);
            let value = !(fields && count[name] >= 2) && !map_key && !known_key(name, k);
            if value {
                out.insert(key.span.clone());
            }
            under
                .entry(if value || map_key { "\u{0}" } else { name })
                .or_default()
                .push(x);
        }
        places.extend(under.into_values().map(|values| (values, false)));
    }
    out
}

/// Names of deployment environments: keys of configuration, not records.
const ENVIRONMENTS: &[&str] = &[
    "alpha",
    "beta",
    "ci",
    "default",
    "demo",
    "dev",
    "develop",
    "development",
    "live",
    "local",
    "preview",
    "prod",
    "production",
    "qa",
    "sandbox",
    "stage",
    "staging",
    "test",
    "testing",
    "uat",
];

/// ISO 639-1 language codes.
const LANGUAGES: &[&str] = &[
    "aa", "ab", "ae", "af", "ak", "am", "an", "ar", "as", "av", "ay", "az", "ba", "be", "bg", "bh",
    "bi", "bm", "bn", "bo", "br", "bs", "ca", "ce", "ch", "co", "cr", "cs", "cu", "cv", "cy", "da",
    "de", "dv", "dz", "ee", "el", "en", "eo", "es", "et", "eu", "fa", "ff", "fi", "fj", "fo", "fr",
    "fy", "ga", "gd", "gl", "gn", "gu", "gv", "ha", "he", "hi", "ho", "hr", "ht", "hu", "hy", "hz",
    "ia", "id", "ie", "ig", "ii", "ik", "io", "is", "it", "iu", "ja", "jv", "ka", "kg", "ki", "kj",
    "kk", "kl", "km", "kn", "ko", "kr", "ks", "ku", "kv", "kw", "ky", "la", "lb", "lg", "li", "ln",
    "lo", "lt", "lu", "lv", "mg", "mh", "mi", "mk", "ml", "mn", "mr", "ms", "mt", "my", "na", "nb",
    "nd", "ne", "ng", "nl", "nn", "no", "nr", "nv", "ny", "oc", "oj", "om", "or", "os", "pa", "pi",
    "pl", "ps", "pt", "qu", "rm", "rn", "ro", "ru", "rw", "sa", "sc", "sd", "se", "sg", "si", "sk",
    "sl", "sm", "sn", "so", "sq", "sr", "ss", "st", "su", "sv", "sw", "ta", "te", "tg", "th", "ti",
    "tk", "tl", "tn", "to", "tr", "ts", "tt", "tw", "ty", "ug", "uk", "ur", "uz", "ve", "vi", "vo",
    "wa", "wo", "xh", "yi", "yo", "za", "zh", "zu",
];

/// Whether `name` is a locale: an ISO 639-1 language, with a region
/// (`pt-BR`, `es_419`) or a script (`zh-Hant`) if any.
fn locale(name: &str) -> bool {
    static LOCALE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^([a-z]{2})(?:[-_](?:[A-Z]{2}|[A-Z][a-z]{3}|\d{3}))?$")
            .expect("static regex")
    });
    LOCALE
        .captures(name)
        .and_then(|c| c.get(1))
        .is_some_and(|l| LANGUAGES.contains(&l.as_str()))
}

/// Whether `name` is a package's path in a lock file: under `node_modules/`,
/// or an npm package's scoped name (`@babel/core`).
fn package_path(name: &str) -> bool {
    static SCOPED: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^@[a-z0-9~-][a-z0-9._~-]*/[a-z0-9~-][a-z0-9._~-]*$")
            .expect("static regex")
    });
    name.starts_with("node_modules/") || SCOPED.is_match(name)
}

/// Words of the names of fields and settings, which name no record.
#[rustfmt::skip]
const KEY_WORDS: &[&str] = &[
    "access", "account", "accounts", "action", "actions", "address", "addresses", "admin", "after",
    "age", "agent", "alias", "aliases", "all", "allow", "amount", "api", "app", "apps", "archive",
    "args", "arguments", "at", "attachment", "attachments", "attribute", "attributes", "audit",
    "auth", "author", "authors", "avatar", "backup", "balance", "bank", "base", "batch", "before",
    "billing", "bin", "birth", "blob", "body", "branch", "brand", "bucket", "budget", "buffer",
    "build", "bundle", "by", "cache", "callback", "card", "cards", "cart", "categories", "category",
    "cert", "certificate", "channel", "channels", "charge", "checksum", "city", "claim", "claims",
    "class", "client", "clients", "cluster", "code", "color", "column", "columns", "command",
    "comment", "comments", "commit", "company", "config", "configuration", "connection",
    "connections", "contact", "contacts", "content", "context", "count", "country", "coupon",
    "created", "credentials", "currency", "cursor", "customer", "customers", "data", "database",
    "databases", "date", "day", "days", "db", "debug", "default", "defaults", "delay", "deleted",
    "dependencies", "dependency", "deploy", "deployment", "description", "detail", "details", "dev",
    "device", "devices", "diff", "digest", "dir", "directory", "disabled", "discount", "display",
    "doc", "docs", "document", "documents", "domain", "download", "driver", "due", "duration",
    "editor", "email", "emails", "enabled", "end", "endpoint", "endpoints", "engine", "engines",
    "entries", "entry", "env", "environment", "environments", "envs", "error", "errors", "event",
    "events", "expires", "expiry", "export", "extra", "feature", "features", "fee", "field",
    "fields", "file", "files", "filter", "filters", "first", "flag", "flags", "folder", "format",
    "from", "full", "group", "groups", "has", "hash", "header", "headers", "health", "height",
    "history", "home", "host", "hosts", "hour", "hours", "href", "icon", "id", "ids", "image",
    "images", "import", "in", "index", "info", "input", "integrity", "interval", "invoice",
    "invoices", "ip", "is", "issue", "issues", "item", "items", "job", "jobs", "key", "keys",
    "kind", "label", "labels", "lang", "language", "last", "latitude", "layout", "level", "license",
    "limit", "limits", "line", "lines", "link", "links", "list", "locale", "location", "lock",
    "lockfile", "log", "login", "logs", "longitude", "mail", "main", "manager", "max", "member",
    "members", "message", "messages", "meta", "metadata", "method", "metrics", "min", "minute",
    "minutes", "mobile", "mode", "model", "models", "module", "modules", "month", "name", "names",
    "network", "next", "no", "node", "note", "notes", "num", "number", "object", "of", "offset",
    "on", "optional", "options", "order", "orders", "org", "organization", "origin", "output",
    "owner", "package", "packages", "page", "pages", "parameters", "params", "parent", "password",
    "path", "paths", "payload", "payment", "payments", "peer", "pending", "per", "period",
    "permission", "permissions", "phone", "pin", "plan", "plans", "platform", "plugin", "plugins",
    "policy", "pool", "port", "postal", "prefix", "prev", "price", "prices", "priority", "private",
    "product", "products", "profile", "profiles", "project", "projects", "properties", "property",
    "provider", "proxy", "public", "quantity", "queue", "quota", "range", "rate", "reason",
    "record", "records", "ref", "region", "release", "remote", "repo", "report", "reports",
    "repository", "request", "requests", "requires", "resolved", "resource", "resources",
    "response", "result", "results", "retries", "retry", "revision", "role", "roles", "root",
    "route", "routes", "rule", "rules", "sample", "schema", "scope", "scopes", "score", "script",
    "scripts", "secret", "secrets", "section", "sections", "seed", "server", "servers", "service",
    "services", "session", "sessions", "setting", "settings", "sha", "shipping", "size", "sku",
    "slug", "source", "sources", "start", "state", "stats", "status", "step", "steps", "storage",
    "store", "street", "subject", "subscription", "summary", "tag", "tags", "target", "task",
    "tasks", "tax", "team", "teams", "template", "tenant", "test", "text", "theme", "time",
    "timeout", "timestamp", "timezone", "title", "to", "token", "tokens", "topic", "total", "type",
    "types", "unit", "units", "updated", "uri", "url", "user", "username", "users", "uuid", "value",
    "values", "variant", "variants", "vendor", "version", "versions", "volume", "webhook", "weight",
    "width", "workers", "workspace", "year", "years", "zip", "zone",
];

/// Whether the frontier already has the key `name`, which is then shown
/// even where keys name records ([`record_keys`]): words of the public
/// files, the task or the schema shown ([`known_words`]), or words of the
/// names of fields and settings ([`KEY_WORDS`]: `created_at`,
/// `lockfileVersion`), every word of it, and numbers of two digits at most.
pub fn known_key(name: &str, k: &dyn Knowledge) -> bool {
    known_words(name, k) || {
        let words = key_words(name);
        !words.is_empty()
            && words.iter().all(|w| {
                KEY_WORDS.binary_search(&w.as_str()).is_ok()
                    || (w.len() <= 2 && w.bytes().all(|b| b.is_ascii_digit()))
            })
    }
}

/// The words of a key, lower-cased: its letters and digits, split where a
/// lower-case letter meets an upper-case one and where letters meet digits.
fn key_words(name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut prev: Option<char> = None;
    for c in name.chars() {
        if !c.is_alphanumeric() {
            prev = None;
            continue;
        }
        let split = prev.is_none_or(|p| {
            (p.is_lowercase() && c.is_uppercase()) || (p.is_alphabetic() != c.is_alphabetic())
        });
        if split {
            out.push(String::new());
        }
        if let Some(w) = out.last_mut() {
            w.extend(c.to_lowercase());
        }
        prev = Some(c);
    }
    out
}

/// Whether `name` is made of words the frontier already has (of the
/// public files, the task or the schema shown): the whole name, or every
/// part of it.
pub fn known_words(name: &str, k: &dyn Knowledge) -> bool {
    let lower = name.to_lowercase();
    k.public_word(&lower)
        || lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .all(|w| k.public_word(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_word_lists_are_sorted_and_keys_split_into_words() {
        for list in [KEY_WORDS, LANGUAGES] {
            assert!(list.windows(2).all(|w| w[0] < w[1]));
        }
        assert_eq!(key_words("lockfileVersion"), ["lockfile", "version"]);
        assert_eq!(key_words("created_at"), ["created", "at"]);
        assert_eq!(key_words("address2"), ["address", "2"]);
        assert_eq!(key_words("jd_001"), ["jd", "001"]);
        for known in [
            "created_at",
            "lockfileVersion",
            "devDependencies",
            "line2",
            "userId",
        ] {
            assert!(known_key(known, &Nothing), "{known}");
        }
        for value in [
            "mlopez",
            "jd_001",
            "jd",
            "mk",
            "bob@corp.example/inbox",
            "acme",
        ] {
            assert!(!known_key(value, &Nothing), "{value}");
        }
        for (name, is) in [
            ("en", true),
            ("pt-BR", true),
            ("es_419", true),
            ("zh-Hant", true),
        ] {
            assert_eq!(locale(name), is, "{name}");
        }
        for name in ["jd", "jd_001", "xx-YY"] {
            assert!(!locale(name), "{name}");
        }
        assert!(package_path("@babel/core") && package_path("node_modules/a/node_modules/b"));
        assert!(!package_path("bob@corp.example/inbox") && !package_path("@ x/y"));
    }

    #[test]
    fn formats_are_detected_by_content_and_extension() {
        let p = |s: &str| Some(Path::new(s).to_owned());
        assert_eq!(detect("{\"a\": [1, 2]}", None), Format::Json);
        assert_eq!(detect("{\"a\":1}\n{\"a\":2}\n", None), Format::JsonLines);
        assert_eq!(
            detect("id,name\n1,a\n2,b\n", p("data/x.csv").as_deref()),
            Format::Delimited { delimiter: ',' }
        );
        assert_eq!(
            detect("id\tname\n1\ta\n2\tb\n", None),
            Format::Delimited { delimiter: '\t' }
        );
        assert_eq!(detect("A=1\nB=two\n", p(".env").as_deref()), Format::Env);
        assert_eq!(
            detect("<r><a x=\"1\">t</a></r>", p("data/x.xml").as_deref()),
            Format::Xml
        );
        assert_eq!(
            detect(
                "2026-09-01T00:00:09Z INFO start, now\n2026-09-01T00:00:10Z ERROR x, y\n",
                p("logs/a.log").as_deref()
            ),
            Format::Log
        );
        assert_eq!(detect("plain words here\nand more\n", None), Format::Text);
    }

    #[test]
    fn keys_that_look_like_values_are_not_schema() {
        for ok in [
            "order_ref",
            "line1",
            "__proto__",
            "Order Date (UTC)",
            "psp_ts",
        ] {
            assert!(schema_key(ok, &Nothing), "{ok}");
        }
        for not in [
            "2026-09-01",
            "cust-004211",
            "",
            &"k".repeat(65),
            "a\nb",
            "x=y",
        ] {
            assert!(!schema_key(not, &Nothing), "{not}");
        }
    }
}
