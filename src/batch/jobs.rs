//! The textual forms of a job list: one job per line, JSON Lines, CSV.
//!
//! Nothing here does I/O; the caller hands in the text and gets back URLs
//! (still strings, so `mpt://` profiles and passwords are resolved later,
//! with the rest of the command's endpoints).

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A job as written in a list: URLs, not yet parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    pub src: String,
    pub dsts: Vec<String>,
}

/// How a job list is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `SRC DST [DST…]` per line, shell quoting, `#` comments.
    Lines,
    /// `{"src": "…", "dst": "…"}` or `"dst": ["…", "…"]` per line.
    Jsonl,
    /// Header row with a `src` column and one or more `dst` columns;
    /// comma- or tab-separated. No comments: every row is a job.
    Csv,
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "lines" | "text" => Ok(Format::Lines),
            "jsonl" | "json" | "ndjson" => Ok(Format::Jsonl),
            "csv" | "tsv" => Ok(Format::Csv),
            other => Err(format!(
                "unknown job list format '{other}' (lines, jsonl, csv)"
            )),
        }
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Format::Lines => "lines",
            Format::Jsonl => "jsonl",
            Format::Csv => "csv",
        })
    }
}

/// Guess the format: from the file name's extension when there is one, else
/// from the first non-empty line (`{` is JSON, a header naming `src` is CSV,
/// anything else is the line form).
pub fn detect(name: Option<&str>, text: &str) -> Format {
    if let Some(name) = name {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".jsonl") || lower.ends_with(".ndjson") || lower.ends_with(".json") {
            return Format::Jsonl;
        }
        if lower.ends_with(".csv") || lower.ends_with(".tsv") {
            return Format::Csv;
        }
    }
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if first.starts_with('{') {
        return Format::Jsonl;
    }
    if is_csv_header(first) {
        return Format::Csv;
    }
    Format::Lines
}

/// A header row is a list of column names, one of which is `src`, with no
/// URL among them.
fn is_csv_header(line: &str) -> bool {
    let sep = if line.contains('\t') { '\t' } else { ',' };
    let cols: Vec<&str> = line
        .split(sep)
        .map(|c| c.trim().trim_matches('"'))
        .collect();
    cols.iter().any(|c| c.eq_ignore_ascii_case("src"))
        && cols.iter().all(|c| !c.contains("://") && !c.contains('/'))
}

/// Parse a job list.
pub fn parse(text: &str, format: Format) -> Result<Vec<JobSpec>> {
    match format {
        Format::Lines => parse_lines(text),
        Format::Jsonl => parse_jsonl(text),
        Format::Csv => parse_csv(text),
    }
}

/// Parse one entry of a list that is read as it arrives (`batch
/// --follow`), a line or a CSV row after its header. The caller knows
/// which line of the input that is, so an error says what is wrong, not
/// which line of `text` it was on.
pub fn parse_entry(text: &str, format: Format) -> Result<Vec<JobSpec>> {
    parse(text, format).map_err(|e| match e {
        Error::InvalidUrl(m) => match m
            .strip_prefix(LINE_PREFIX)
            .and_then(|rest| rest.split_once(": "))
        {
            Some((_, what)) => Error::InvalidUrl(format!("job list: {what}")),
            None => Error::InvalidUrl(m),
        },
        e => e,
    })
}

/// What a parse error starts with, before the number of the line.
const LINE_PREFIX: &str = "job list line ";

fn bad(line: usize, what: impl std::fmt::Display) -> Error {
    Error::InvalidUrl(format!("{LINE_PREFIX}{line}: {what}"))
}

fn parse_lines(text: &str) -> Result<Vec<JobSpec>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let words = shlex::split(trimmed).ok_or_else(|| bad(n, "unbalanced quotes"))?;
        let mut words = words.into_iter();
        let src = words.next().ok_or_else(|| bad(n, "empty"))?;
        let dsts: Vec<String> = words.collect();
        if dsts.is_empty() {
            return Err(bad(n, "a source needs at least one target"));
        }
        out.push(JobSpec { src, dsts });
    }
    Ok(out)
}

/// `"dst": "…"` or `"dst": ["…", "…"]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(d) => vec![d],
            OneOrMany::Many(d) => d,
        }
    }
}

/// A job in its JSON form: `{"src": "…", "dst": "…" | ["…", …]}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonJob {
    pub src: String,
    #[serde(alias = "dsts")]
    pub dst: OneOrMany,
}

impl JsonJob {
    /// The job as a spec, refusing an empty source or no target at all.
    pub fn into_spec(self) -> std::result::Result<JobSpec, &'static str> {
        let dsts: Vec<String> = self
            .dst
            .into_vec()
            .into_iter()
            .filter(|d| !d.is_empty())
            .collect();
        if self.src.is_empty() {
            return Err("empty src");
        }
        if dsts.is_empty() {
            return Err("a source needs at least one target");
        }
        Ok(JobSpec {
            src: self.src,
            dsts,
        })
    }
}

fn parse_jsonl(text: &str) -> Result<Vec<JobSpec>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let job: JsonJob = serde_json::from_str(trimmed).map_err(|e| bad(n, e))?;
        out.push(job.into_spec().map_err(|e| bad(n, e))?);
    }
    Ok(out)
}

fn parse_csv(text: &str) -> Result<Vec<JobSpec>> {
    let header = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let delimiter = if header.contains('\t') { b'\t' } else { b',' };
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .trim(csv::Trim::All)
        // No comments: `#` is an ordinary first character of a cell (a
        // source `#archive/x`), and a spreadsheet has no comment rows.
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| bad(1, e))?
        .iter()
        .map(|h| h.trim_matches('"').to_ascii_lowercase())
        .collect::<Vec<_>>();
    let src_col = headers
        .iter()
        .position(|h| h == "src")
        .ok_or_else(|| bad(1, "the header row needs a 'src' column"))?;
    let dst_cols: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter(|(_, h)| *h == "dst")
        .map(|(i, _)| i)
        .collect();
    if dst_cols.is_empty() {
        return Err(bad(1, "the header row needs at least one 'dst' column"));
    }
    let mut out = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|e| {
            let line = e.position().map(|p| p.line() as usize).unwrap_or(0);
            bad(line, e)
        })?;
        let line = record.position().map(|p| p.line() as usize).unwrap_or(0);
        let src = record.get(src_col).unwrap_or("").to_string();
        if src.is_empty() {
            if record.iter().all(|c| c.is_empty()) {
                continue;
            }
            return Err(bad(line, "empty src"));
        }
        let dsts: Vec<String> = dst_cols
            .iter()
            .filter_map(|&c| record.get(c))
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect();
        if dsts.is_empty() {
            return Err(bad(line, "a source needs at least one target"));
        }
        out.push(JobSpec { src, dsts });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(src: &str, dsts: &[&str]) -> JobSpec {
        JobSpec {
            src: src.into(),
            dsts: dsts.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// An entry read on its own is not numbered: its line in the input is
    /// the caller's to tell.
    #[test]
    fn an_entry_is_not_numbered() {
        let err = parse_entry("'unbalanced x/", Format::Lines)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "invalid URL: job list: unbalanced quotes");
        let err = parse_entry("src,dst\n,x/", Format::Csv)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "invalid URL: job list: empty src");
        let err = parse_entry("{\"src\": 1}", Format::Jsonl)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("invalid URL: job list: invalid type"),
            "{err}"
        );
        assert!(parse_entry("a b/", Format::Lines).is_ok());
    }

    #[test]
    fn lines_with_quotes_and_comments() {
        let text = "# jobs\n\n/tmp/a.bin sftp://h/in/ s3://b/x/\n'/tmp/my file.bin' \"mailto:a@example.com\"\n";
        let jobs = parse(text, Format::Lines).unwrap();
        assert_eq!(
            jobs,
            vec![
                spec("/tmp/a.bin", &["sftp://h/in/", "s3://b/x/"]),
                spec("/tmp/my file.bin", &["mailto:a@example.com"]),
            ]
        );
    }

    #[test]
    fn lines_report_the_line_number() {
        let err = parse("/tmp/a sftp://h/\n/tmp/b\n", Format::Lines)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 2"), "{err}");
        let err = parse("/tmp/a 'sftp://h/\n", Format::Lines)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 1") && err.contains("quotes"), "{err}");
    }

    #[test]
    fn jsonl_takes_one_or_many_targets() {
        let text = r#"{"src": "/tmp/a", "dst": "sftp://h/in/"}
{"src": "/tmp/b", "dst": ["sftp://h/in/", "s3://b/"]}

{"src": "/tmp/c", "dsts": ["ftp://f/"]}
"#;
        let jobs = parse(text, Format::Jsonl).unwrap();
        assert_eq!(
            jobs,
            vec![
                spec("/tmp/a", &["sftp://h/in/"]),
                spec("/tmp/b", &["sftp://h/in/", "s3://b/"]),
                spec("/tmp/c", &["ftp://f/"]),
            ]
        );
        let err = parse(r#"{"src": "/tmp/a", "dst": []}"#, Format::Jsonl)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 1"), "{err}");
        assert!(
            parse(
                r#"{"src": "/tmp/a", "dst": "x", "extra": 1}"#,
                Format::Jsonl
            )
            .is_err()
        );
        assert!(parse(r#"not json"#, Format::Jsonl).is_err());
    }

    #[test]
    fn csv_with_extra_columns_and_several_targets() {
        let text = "id,src,dst,dst,note\n1,/tmp/a,sftp://h/in/,s3://b/,first\n2,\"/tmp/b, with comma\",ftp://f/,,\n\n";
        let jobs = parse(text, Format::Csv).unwrap();
        assert_eq!(
            jobs,
            vec![
                spec("/tmp/a", &["sftp://h/in/", "s3://b/"]),
                spec("/tmp/b, with comma", &["ftp://f/"]),
            ]
        );
    }

    #[test]
    fn a_csv_row_starting_with_a_hash_is_a_job() {
        let text = "src,dst\n#archive/x,sftp://h/in/\n/tmp/a,sftp://h/in/\n";
        assert_eq!(
            parse(text, Format::Csv).unwrap(),
            vec![
                spec("#archive/x", &["sftp://h/in/"]),
                spec("/tmp/a", &["sftp://h/in/"]),
            ]
        );
    }

    #[test]
    fn tsv_is_recognized_by_its_header() {
        let text = "src\tdst\n/tmp/a\tsftp://h/in/\n";
        assert_eq!(detect(None, text), Format::Csv);
        assert_eq!(
            parse(text, Format::Csv).unwrap(),
            vec![spec("/tmp/a", &["sftp://h/in/"])]
        );
    }

    #[test]
    fn csv_without_the_columns_is_an_error() {
        let err = parse("source,target\n/tmp/a,sftp://h/\n", Format::Csv)
            .unwrap_err()
            .to_string();
        assert!(err.contains("'src'"), "{err}");
        let err = parse("src,target\n/tmp/a,sftp://h/\n", Format::Csv)
            .unwrap_err()
            .to_string();
        assert!(err.contains("'dst'"), "{err}");
        let err = parse("src,dst\n/tmp/a,\n", Format::Csv)
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn detection() {
        assert_eq!(detect(Some("jobs.csv"), "whatever"), Format::Csv);
        assert_eq!(detect(Some("jobs.tsv"), "whatever"), Format::Csv);
        assert_eq!(detect(Some("jobs.jsonl"), "whatever"), Format::Jsonl);
        assert_eq!(
            detect(Some("jobs.txt"), "/tmp/a sftp://h/\n"),
            Format::Lines
        );
        assert_eq!(
            detect(None, "\n{\"src\": \"a\", \"dst\": \"b\"}\n"),
            Format::Jsonl
        );
        assert_eq!(detect(None, "src,dst\n"), Format::Csv);
        assert_eq!(detect(None, "SRC,DST\n"), Format::Csv);
        assert_eq!(detect(None, "/data/src sftp://h/dst/\n"), Format::Lines);
        // A line-form job whose source happens to be called src.
        assert_eq!(detect(None, "src sftp://h/dst/\n"), Format::Lines);
        assert_eq!(detect(None, ""), Format::Lines);
    }

    #[test]
    fn empty_lists_are_fine() {
        assert!(parse("", Format::Lines).unwrap().is_empty());
        assert!(parse("# nothing\n", Format::Lines).unwrap().is_empty());
        assert!(parse("", Format::Jsonl).unwrap().is_empty());
        assert!(parse("src,dst\n", Format::Csv).unwrap().is_empty());
    }

    #[test]
    fn format_names() {
        assert_eq!("csv".parse::<Format>().unwrap(), Format::Csv);
        assert_eq!("NDJSON".parse::<Format>().unwrap(), Format::Jsonl);
        assert!("xml".parse::<Format>().is_err());
    }
}
