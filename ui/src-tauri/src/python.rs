//! Finding a Python that can actually run the Aegis half of this app.
//!
//! The bug this exists for: every call site said `Command::new("python3")`,
//! and an app launched from Finder inherits a PATH of
//! `/usr/bin:/bin:/usr/sbin:/sbin` — nothing else. On macOS `/usr/bin/python3`
//! is the Command Line Tools shim, which is **Python 3.9**. Aegis has required
//! 3.10 since the first commit (`requires-python = ">=3.10"`), so the window
//! ran the one interpreter on the machine that cannot load it, and the user
//! saw an annotation TypeError from `aegis/cli.py` on the Permissions screen.
//!
//! The developer never saw it because a terminal-launched build inherits the
//! shell's PATH, where `python3` is whatever the user installed. Same shape as
//! every other bug in this sprint: **the environment reality produces was the
//! one the tests never had.**
//!
//! So: candidates are probed, `sys.version_info` decides, and nothing is
//! assumed. The three rules here are the same three locate.rs follows.
//!
//!   1. **Ask, never guess.** The version comes from running the interpreter,
//!      not from its filename. `python3.11` on PATH can be a symlink to
//!      anything; a name is not a version.
//!   2. **No fallback to "probably fine".** If nothing qualifies, `find()`
//!      returns a sentence naming the version required and every place it
//!      looked. It does not return the newest thing it found and hope.
//!   3. **Probe once.** The Status screen polls every two seconds and each
//!      poll verifies the chain; re-probing a dozen interpreters on every tick
//!      would be absurd. The answer is resolved on first use and cached.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The minimum this app will run. Kept in agreement, by hand, with
/// `requires-python` in pyproject.toml, `MIN_PYTHON` in aegis/__init__.py and
/// `MIN_PYTHON` in aegis/verify.py — four copies in three languages, none of
/// which can import the others. tests/bundle.py asserts they agree.
pub const MIN_PYTHON: (u32, u32) = (3, 10);

pub fn required() -> String {
    format!("{}.{}", MIN_PYTHON.0, MIN_PYTHON.1)
}

#[derive(Debug, Clone)]
pub struct Interpreter {
    /// The path to run. This is `sys.executable` as the interpreter itself
    /// reported it, not the name we happened to invoke — so a shim, a symlink
    /// or a `pyenv` stub resolves to the real thing before it is stored.
    pub path: PathBuf,
    pub version: (u32, u32, u32),
    /// Where it came from, in words a person can act on.
    pub source: String,
}

impl Interpreter {
    pub fn version_string(&self) -> String {
        format!("{}.{}.{}", self.version.0, self.version.1, self.version.2)
    }

    /// A `Command` ready to run. Every caller goes through this so no code path
    /// can quietly reintroduce a bare `python3`.
    pub fn command(&self) -> Command {
        Command::new(&self.path)
    }
}

/// One line per interpreter that was found but rejected, kept so the failure
/// message can name what IS on the machine rather than only what is missing.
#[derive(Debug, Clone)]
pub struct Rejected {
    pub path: String,
    pub version: (u32, u32, u32),
}

#[derive(Debug, Clone)]
pub struct Search {
    pub found: Option<Interpreter>,
    pub rejected: Vec<Rejected>,
}

static RESOLVED: OnceLock<Search> = OnceLock::new();

/// The resolved interpreter, or a sentence explaining why there is none.
///
/// The error is the message the user reads. It names the version required, the
/// newest version actually present, and what to do — never a traceback and
/// never a bare path.
pub fn find() -> Result<&'static Interpreter, String> {
    let search = RESOLVED.get_or_init(resolve);
    match &search.found {
        Some(i) => Ok(i),
        None => Err(not_found_message(&search.rejected)),
    }
}

/// The whole search, for `aegis-ui --python`. Reports rather than decides.
pub fn search() -> &'static Search {
    RESOLVED.get_or_init(resolve)
}

/// What happened, in one sentence. Names the version required and the newest
/// version the machine actually has, because "install Python" is useless advice
/// to someone who has Python.
pub fn not_found_summary(rejected: &[Rejected]) -> String {
    let need = required();
    match rejected.iter().max_by_key(|r| r.version) {
        Some(r) => format!(
            "Aegis needs Python {need} or newer and did not find it. The newest \
             on this machine is Python {}.{}.{}, at {}.",
            r.version.0, r.version.1, r.version.2, r.path
        ),
        None => format!("Aegis needs Python {need} or newer and found no Python at all."),
    }
}

/// What to do about it. Separate from the summary so a screen can show the two
/// differently — the first is the fact, the second is the way out.
pub fn not_found_remedy() -> String {
    let need = required();
    format!(
        "Install Python {need} or newer — from python.org, or with `brew install \
         python@3.12` — then reopen Aegis. If you already have one, set \
         AEGIS_PYTHON to its full path. Looked at: AEGIS_PYTHON, python3 and \
         python3.10 through python3.14 on this app's PATH, Homebrew \
         (/opt/homebrew, /usr/local), /Library/Frameworks/Python.framework, and \
         pyenv."
    )
}

pub fn not_found_message(rejected: &[Rejected]) -> String {
    format!("{} {}", not_found_summary(rejected), not_found_remedy())
}

/// Ask an interpreter what it is. Nothing is inferred from the file name.
///
/// Written in the oldest Python that could possibly be on the other end: this
/// runs on the 3.9 that is being rejected, so it uses `%` formatting and no
/// annotations. A probe that crashes on the interpreter it is measuring would
/// report "no Python here" for a Python that is merely old, and the message
/// would name the wrong problem.
const PROBE: &str = "import sys;\
                     print('%d %d %d' % sys.version_info[:3]);\
                     print(sys.executable or '')";

fn probe(exe: &Path) -> Option<(u32, u32, u32, PathBuf)> {
    let out = Command::new(exe).arg("-c").arg(PROBE).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let nums: Vec<u32> = lines
        .next()?
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    if nums.len() != 3 {
        return None;
    }
    let real = lines.next().unwrap_or("").trim();
    let path = if real.is_empty() { exe.to_path_buf() } else { PathBuf::from(real) };
    Some((nums[0], nums[1], nums[2], path))
}

fn qualifies(v: (u32, u32, u32)) -> bool {
    (v.0, v.1) >= MIN_PYTHON
}

/// Version names newest-first. `python3` is tried before all of them so a
/// machine whose default already qualifies keeps using the interpreter its
/// owner chose; the numbered names are the fallback, not the preference.
const NAMES: &[&str] = &[
    "python3", "python3.14", "python3.13", "python3.12", "python3.11", "python3.10",
];

/// Directories a Finder-launched app cannot reach through PATH.
///
/// This list is the whole reason the bug existed: PATH inside a double-clicked
/// .app is `/usr/bin:/bin:/usr/sbin:/sbin`, and every Python a person actually
/// installs lands somewhere else.
///
/// `AEGIS_PYTHON_DIRS` REPLACES this list — colon-separated, same shape as
/// PATH. It exists so a test can put the search in a world containing only the
/// interpreters it chose, which is the only way to exercise the refusal on a
/// developer machine that has a good Python in three of these directories.
/// It can only ever narrow the search: the version gate is applied to whatever
/// it finds, so no value of this variable can make Aegis accept an interpreter
/// older than MIN_PYTHON. Documented rather than hidden, for the same reason
/// AEGIS_HOME is — an operator with an unusual install can use it too.
fn well_known_dirs() -> Vec<PathBuf> {
    if let Ok(only) = std::env::var("AEGIS_PYTHON_DIRS") {
        return only
            .split(':')
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .collect();
    }
    let mut dirs: Vec<PathBuf> = vec![
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/opt/local/bin"),
    ];
    for minor in (MIN_PYTHON.1..=20).rev() {
        dirs.push(PathBuf::from(format!(
            "/Library/Frameworks/Python.framework/Versions/3.{minor}/bin"
        )));
        dirs.push(PathBuf::from(format!("/opt/homebrew/opt/python@3.{minor}/bin")));
        dirs.push(PathBuf::from(format!("/usr/local/opt/python@3.{minor}/bin")));
    }
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(&home).join(".pyenv/shims"));
        dirs.push(PathBuf::from(&home).join(".local/bin"));
    }
    dirs.push(PathBuf::from("/usr/bin"));
    dirs
}

fn resolve() -> Search {
    let mut rejected: Vec<Rejected> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();

    // Each candidate is (what to run, how to describe it if it wins).
    let mut candidates: Vec<(PathBuf, String)> = Vec::new();

    if let Ok(explicit) = std::env::var("AEGIS_PYTHON") {
        if !explicit.trim().is_empty() {
            candidates.push((PathBuf::from(explicit), "AEGIS_PYTHON".into()));
        }
    }
    for name in NAMES {
        candidates.push((PathBuf::from(name), format!("`{name}` on this app's PATH")));
    }
    for dir in well_known_dirs() {
        for name in NAMES {
            let path = dir.join(name);
            if path.is_file() {
                candidates.push((path.clone(), path.display().to_string()));
            }
        }
    }

    for (exe, source) in candidates {
        let Some((maj, min, patch, real)) = probe(&exe) else {
            continue;
        };
        if seen.contains(&real) {
            continue;
        }
        seen.push(real.clone());
        if qualifies((maj, min, patch)) {
            return Search {
                found: Some(Interpreter {
                    path: real,
                    version: (maj, min, patch),
                    source,
                }),
                rejected,
            };
        }
        // Too old. Remembered rather than discarded: naming the 3.9 that IS
        // installed is what makes the failure message actionable.
        rejected.push(Rejected {
            path: real.display().to_string(),
            version: (maj, min, patch),
        });
    }

    Search { found: None, rejected }
}
