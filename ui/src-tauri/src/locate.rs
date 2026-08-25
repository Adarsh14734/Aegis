//! Finding the Python half of Aegis, from wherever this window happens to run.
//!
//! S6 walked up from the executable looking for `aegis/verify.py`. That works
//! in the dev tree, where the repository sits above `ui/src-tauri/target/...`,
//! and it fails for **every real user**: inside `/Applications/Aegis.app` there
//! is no repository above the binary, so the chain could not be verified and
//! the Permissions screen refused every edit. The shape reality produces was
//! the one shape the tests never had.
//!
//! So the search now covers the installed cases first and the dev tree last:
//!
//!   1. `AEGIS_HOME` — the operator override, unchanged from S6. A stale value
//!      is ignored rather than used, because "missing" and "somewhere else"
//!      must not look the same on screen.
//!   2. The **bundled resource**, via Tauri's own resolver. `tauri.conf.json`
//!      ships `aegis/` inside the app, which is what makes an installed .app
//!      self-contained.
//!   3. The same directory computed from the executable — `Contents/Resources`
//!      on macOS — for callers that have no `AppHandle` to hand.
//!   4. An **installed `aegis-mcp`** package, asked of `python3` itself. This
//!      is the case where someone `pip install`ed Aegis and also runs the app.
//!   5. The dev tree, by walking up. Last, because it is the rarest.
//!
//! **There is no sixth step that assumes everything is fine.** When none of
//! these finds the Python side, `find()` returns `None` and every caller says
//! so. A viewer that cannot check the chain has to keep saying it cannot check
//! the chain — the alternative is a green screen that means nothing, which is
//! the failure S6 was built to avoid and the one this bug produced.

use std::path::{Path, PathBuf};

/// A directory that CONTAINS the `aegis` package directory.
///
/// Both users need that rather than the package itself: the verifier is
/// `<dir>/aegis/verify.py`, and `python3 -m aegis.cli` needs `<dir>` on
/// PYTHONPATH.
#[derive(Debug, Clone)]
pub struct AegisRoot {
    pub dir: PathBuf,
    pub source: String,
}

impl AegisRoot {
    pub fn verifier(&self) -> PathBuf {
        self.dir.join("aegis").join("verify.py")
    }
}

fn holds_aegis(dir: &Path) -> bool {
    dir.join("aegis").join("verify.py").is_file()
}

fn candidate(dir: PathBuf, source: &str) -> Option<AegisRoot> {
    holds_aegis(&dir).then(|| AegisRoot { dir, source: source.to_string() })
}

/// Ask the interpreter where an installed `aegis-mcp` lives.
///
/// Deliberately asks Python rather than guessing at site-packages paths: the
/// answer depends on the interpreter, the virtualenv and the platform, and the
/// interpreter is the only thing that knows all three. Kept cheap — one short
/// subprocess, only reached when the bundled copy is absent.
///
/// Returns None when there is no interpreter new enough to run Aegis. That is
/// the honest answer: an installed package this app cannot execute is not an
/// installation it can use, and pretending otherwise moves the failure to a
/// later, less legible place.
fn installed_package() -> Option<AegisRoot> {
    // The same interpreter everything else will use. Asking a Python that
    // cannot load Aegis where Aegis is installed would answer for the wrong
    // machine — and on a Finder-launched app, bare `python3` is exactly that
    // Python. See python.rs.
    let out = crate::python::find()
        .ok()?
        .command()
        .arg("-c")
        .arg("import aegis,os,sys; sys.stdout.write(os.path.dirname(os.path.dirname(os.path.abspath(aegis.__file__))))")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8(out.stdout).ok()?;
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    candidate(PathBuf::from(dir), "installed aegis-mcp package")
}

/// Where the app's bundled resources live, derived from the executable.
///
/// `<app>/Contents/MacOS/aegis-ui` -> `<app>/Contents/Resources`. Used when no
/// `AppHandle` is available; the Tauri resolver is preferred when one is.
fn exe_resource_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let macos_dir = exe.parent()?;
    let contents = macos_dir.parent()?;
    Some(contents.join("Resources"))
}

pub fn find(app: Option<&tauri::AppHandle>) -> Option<AegisRoot> {
    if let Ok(home) = std::env::var("AEGIS_HOME") {
        if let Some(found) = candidate(PathBuf::from(home), "AEGIS_HOME") {
            return Some(found);
        }
    }

    if let Some(handle) = app {
        use tauri::Manager;
        if let Ok(res) = handle.path().resource_dir() {
            if let Some(found) = candidate(res, "bundled with the app") {
                return Some(found);
            }
        }
    }

    if let Some(res) = exe_resource_dir() {
        if let Some(found) = candidate(res, "bundled with the app") {
            return Some(found);
        }
    }

    if let Some(found) = installed_package() {
        return Some(found);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(found) = exe
            .ancestors()
            .find(|d| holds_aegis(d))
            .and_then(|d| candidate(d.to_path_buf(), "the development tree"))
        {
            return Some(found);
        }
    }
    std::env::current_dir().ok().and_then(|cwd| {
        cwd.ancestors()
            .find(|d| holds_aegis(d))
            .and_then(|d| candidate(d.to_path_buf(), "the working directory"))
    })
}

/// What to tell the user when nothing was found. Names every place looked, so
/// the message is actionable rather than a shrug.
pub fn not_found_message() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "this app".into());
    format!(
        "Aegis could not find its own Python components. Looked in: AEGIS_HOME, \
         this app's bundled resources, an installed aegis-mcp package (via \
         python3), and the folders above {exe}. Reinstall Aegis, or `pip install \
         aegis-mcp`, or set AEGIS_HOME to the Aegis source directory."
    )
}
