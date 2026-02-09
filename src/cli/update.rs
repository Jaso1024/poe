use anyhow::{bail, Context, Result};

const REPO: &str = "Jaso1024/poe";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

struct ReleaseInfo {
    tag: String,
    asset_url: String,
}

fn get_target() -> Result<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Ok("x86_64-unknown-linux-musl");
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return Ok("aarch64-unknown-linux-gnu");
    #[cfg(not(target_os = "linux"))]
    bail!("poe update only supports Linux");
}

fn parse_tag_from_json(body: &str) -> Option<String> {
    for line in body.lines() {
        if !line.contains("\"tag_name\"") {
            continue;
        }
        let after = &line[line.find("tag_name")? + 8..];
        let q1 = after.find('"')? + 1;
        let inner = &after[q1..];
        let q2 = inner.find('"')?;
        return Some(inner[..q2].to_string());
    }
    None
}

fn fetch_latest_release() -> Result<ReleaseInfo> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", REPO);
    let output = std::process::Command::new("curl")
        .args(["-sSf", "-H", "Accept: application/vnd.github.v3+json", &url])
        .output()
        .context("failed to run curl")?;

    if !output.status.success() {
        bail!(
            "failed to fetch release info: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let body = String::from_utf8(output.stdout)?;
    let tag = parse_tag_from_json(&body).context("could not parse tag_name from release")?;
    let target = get_target()?;

    let asset_url = format!(
        "https://github.com/{}/releases/download/{}/poe-{}.tar.gz",
        REPO, tag, target
    );

    Ok(ReleaseInfo { tag, asset_url })
}

fn version_is_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect()
    };
    parse(latest) > parse(current)
}

pub fn execute() -> Result<()> {
    println!("poe update");
    println!("  current version: v{}", CURRENT_VERSION);
    println!("  checking for updates...");

    let release = fetch_latest_release()?;
    let latest_version = release.tag.trim_start_matches('v');

    if !version_is_newer(latest_version, CURRENT_VERSION) {
        println!("  already up to date (v{})", CURRENT_VERSION);
        return Ok(());
    }

    println!("  new version available: {}", release.tag);
    println!("  downloading...");

    let tmp_path = std::env::temp_dir().join(format!("poe-update-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_path).context("failed to create temp dir")?;

    let tarball = tmp_path.join("poe.tar.gz");
    let dl_status = std::process::Command::new("curl")
        .args(["-sSfL", &release.asset_url, "-o", tarball.to_str().unwrap()])
        .status()
        .context("failed to download release")?;

    if !dl_status.success() {
        let _ = std::fs::remove_dir_all(&tmp_path);
        bail!("download failed (HTTP error). URL: {}", release.asset_url);
    }

    println!("  extracting...");
    let ex_status = std::process::Command::new("tar")
        .args([
            "xzf",
            tarball.to_str().unwrap(),
            "-C",
            tmp_path.to_str().unwrap(),
        ])
        .status()
        .context("failed to extract tarball")?;

    if !ex_status.success() {
        let _ = std::fs::remove_dir_all(&tmp_path);
        bail!("failed to extract tarball");
    }

    let new_binary = tmp_path.join("poe");
    if !new_binary.exists() {
        let _ = std::fs::remove_dir_all(&tmp_path);
        bail!("extracted archive did not contain 'poe' binary");
    }

    let current_exe = std::fs::canonicalize(
        std::env::current_exe().context("cannot determine current executable path")?,
    )?;
    let backup = current_exe.with_extension("old");

    std::fs::rename(&current_exe, &backup)
        .context("failed to back up current binary (do you have write permission?)")?;

    match std::fs::copy(&new_binary, &current_exe) {
        Ok(_) => {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&current_exe, std::fs::Permissions::from_mode(0o755))?;
            let _ = std::fs::remove_file(&backup);
            let _ = std::fs::remove_dir_all(&tmp_path);
            println!("  updated: v{} -> {}", CURRENT_VERSION, release.tag);
        }
        Err(e) => {
            let _ = std::fs::rename(&backup, &current_exe);
            let _ = std::fs::remove_dir_all(&tmp_path);
            bail!("failed to install new binary: {}. Rolled back.", e);
        }
    }

    Ok(())
}
