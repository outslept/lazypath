use std::collections::HashMap;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::model::{EnvScope, EnvVariable};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub(crate) fn silent_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

pub fn parse_reg_query_output(raw: &str, scope: EnvScope) -> Vec<EnvVariable> {
    let mut vars = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
            continue;
        }

        let reg_marker = if let Some(idx) = trimmed.find("REG_EXPAND_SZ") {
            Some((idx, "REG_EXPAND_SZ".len()))
        } else {
            trimmed.find("REG_SZ").map(|idx| (idx, "REG_SZ".len()))
        };

        let Some((marker_idx, marker_len)) = reg_marker else {
            continue;
        };

        let name = trimmed[..marker_idx].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let value = trimmed[marker_idx + marker_len..].trim().to_string();

        vars.push(EnvVariable {
            name,
            value,
            scope,
            modified: false,
        });
    }

    vars.sort_by_key(|v| (!v.is_path_var(), v.name.to_ascii_lowercase()));
    vars
}

pub fn read_scope_variables(scope: EnvScope) -> Result<Vec<EnvVariable>> {
    let output = silent_command("reg")
        .args(["query", scope.registry_key()])
        .output()
        .with_context(|| format!("failed to query registry key {}", scope.registry_key()))?;

    if !output.status.success() {
        bail!(
            "reg query exited with {} for {}",
            output.status,
            scope.registry_key()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_reg_query_output(&stdout, scope))
}

pub fn load_all_variables() -> (Vec<EnvVariable>, Vec<EnvVariable>) {
    let user_vars = read_scope_variables(EnvScope::User).unwrap_or_default();
    let sys_vars = read_scope_variables(EnvScope::System).unwrap_or_default();
    (user_vars, sys_vars)
}

pub fn build_lookup_map(
    user_vars: &[EnvVariable],
    sys_vars: &[EnvVariable],
) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in std::env::vars() {
        map.insert(k.to_ascii_uppercase(), v);
    }
    for v in sys_vars {
        map.insert(v.name.to_ascii_uppercase(), v.value.clone());
    }
    for v in user_vars {
        map.insert(v.name.to_ascii_uppercase(), v.value.clone());
    }
    map
}

pub fn write_scope_variable(scope: EnvScope, name: &str, value: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("variable name cannot be empty");
    }
    let reg_type = if value.contains('%') || name.eq_ignore_ascii_case("PATH") {
        "REG_EXPAND_SZ"
    } else {
        "REG_SZ"
    };

    let output = silent_command("reg")
        .args([
            "add",
            scope.registry_key(),
            "/v",
            name,
            "/t",
            reg_type,
            "/d",
            value,
            "/f",
        ])
        .output()
        .with_context(|| format!("failed to execute reg add for {name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "reg add failed for {} ({}): {}",
            name,
            scope.label(),
            if stderr.is_empty() {
                "access denied or invalid key"
            } else {
                &stderr
            }
        );
    }

    Ok(())
}

pub fn broadcast_environment_change() {
    let script = concat!(
        "Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition '",
        "[DllImport(\"user32.dll\", SetLastError = true, CharSet = CharSet.Auto)]",
        "public static extern IntPtr SendMessageTimeout(",
        "IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, ",
        "uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'; ",
        "$r = [UIntPtr]::Zero; ",
        "[Win32.NativeMethods]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, 'Environment', 2, 2000, [ref]$r) | Out-Null"
    );
    let _ = silent_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output();
}

pub fn is_elevated() -> bool {
    silent_command("net")
        .arg("session")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn relaunch_elevated() -> Result<()> {
    let exe = std::env::current_exe().context("failed to resolve current executable path")?;
    let exe_str = exe.to_string_lossy().replace('\'', "''");
    let script = format!("Start-Process -FilePath '{exe_str}' -Verb RunAs");
    let status = silent_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .context("failed to invoke UAC elevation via PowerShell")?;

    if !status.success() {
        bail!("UAC elevation was canceled or failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reg_query_output_lines() {
        let sample = "\
HKEY_CURRENT_USER\\Environment
    Path    REG_EXPAND_SZ    C:\\Users\\Me\\.cargo\\bin;C:\\Users\\Me\\AppData\\Local\\Microsoft\\WindowsApps
    JAVA_HOME    REG_SZ    C:\\Program Files\\Eclipse Adoptium\\jdk-21
    TEMP    REG_EXPAND_SZ    %USERPROFILE%\\AppData\\Local\\Temp
";
        let vars = parse_reg_query_output(sample, EnvScope::User);
        assert_eq!(vars.len(), 3);
        assert!(vars[0].is_path_var());
        assert_eq!(vars[1].name, "JAVA_HOME");
        assert_eq!(vars[2].name, "TEMP");
    }

    #[test]
    fn rejects_empty_variable_name_on_write() {
        assert!(write_scope_variable(EnvScope::User, "   ", "value").is_err());
    }
}
