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
}
