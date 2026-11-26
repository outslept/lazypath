use crate::expand::expand_env_vars;
use crate::model::{validate_variable_name, EnvScope, EnvVariable, RegValueKind};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;

/// Registry value type token for strings containing `%VAR%` environment references.
const REG_EXPAND_SZ_TOKEN: &str = "REG_EXPAND_SZ";
/// Registry value type token for literal strings.
const REG_SZ_TOKEN: &str = "REG_SZ";

/// Parses the tabular stdout of `reg query <KEY>` into sorted [`EnvVariable`] records.
///
/// The `PATH` variable (if present) is sorted first, followed by remaining variables
/// in case-insensitive alphabetical order.
#[must_use]
pub fn parse_reg_query_output(raw: &str, scope: EnvScope) -> Vec<EnvVariable> {
    let mut vars = Vec::new();
    for line in raw.lines() {
        let trimmed_end = line.trim_end_matches(['\r', '\n']);
        let trimmed_start = trimmed_end.trim_start();
        if trimmed_start.is_empty() || trimmed_start.starts_with("HKEY_") {
            continue;
        }

        let Some((marker_idx, marker_len, kind)) = find_earliest_reg_type_marker(trimmed_start)
        else {
            continue;
        };

        let name = trimmed_start[..marker_idx].trim().to_string();
        if name.is_empty() {
            continue;
        }

        let after_marker = &trimmed_start[marker_idx + marker_len..];
        let value = after_marker
            .strip_prefix("    ")
            .unwrap_or_else(|| after_marker.trim_start())
            .to_string();

        vars.push(EnvVariable::with_kind(name, value, scope, kind));
    }
    vars.sort_by_key(|v| (!v.is_path_var(), v.name.to_lowercase()));
    vars
}

/// Locates the earliest whitespace-delimited `REG_EXPAND_SZ` or `REG_SZ` column marker in `line`
/// so that literal occurrences of `"REG_EXPAND_SZ"` inside a `REG_SZ` value do not misclassify the line.
fn find_earliest_reg_type_marker(line: &str) -> Option<(usize, usize, RegValueKind)> {
    let candidates = [
        (REG_EXPAND_SZ_TOKEN, RegValueKind::ExpandSz),
        (REG_SZ_TOKEN, RegValueKind::Sz),
    ];

    let mut best: Option<(usize, usize, RegValueKind)> = None;
    for (token, kind) in candidates {
        let mut search_from = 0;
        while let Some(rel_idx) = line[search_from..].find(token) {
            let idx = search_from + rel_idx;
            let before_ok = idx > 0 && line.as_bytes()[idx - 1].is_ascii_whitespace();
            let after_idx = idx + token.len();
            let after_ok =
                after_idx == line.len() || line.as_bytes()[after_idx].is_ascii_whitespace();

            if before_ok && after_ok {
                if best.is_none_or(|(best_idx, _, _)| idx < best_idx) {
                    best = Some((idx, token.len(), kind));
                }
                break;
            }
            search_from = after_idx;
        }
    }
    best
}

/// Queries all `REG_SZ` and `REG_EXPAND_SZ` environment variables for the given [`EnvScope`]
/// directly from the Windows Registry in UTF-16.
///
/// # Errors
///
/// Returns an error if the registry key cannot be opened, enumeration fails, or the
/// current platform is not Windows.
pub fn read_scope_variables(scope: EnvScope) -> Result<Vec<EnvVariable>> {
    #[cfg(windows)]
    {
        win32::read_scope_variables_utf16(scope)
    }
    #[cfg(not(windows))]
    {
        bail!(
            "cannot read {}: Windows Registry is only available on Windows",
            scope.registry_key()
        )
    }
}

/// Loads both User and System environment variables from the Windows Registry.
///
/// # Errors
///
/// Returns an error if either [`EnvScope::User`] or [`EnvScope::System`] cannot be read,
/// preventing silent empty audits in CI or the TUI.
pub fn load_all_variables() -> Result<(Vec<EnvVariable>, Vec<EnvVariable>)> {
    let user_vars = read_scope_variables(EnvScope::User)
        .with_context(|| format!("failed to load {} variables", EnvScope::User.label()))?;
    let sys_vars = read_scope_variables(EnvScope::System)
        .with_context(|| format!("failed to load {} variables", EnvScope::System.label()))?;
    Ok((user_vars, sys_vars))
}

/// Builds an uppercase lookup table merging current process variables, System variables,
/// and User variables in Windows environment initialization order.
///
/// System variables are expanded against the process/system environment first, and User
/// variables are then expanded against the combined System + User environment. Uses
/// [`std::env::vars_os`] so non-UTF-8 process variables never cause a panic.
#[must_use]
pub fn build_lookup_map(
    user_vars: &[EnvVariable],
    sys_vars: &[EnvVariable],
) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in std::env::vars_os() {
        let key = k.to_string_lossy().to_uppercase();
        let val = v.to_string_lossy().into_owned();
        map.insert(key, val);
    }

    // Phase 1: Insert raw System variables, then resolve expandable System variables.
    for v in sys_vars {
        map.insert(v.name.to_uppercase(), v.value.clone());
    }
    for v in sys_vars {
        if v.effective_kind() == RegValueKind::ExpandSz || v.value.contains('%') {
            let expanded = expand_env_vars(&v.value, &map);
            map.insert(v.name.to_uppercase(), expanded);
        }
    }

    // Phase 2: Insert User variables (except PATH, which Windows appends rather than overwrites,
    // though for non-PATH lookup User overrides System) and resolve expandable User variables.
    for v in user_vars {
        map.insert(v.name.to_uppercase(), v.value.clone());
    }
    for v in user_vars {
        if v.effective_kind() == RegValueKind::ExpandSz || v.value.contains('%') {
            let expanded = expand_env_vars(&v.value, &map);
            map.insert(v.name.to_uppercase(), expanded);
        }
    }

    map
}

/// Writes an environment variable to the Windows Registry for the given [`EnvScope`],
/// inferring `REG_EXPAND_SZ` vs `REG_SZ` from the variable name and value.
///
/// # Errors
///
/// Returns an error if `name` is invalid or the registry write fails (e.g., `ERROR_ACCESS_DENIED`).
pub fn write_scope_variable(scope: EnvScope, name: &str, value: &str) -> Result<()> {
    let kind = RegValueKind::infer(name, value);
    write_scope_variable_with_kind(scope, name, value, kind)
}

/// Writes an environment variable to the Windows Registry with an explicit [`RegValueKind`].
///
/// Preserves literal `REG_SZ` values containing `%` during snapshot imports while ensuring
/// `PATH` is always written as `REG_EXPAND_SZ`.
///
/// # Errors
///
/// Returns an error if `name` is invalid or the registry write fails.
pub fn write_scope_variable_with_kind(
    scope: EnvScope,
    name: &str,
    value: &str,
    kind: RegValueKind,
) -> Result<()> {
    if let Err(msg) = validate_variable_name(name) {
        bail!("{msg}");
    }
    let effective_kind = if name.eq_ignore_ascii_case("PATH") {
        RegValueKind::ExpandSz
    } else {
        kind
    };

    #[cfg(windows)]
    {
        win32::write_scope_variable_utf16(scope, name, value, effective_kind)
    }
    #[cfg(not(windows))]
    {
        let _ = (scope, value, effective_kind);
        bail!("cannot write registry variable '{name}': only supported on Windows")
    }
}

/// Deletes an environment variable from the Windows Registry for the given [`EnvScope`].
///
/// Succeeds if the value is deleted or if it was already absent.
///
/// # Errors
///
/// Returns an error if `name` is invalid or the registry deletion fails.
pub fn delete_scope_variable(scope: EnvScope, name: &str) -> Result<()> {
    if let Err(msg) = validate_variable_name(name) {
        bail!("{msg}");
    }
    #[cfg(windows)]
    {
        win32::delete_scope_variable_utf16(scope, name)
    }
    #[cfg(not(windows))]
    {
        let _ = scope;
        bail!("cannot delete registry variable '{name}': only supported on Windows")
    }
}

/// Broadcasts `WM_SETTINGCHANGE` (`0x001A`) with `lParam = L"Environment"` to `HWND_BROADCAST`
/// (`0xffff`) using `SMTO_ABORTIFHUNG` (`0x0002`) and a 2000ms timeout so running shells
/// and Explorer pick up registry updates without logging out.
///
/// # Errors
///
/// Returns an error if `SendMessageTimeoutW` fails or times out.
pub fn broadcast_environment_change() -> Result<()> {
    #[cfg(windows)]
    {
        win32::broadcast_setting_change_utf16()
    }
    #[cfg(not(windows))]
    {
        bail!("WM_SETTINGCHANGE broadcast is only supported on Windows")
    }
}

/// Returns `true` if the current process token is running with Administrator elevation.
#[must_use]
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        win32::is_process_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Relaunches the current executable in an elevated Administrator window via UAC (`runas`).
///
/// # Errors
///
/// Returns an error if the current executable path cannot be resolved or the user declines
/// the UAC prompt.
pub fn relaunch_elevated() -> Result<()> {
    relaunch_elevated_with_args(&[])
}

/// Relaunches the current executable with UAC elevation (`runas`), forwarding `extra_args`
/// (such as `--resume-pending <FILE>`) so unsaved edits are preserved across elevation.
///
/// # Errors
///
/// Returns an error if the current executable path cannot be resolved or `ShellExecuteW` fails.
pub fn relaunch_elevated_with_args(extra_args: &[String]) -> Result<()> {
    #[cfg(windows)]
    {
        win32::shell_execute_runas(extra_args)
    }
    #[cfg(not(windows))]
    {
        let _ = extra_args;
        bail!("UAC elevation is only supported on Windows")
    }
}

#[cfg(windows)]
mod win32 {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;
    use std::ptr;

    use anyhow::{bail, Context, Result};

    use crate::model::{EnvScope, EnvVariable, RegValueKind};

    type Hkey = isize;
    type Handle = isize;
    type Hwnd = isize;
    type Bool = i32;

    const HKEY_CURRENT_USER: Hkey = 0x8000_0001_u32 as i32 as isize;
    const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002_u32 as i32 as isize;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_MORE_DATA: u32 = 234;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: u32 = 20;
    const HWND_BROADCAST: Hwnd = 0xffff;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;
    const SW_SHOWNORMAL: i32 = 1;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            hKey: Hkey,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut Hkey,
        ) -> u32;
        fn RegCloseKey(hKey: Hkey) -> u32;
        fn RegQueryInfoKeyW(
            hKey: Hkey,
            lpClass: *mut u16,
            lpcchClass: *mut u32,
            lpReserved: *const u32,
            lpcSubKeys: *mut u32,
            lpcbMaxSubKeyLen: *mut u32,
            lpcbMaxClassLen: *mut u32,
            lpcValues: *mut u32,
            lpcbMaxValueNameLen: *mut u32,
            lpcbMaxValueLen: *mut u32,
            lpcbSecurityDescriptor: *mut u32,
            lpftLastWriteTime: *mut u64,
        ) -> u32;
        fn RegEnumValueW(
            hKey: Hkey,
            dwIndex: u32,
            lpValueName: *mut u16,
            lpcchValueName: *mut u32,
            lpReserved: *const u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> u32;
        fn RegSetValueExW(
            hKey: Hkey,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> u32;
        fn RegDeleteValueW(hKey: Hkey, lpValueName: *const u16) -> u32;
        fn OpenProcessToken(
            ProcessHandle: Handle,
            DesiredAccess: u32,
            TokenHandle: *mut Handle,
        ) -> Bool;
        fn GetTokenInformation(
            TokenHandle: Handle,
            TokenInformationClass: u32,
            TokenInformation: *mut core::ffi::c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> Bool;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(hObject: Handle) -> Bool;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn SendMessageTimeoutW(
            hWnd: Hwnd,
            Msg: u32,
            wParam: usize,
            lParam: *const u16,
            fuFlags: u32,
            uTimeout: u32,
            lpdwResult: *mut usize,
        ) -> isize;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            hwnd: Hwnd,
            lpOperation: *const u16,
            lpFile: *const u16,
            lpParameters: *const u16,
            lpDirectory: *const u16,
            nShowCmd: i32,
        ) -> isize;
    }

    struct RegKeyGuard(Hkey);

    impl Drop for RegKeyGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is an open registry key handle obtained from `RegOpenKeyExW`.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn to_wide_null(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn path_to_wide_null(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    const fn hive_for_scope(scope: EnvScope) -> Hkey {
        match scope {
            EnvScope::User => HKEY_CURRENT_USER,
            EnvScope::System => HKEY_LOCAL_MACHINE,
        }
    }

    fn open_env_key(scope: EnvScope, access: u32) -> Result<RegKeyGuard> {
        let subkey = to_wide_null(scope.registry_subkey());
        let mut hkey: Hkey = 0;
        // SAFETY: `subkey` is a valid NUL-terminated UTF-16 buffer and `hkey` is a valid out-pointer.
        let status = unsafe {
            RegOpenKeyExW(
                hive_for_scope(scope),
                subkey.as_ptr(),
                0,
                access | KEY_WOW64_64KEY,
                &raw mut hkey,
            )
        };
        if status != ERROR_SUCCESS {
            let err = io::Error::from_raw_os_error(status.cast_signed());
            bail!(
                "failed to open {}: {err} (os error {status})",
                scope.registry_key()
            );
        }
        Ok(RegKeyGuard(hkey))
    }

    pub(super) fn read_scope_variables_utf16(scope: EnvScope) -> Result<Vec<EnvVariable>> {
        let key = open_env_key(scope, KEY_QUERY_VALUE)?;

        let mut value_count: u32 = 0;
        let mut max_name_chars: u32 = 0;
        let mut max_value_bytes: u32 = 0;

        // SAFETY: `key.0` is a valid open registry key handle.
        let info_status = unsafe {
            RegQueryInfoKeyW(
                key.0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut value_count,
                &raw mut max_name_chars,
                &raw mut max_value_bytes,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if info_status != ERROR_SUCCESS {
            let err = io::Error::from_raw_os_error(info_status.cast_signed());
            bail!(
                "failed to query metadata for {}: {err} (os error {info_status})",
                scope.registry_key()
            );
        }

        let mut name_buf = vec![0_u16; (max_name_chars as usize).saturating_add(2).max(256)];
        let mut data_u16_buf =
            vec![0_u16; ((max_value_bytes as usize) / 2).saturating_add(4).max(512)];
        let mut vars = Vec::with_capacity(value_count as usize);

        let mut index: u32 = 0;
        loop {
            let mut name_len = u32::try_from(name_buf.len()).unwrap_or(u32::MAX);
            let mut data_bytes = u32::try_from(data_u16_buf.len() * 2).unwrap_or(u32::MAX);
            let mut value_type: u32 = 0;

            // SAFETY: Buffers are sized according to `name_len` (in UTF-16 code units)
            // and `data_bytes` (in bytes).
            let status = unsafe {
                RegEnumValueW(
                    key.0,
                    index,
                    name_buf.as_mut_ptr(),
                    &raw mut name_len,
                    ptr::null(),
                    &raw mut value_type,
                    data_u16_buf.as_mut_ptr().cast::<u8>(),
                    &raw mut data_bytes,
                )
            };

            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == ERROR_MORE_DATA {
                name_buf.resize(name_buf.len().saturating_mul(2), 0);
                data_u16_buf.resize(data_u16_buf.len().saturating_mul(2), 0);
                continue;
            }
            if status != ERROR_SUCCESS {
                let err = io::Error::from_raw_os_error(status.cast_signed());
                bail!(
                    "failed to enumerate {} at index {index}: {err} (os error {status})",
                    scope.registry_key()
                );
            }

            index += 1;

            let kind = match value_type {
                REG_SZ => RegValueKind::Sz,
                REG_EXPAND_SZ => RegValueKind::ExpandSz,
                _ => continue,
            };

            let name = OsString::from_wide(&name_buf[..name_len as usize])
                .to_string_lossy()
                .into_owned();
            if name.is_empty() {
                continue;
            }

            let u16_count = (data_bytes as usize) / 2;
            let mut value_slice = &data_u16_buf[..u16_count.min(data_u16_buf.len())];
            while value_slice.last() == Some(&0) {
                value_slice = &value_slice[..value_slice.len() - 1];
            }
            let value = OsString::from_wide(value_slice)
                .to_string_lossy()
                .into_owned();

            vars.push(EnvVariable::with_kind(name, value, scope, kind));
        }

        vars.sort_by_key(|v| (!v.is_path_var(), v.name.to_lowercase()));
        Ok(vars)
    }

    pub(super) fn write_scope_variable_utf16(
        scope: EnvScope,
        name: &str,
        value: &str,
        kind: RegValueKind,
    ) -> Result<()> {
        let key = open_env_key(scope, KEY_SET_VALUE)?;
        let wide_name = to_wide_null(name);
        let wide_value = to_wide_null(value);
        let dw_type = match kind {
            RegValueKind::Sz => REG_SZ,
            RegValueKind::ExpandSz => REG_EXPAND_SZ,
        };
        let cb_data = u32::try_from(wide_value.len() * 2)
            .context("environment variable value exceeds maximum registry byte size")?;

        // SAFETY: `key.0` is an open registry key with `KEY_SET_VALUE`, `wide_name` and
        // `wide_value` are NUL-terminated UTF-16 buffers, and `cb_data` is the exact byte length.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                wide_name.as_ptr(),
                0,
                dw_type,
                wide_value.as_ptr().cast::<u8>(),
                cb_data,
            )
        };
        if status != ERROR_SUCCESS {
            let err = io::Error::from_raw_os_error(status.cast_signed());
            bail!(
                "failed to write '{}' to {}: {err} (os error {status})",
                name,
                scope.registry_key()
            );
        }
        Ok(())
    }

    pub(super) fn delete_scope_variable_utf16(scope: EnvScope, name: &str) -> Result<()> {
        let key = open_env_key(scope, KEY_SET_VALUE)?;
        let wide_name = to_wide_null(name);
        // SAFETY: `key.0` is an open registry key with `KEY_SET_VALUE`, and `wide_name` is NUL-terminated.
        let status = unsafe { RegDeleteValueW(key.0, wide_name.as_ptr()) };
        if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
            let err = io::Error::from_raw_os_error(status.cast_signed());
            bail!(
                "failed to delete '{}' from {}: {err} (os error {status})",
                name,
                scope.registry_key()
            );
        }
        Ok(())
    }

    pub(super) fn broadcast_setting_change_utf16() -> Result<()> {
        let env_param = to_wide_null("Environment");
        let mut result: usize = 0;
        // SAFETY: `env_param` is a valid NUL-terminated UTF-16 string and `result` is a valid out-pointer.
        let ok = unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_param.as_ptr(),
                SMTO_ABORTIFHUNG,
                2000,
                &raw mut result,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            bail!("WM_SETTINGCHANGE broadcast timed out or failed: {err}");
        }
        Ok(())
    }

    pub(super) fn is_process_elevated() -> bool {
        let mut token: Handle = 0;
        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle valid for the lifetime of the process.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
        if opened == 0 || token == 0 {
            return false;
        }

        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut return_len: u32 = 0;
        // SAFETY: `token` is a valid handle opened with `TOKEN_QUERY`, and `elevation` matches `TokenElevation`.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TOKEN_ELEVATION_CLASS,
                (&raw mut elevation).cast::<core::ffi::c_void>(),
                u32::try_from(std::mem::size_of::<TokenElevation>()).unwrap_or(4),
                &raw mut return_len,
            )
        };
        // SAFETY: Closing the token handle opened by `OpenProcessToken`.
        unsafe {
            let _ = CloseHandle(token);
        }
        ok != 0 && elevation.token_is_elevated != 0
    }

    pub(super) fn shell_execute_runas(extra_args: &[String]) -> Result<()> {
        let exe = std::env::current_exe().context("failed to resolve current executable path")?;
        let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());

        let verb = to_wide_null("runas");
        let file = path_to_wide_null(&exe);
        let dir = path_to_wide_null(&cwd);

        let params_str = extra_args
            .iter()
            .map(|arg| quote_windows_arg(arg))
            .collect::<Vec<_>>()
            .join(" ");
        let params = to_wide_null(&params_str);
        let params_ptr = if extra_args.is_empty() {
            ptr::null()
        } else {
            params.as_ptr()
        };

        // SAFETY: All pointers are either null or valid NUL-terminated UTF-16 buffers.
        let instance = unsafe {
            ShellExecuteW(
                0,
                verb.as_ptr(),
                file.as_ptr(),
                params_ptr,
                dir.as_ptr(),
                SW_SHOWNORMAL,
            )
        };
        // Per Win32 documentation, `ShellExecuteW` returns a value > 32 on success.
        if instance <= 32 {
            let err = io::Error::last_os_error();
            bail!("UAC elevation was canceled or failed (code {instance}: {err})");
        }
        Ok(())
    }

    fn quote_windows_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            return arg.to_string();
        }
        let escaped = arg.replace('"', r#"\""#);
        format!("\"{escaped}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reg_query_output_lines_and_records_value_kind() {
        let sample = "\
HKEY_CURRENT_USER\\Environment
    Path    REG_EXPAND_SZ    C:\\Users\\Аня\\.cargo\\bin;C:\\Users\\Аня\\AppData\\Local\\Microsoft\\WindowsApps
    JAVA_HOME    REG_SZ    C:\\Program Files\\Eclipse Adoptium\\jdk-21
    TEMP    REG_EXPAND_SZ    %USERPROFILE%\\AppData\\Local\\Temp
";
        let vars = parse_reg_query_output(sample, EnvScope::User);
        assert_eq!(vars.len(), 3);
        assert!(vars[0].is_path_var());
        assert_eq!(vars[0].kind, RegValueKind::ExpandSz);
        assert_eq!(vars[1].name, "JAVA_HOME");
        assert_eq!(vars[1].kind, RegValueKind::Sz);
        assert_eq!(vars[2].name, "TEMP");
        assert_eq!(vars[2].kind, RegValueKind::ExpandSz);
    }

    #[test]
    fn parser_does_not_misclassify_reg_sz_containing_reg_expand_sz_in_value() {
        let sample = "\
HKEY_CURRENT_USER\\Environment
    FOO    REG_SZ    C:\\literal\\REG_EXPAND_SZ\\bar
";
        let vars = parse_reg_query_output(sample, EnvScope::User);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, "FOO");
        assert_eq!(vars[0].kind, RegValueKind::Sz);
        assert_eq!(vars[0].value, r"C:\literal\REG_EXPAND_SZ\bar");
    }

    #[test]
    fn builds_phased_lookup_map_resolving_chained_variables() {
        let sys = vec![EnvVariable::with_kind(
            "BASE_DIR",
            r"C:\Tools",
            EnvScope::System,
            RegValueKind::Sz,
        )];
        let user = vec![EnvVariable::with_kind(
            "USER_TOOLS",
            r"%BASE_DIR%\bin",
            EnvScope::User,
            RegValueKind::ExpandSz,
        )];
        let map = build_lookup_map(&user, &sys);
        assert_eq!(map.get("BASE_DIR").map(String::as_str), Some(r"C:\Tools"));
        assert_eq!(
            map.get("USER_TOOLS").map(String::as_str),
            Some(r"C:\Tools\bin")
        );
    }

    #[test]
    fn rejects_invalid_variable_names_on_write_and_delete() {
        assert!(write_scope_variable(EnvScope::User, "   ", "value").is_err());
        assert!(write_scope_variable(EnvScope::User, "BAD=NAME", "value").is_err());
        assert!(write_scope_variable(EnvScope::User, "BAD\0NAME", "value").is_err());
        assert!(delete_scope_variable(EnvScope::User, "").is_err());
    }
}
