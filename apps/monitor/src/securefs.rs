//! Безопасное чтение приватных файлов (конфигурация Monitor, ключи пересчёта).
//!
//! Все приватные файлы читаются через один дескриптор с `O_NOFOLLOW` (не идём
//! по symlink последнего компонента), проверкой regular file, владельца (euid)
//! и прав (никаких group/other битов), с ограничением размера. Ошибка —
//! явный отказ, а не частичное доверие.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;
pub const MAX_KEY_BYTES: u64 = 64 * 1024;

pub struct SecureReadPolicy {
    pub max_bytes: u64,
    /// Требовать `st_uid == geteuid()`.
    pub require_owner: bool,
    /// Требовать отсутствие group/other битов (`mode & 0o077 == 0`).
    pub require_private_mode: bool,
    pub what: &'static str,
}

/// Отвергает symlink в любом компоненте пути (TOCTOU-окно между проверкой и
/// open закрыто `O_NOFOLLOW` только для последнего компонента; промежуточные
/// проверяются `symlink_metadata` до открытия).
fn reject_symlink_components(path: &Path) -> Result<(), String> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!("symlink component {}", current.display()));
            }
            Ok(_) => {}
            Err(e) => return Err(format!("stat {}: {e}", current.display())),
        }
    }
    Ok(())
}

pub fn read_private(path: &Path, policy: &SecureReadPolicy) -> Result<Vec<u8>, String> {
    let fail = |why: String| format!("{} {}: {why}", policy.what, path.display());
    reject_symlink_components(path).map_err(fail)?;
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| fail(format!("open: {e}")))?;
    let meta = file.metadata().map_err(|e| fail(format!("fstat: {e}")))?;
    if !meta.is_file() {
        return Err(fail("not a regular file".into()));
    }
    if policy.require_owner && meta.uid() != unsafe { libc::geteuid() } {
        return Err(fail(format!(
            "owner uid {} is not the monitor euid",
            meta.uid()
        )));
    }
    if policy.require_private_mode && meta.mode() & 0o077 != 0 {
        return Err(fail("group/other accessible (require chmod 600)".into()));
    }
    if meta.len() > policy.max_bytes {
        return Err(fail(format!(
            "size {} exceeds limit {}",
            meta.len(),
            policy.max_bytes
        )));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize + 1);
    file.take(policy.max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|e| fail(format!("read: {e}")))?;
    if buf.len() as u64 > policy.max_bytes {
        return Err(fail(format!("size exceeds limit {}", policy.max_bytes)));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    fn policy(max: u64) -> SecureReadPolicy {
        SecureReadPolicy {
            max_bytes: max,
            require_owner: true,
            require_private_mode: true,
            what: "test file",
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("onelayer-securefs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reads_private_file_and_rejects_modes_symlinks_and_limits() {
        let dir = tmp("read");
        let path = dir.join("keys.json");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        f.write_all(b"{}").unwrap();
        drop(f);
        assert_eq!(read_private(&path, &policy(64)).unwrap(), b"{}");

        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();
        assert!(read_private(&path, &policy(64))
            .unwrap_err()
            .contains("group/other"));

        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        assert!(read_private(&path, &policy(1))
            .unwrap_err()
            .contains("exceeds limit"));

        let link = dir.join("link.json");
        symlink(&path, &link).unwrap();
        assert!(read_private(&link, &policy(64)).is_err());

        let dir_link = dir.join("dir");
        symlink(&dir, &dir_link).unwrap();
        assert!(read_private(&dir_link.join("keys.json"), &policy(64)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
