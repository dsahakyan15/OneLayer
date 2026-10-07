//! Безопасное чтение приватных файлов audit-сервиса (config, capability key):
//! один дескриптор `O_NOFOLLOW|O_CLOEXEC`, regular file, владелец euid, права
//! без group/other, ограниченный размер, ни одного symlink в компонентах пути.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;
pub const MAX_KEY_BYTES: u64 = 64 * 1024;

pub struct SecureReadPolicy {
    pub max_bytes: u64,
    pub what: &'static str,
}

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
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(fail(format!(
            "owner uid {} is not the service euid",
            meta.uid()
        )));
    }
    if meta.mode() & 0o077 != 0 {
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
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn refuses_public_modes_and_symlinks() {
        let dir =
            std::env::temp_dir().join(format!("onelayer-audit-secure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        f.write_all(b"x").unwrap();
        drop(f);
        let policy = SecureReadPolicy {
            max_bytes: 64,
            what: "test",
        };
        assert_eq!(read_private(&path, &policy).unwrap(), b"x");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, &policy).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(read_private(&link, &policy).is_err());
        let dirlink = dir.join("dirlink");
        symlink(&dir, &dirlink).unwrap();
        assert!(read_private(&dirlink.join("key"), &policy).is_err());
        assert!(read_private(
            &path,
            &SecureReadPolicy {
                max_bytes: 0,
                what: "test"
            }
        )
        .is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
