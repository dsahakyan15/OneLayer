//! Запись golden vectors в `spec/vectors/`.
//!
//! `cargo run -p onelayer-canonical --bin gen-vectors -- [каталог]`
//!
//! Файлы в репозитории заморожены после Gate B: расхождение между
//! сгенерированным содержимым и содержимым на диске ловится тестом
//! `vectors_on_disk_match_implementation` и означает либо ошибку в
//! реализации, либо изменение протокола, требующее ADR.

use onelayer_canonical::vectors;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "spec/vectors".to_string())
        .into();
    std::fs::create_dir_all(&dir)?;

    for (name, value) in vectors::all() {
        let path = dir.join(name);
        std::fs::write(&path, vectors::render(&value))?;
        println!("написан {}", path.display());
    }
    Ok(())
}
