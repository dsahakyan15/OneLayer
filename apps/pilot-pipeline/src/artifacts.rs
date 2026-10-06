use crate::BatchArtifact;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum ArtifactError {
    Io(std::io::Error),
    Canonical(onelayer_canonical::cbor::CborError),
}

impl From<std::io::Error> for ArtifactError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<onelayer_canonical::cbor::CborError> for ArtifactError {
    fn from(error: onelayer_canonical::cbor::CborError) -> Self {
        Self::Canonical(error)
    }
}

pub struct ArtifactCopies {
    pub primary: PathBuf,
    pub local: PathBuf,
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn write_copy(root: &Path, batch: &BatchArtifact) -> Result<PathBuf, ArtifactError> {
    let directory = root
        .join(hex::encode(batch.manifest.registry_id_hash))
        .join(batch.batch_sequence.to_string());
    fs::create_dir_all(&directory)?;
    write_new(&directory.join("leaves.cbor"), &batch.leaves_cbor)?;
    write_new(
        &directory.join("manifest.cbor"),
        &batch.manifest.unsigned_cbor()?,
    )?;
    write_new(
        &directory.join("manifest.hash"),
        &batch.signed_manifest.manifest_hash,
    )?;
    write_new(
        &directory.join("manifest.signature"),
        &batch.signed_manifest.manifest_signature,
    )?;
    write_new(
        &directory.join("operator.public-key"),
        &batch.signed_manifest.operator_public_key,
    )?;
    Ok(directory)
}

pub fn write_artifact_copies(
    batch: &BatchArtifact,
    primary_root: &Path,
    local_root: &Path,
) -> Result<ArtifactCopies, ArtifactError> {
    if primary_root == local_root {
        return Err(ArtifactError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "primary and local artifact roots must differ",
        )));
    }
    let primary = write_copy(primary_root, batch)?;
    let local = write_copy(local_root, batch)?;
    Ok(ArtifactCopies { primary, local })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn immutable_artifact_file_cannot_be_replaced() {
        let directory = std::env::temp_dir().join(format!(
            "onelayer-artifact-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("manifest.hash");
        write_new(&path, &[1; 32]).unwrap();
        assert_eq!(
            write_new(&path, &[2; 32]).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(path).unwrap(), vec![1; 32]);
        fs::remove_dir_all(directory).unwrap();
    }
}
