//! One native product metadata root, shared by accounts, replica and CLI hosts.
//! Native credential material remains in the platform credential adapter.
use crate::ClientError;
use std::path::PathBuf;

pub fn private_data_directory() -> Result<PathBuf, ClientError> {
    #[cfg(target_os = "android")]
    {
        crate::android::private_data_directory()
    }
    #[cfg(not(target_os = "android"))]
    {
        #[cfg(target_os = "windows")]
        let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        let root = std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support"));
        #[cfg(target_os = "linux")]
        let root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
            });
        let root = root
            .filter(|path| path.is_absolute())
            .ok_or(ClientError::CredentialStore)?;
        Ok(root.join("nddev-device-sync"))
    }
}
