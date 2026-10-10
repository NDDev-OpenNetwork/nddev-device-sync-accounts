//! Application context initialization for native secrets and OS TLS verification.
//! The Flutter plugin invokes these before creating an identity client. No
//! credential ever crosses a Dart MethodChannel.

struct Context {
    vm: jni_legacy::JavaVM,
    application: jni_legacy::objects::GlobalRef,
}
static CONTEXT: std::sync::OnceLock<Context> = std::sync::OnceLock::new();

pub fn initialize_keyring(
    env: jni_legacy::JNIEnv<'_>,
    class: jni_legacy::objects::JObject<'_>,
    context: jni_legacy::objects::JObject<'_>,
) {
    if let (Ok(vm), Ok(application)) = (env.get_java_vm(), env.new_global_ref(&context)) {
        let _ = CONTEXT.set(Context { vm, application });
    }
    android_native_keyring_store::Java_io_crates_keyring_Keyring_00024Companion_initializeNdkContext(env, class, context);
}

/// App-private metadata location; no user-selected path or private key is returned
/// through the Flutter bridge. Android supplies the sandbox and app UID boundary.
pub fn private_data_directory() -> Result<std::path::PathBuf, crate::ClientError> {
    let context = CONTEXT.get().ok_or(crate::ClientError::CredentialStore)?;
    let mut env = context
        .vm
        .attach_current_thread()
        .map_err(|_| crate::ClientError::CredentialStore)?;
    let directory = env
        .call_method(
            context.application.as_obj(),
            "getFilesDir",
            "()Ljava/io/File;",
            &[],
        )
        .map_err(|_| crate::ClientError::CredentialStore)?
        .l()
        .map_err(|_| crate::ClientError::CredentialStore)?;
    let path = env
        .call_method(directory, "getAbsolutePath", "()Ljava/lang/String;", &[])
        .map_err(|_| crate::ClientError::CredentialStore)?
        .l()
        .map_err(|_| crate::ClientError::CredentialStore)?;
    let text: jni_legacy::objects::JString = path.into();
    let value: String = env
        .get_string(&text)
        .map_err(|_| crate::ClientError::CredentialStore)?
        .into();
    let path = std::path::PathBuf::from(value);
    if !path.is_absolute() {
        return Err(crate::ClientError::CredentialStore);
    }
    Ok(path.join("nds"))
}

pub fn initialize_tls<'local>(
    mut environment: jni::EnvUnowned<'local>,
    context: jni::objects::JObject<'local>,
) {
    use jni::errors::ThrowRuntimeExAndDefault;
    environment
        .with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<ThrowRuntimeExAndDefault>();
}
