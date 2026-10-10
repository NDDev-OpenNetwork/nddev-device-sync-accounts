//! Application context initialization for native secrets and OS TLS verification.
//! The Flutter plugin invokes these before creating an identity client. No
//! credential ever crosses a Dart MethodChannel.

pub fn initialize_keyring(
    env: jni_legacy::JNIEnv<'_>,
    class: jni_legacy::objects::JObject<'_>,
    context: jni_legacy::objects::JObject<'_>,
) {
    android_native_keyring_store::Java_io_crates_keyring_Keyring_00024Companion_initializeNdkContext(env, class, context);
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
