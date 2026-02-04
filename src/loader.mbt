///|
/// Runtime loader for OpenSSL using dlopen/dlsym.

///|
suberror OpenSslError {
  LoadFailed(String)
  SymbolMissing(@dl.DynamicLibraryError)
} derive(Show)

///|
priv struct OpenSsl {
  dl_ssl : @dl.DynamicLibrary
  dl_crypto : @dl.DynamicLibrary
  init_ssl : FuncRef[(UInt64, @c.Pointer[Unit]) -> Int]
  tls_client_method : FuncRef[() -> SslMethod]
  tls_server_method : FuncRef[() -> SslMethod]
  ssl_ctx_new : FuncRef[(SslMethod) -> SslCtx]
  ssl_ctx_set_cert_store : FuncRef[(SslCtx, X509Store) -> Unit]
  ssl_ctx_set_verify : FuncRef[(SslCtx, Int) -> Unit]
  ssl_ctx_ctrl : FuncRef[(SslCtx, Int, Int64, @c.Pointer[Unit]) -> Int64]
  ssl_ctrl : FuncRef[(Ssl, Int, Int64, @c.Pointer[Unit]) -> Int64]
  ssl_ctx_set_options : FuncRef[(SslCtx, UInt64) -> UInt64]
  ssl_ctx_clear_options : FuncRef[(SslCtx, UInt64) -> UInt64]
  ssl_ctx_get_options : FuncRef[(SslCtx) -> UInt64]
  ssl_set_options : FuncRef[(Ssl, UInt64) -> UInt64]
  ssl_clear_options : FuncRef[(Ssl, UInt64) -> UInt64]
  ssl_get_options : FuncRef[(Ssl) -> UInt64]
  ssl_ctx_set_default_verify_paths : FuncRef[(SslCtx) -> Int]
  ssl_ctx_set_cipher_list : FuncRef[(SslCtx, @c.Pointer[Byte]) -> Int]
  ssl_set_cipher_list : FuncRef[(Ssl, @c.Pointer[Byte]) -> Int]
  ssl_ctx_set_ciphersuites : FuncRef[(SslCtx, @c.Pointer[Byte]) -> Int]
  ssl_set_ciphersuites : FuncRef[(Ssl, @c.Pointer[Byte]) -> Int]
  ssl_ctx_use_certificate : FuncRef[(SslCtx, X509) -> Int]
  ssl_ctx_use_private_key : FuncRef[(SslCtx, EvpPkey) -> Int]
  ssl_ctx_free : FuncRef[(SslCtx) -> Unit]
  ssl_new : FuncRef[(SslCtx) -> Ssl]
  ssl_set_fd : FuncRef[(Ssl, Int) -> Int]
  ssl_set1_host : FuncRef[(Ssl, @c.Pointer[Byte]) -> Int]
  ssl_set_accept_state : FuncRef[(Ssl) -> Unit]
  ssl_do_handshake : FuncRef[(Ssl) -> Int]
  ssl_connect : FuncRef[(Ssl) -> Int]
  ssl_accept : FuncRef[(Ssl) -> Int]
  ssl_shutdown : FuncRef[(Ssl) -> Int]
  ssl_free : FuncRef[(Ssl) -> Unit]
  ssl_read : FuncRef[(Ssl, @c.Pointer[Byte], Int) -> Int]
  ssl_write : FuncRef[(Ssl, @c.Pointer[Byte], Int) -> Int]
  ssl_get_error : FuncRef[(Ssl, Int) -> SslError]
  ssl_get_version : FuncRef[(Ssl) -> @c.Pointer[Byte]]
  ssl_version : FuncRef[(Ssl) -> Int]
  ssl_client_version : FuncRef[(Ssl) -> Int]
  ssl_get0_peer_certificate : FuncRef[(Ssl) -> @c.Pointer[Unit]]
  ssl_get1_peer_certificate : FuncRef[(Ssl) -> @c.Pointer[Unit]]
  ssl_get_verify_result : FuncRef[(Ssl) -> Int64]
  ssl_set_bio : FuncRef[(Ssl, Bio, Bio) -> Unit]
  ssl_ctx_use_private_key_file : FuncRef[(SslCtx, @c.Pointer[Byte], Int) -> Int]
  ssl_ctx_use_certificate_file : FuncRef[(SslCtx, @c.Pointer[Byte], Int) -> Int]
  x509_store_new : FuncRef[() -> X509Store]
  x509_store_free : FuncRef[(X509Store) -> Unit]
  x509_store_add_cert : FuncRef[(X509Store, X509) -> Int]
  x509_free : FuncRef[(X509) -> Unit]
  x509_get_subject_name : FuncRef[(X509) -> X509Name]
  x509_get_issuer_name : FuncRef[(X509) -> X509Name]
  pem_read_bio_x509 : FuncRef[(Bio) -> X509]
  bio_new_mem_buf : FuncRef[(@c.Pointer[Byte], Int) -> Bio]
  bio_free : FuncRef[(Bio) -> Int]
  pem_read_bio_private_key : FuncRef[(Bio) -> EvpPkey]
  evp_pkey_free : FuncRef[(EvpPkey) -> Unit]
  bio_s_mem : FuncRef[() -> BioMethod]
  bio_new : FuncRef[(BioMethod) -> Bio]
  bio_read : FuncRef[(Bio, @c.Pointer[Byte], Int) -> Int]
  bio_read_ex : FuncRef[
    (Bio, @c.Pointer[Byte], UInt64, @c.Pointer[UInt64]) -> Int,
  ]
  bio_write : FuncRef[(Bio, @c.Pointer[Byte], Int) -> Int]
  bio_write_ex : FuncRef[
    (Bio, @c.Pointer[Byte], UInt64, @c.Pointer[UInt64]) -> Int,
  ]
  bio_ctrl : FuncRef[(Bio, Int, Int64, @c.Pointer[Unit]) -> Int64]
  bio_ctrl_pending : FuncRef[(Bio) -> UInt64]
  bio_ctrl_wpending : FuncRef[(Bio) -> UInt64]
  err_get_error : FuncRef[() -> UInt64]
  err_peek_error : FuncRef[() -> UInt64]
  err_error_string_n : FuncRef[(UInt64, @c.Pointer[Byte], Int) -> Unit]
}

///|
let openssl : Result[OpenSsl, OpenSslError] = try? load()

///|
fn ensure_openssl() -> OpenSsl raise OpenSslError {
  openssl.unwrap_or_error()
}

///|
fn load_library(paths : Array[String]) -> @dl.DynamicLibrary? {
  for path in paths {
    match @dl.DynamicLibrary::try_open(path) {
      Some(dl) => return Some(dl)
      None => ()
    }
  } else {
    None
  }
}

///|
fn moon_home() -> String raise {
  if @os.getenv("MOON_HOME") is Some(home) {
    return home
  }
  @path.Path(@os.home()).join(".moon").to_string()
}

///|
fn build_paths(names : Array[String]) -> Array[String] raise {
  let paths = []
  if @os.getenv("OPENSSL_LIB_DIR") is Some(dir) {
    for name in names {
      paths.push(@path.Path(dir).join(name).to_string())
    }
  }
  match @env.current_dir() {
    None => ()
    Some(dir) =>
      for name in names {
        paths.push(@path.Path(dir).join(name).to_string())
      }
  }
  let home = moon_home()
  for name in names {
    paths.push(@path.Path(home).join("lib").join(name).to_string())
  }
  paths
}

///|
fn lib_names_ssl() -> Array[String] raise OpenSslError {
  if @platform.macos {
    ["libssl.dylib", "libssl.3.dylib"]
  } else if @platform.linux {
    ["libssl.so", "libssl.so.3"]
  } else {
    raise LoadFailed("Unsupported platform for OpenSSL loader")
  }
}

///|
fn lib_names_crypto() -> Array[String] raise OpenSslError {
  if @platform.macos {
    ["libcrypto.dylib", "libcrypto.3.dylib"]
  } else if @platform.linux {
    ["libcrypto.so", "libcrypto.so.3"]
  } else {
    raise LoadFailed("Unsupported platform for OpenSSL loader")
  }
}

///|
fn init {
  @os.atexit(() => match openssl {
    Ok(openssl) => {
      ignore(try? openssl.dl_ssl.close())
      ignore(try? openssl.dl_crypto.close())
    }
    _ => ()
  })
}

///|
fn load() -> OpenSsl raise OpenSslError {
  let ssl_paths = build_paths(lib_names_ssl()) catch {
    error => raise LoadFailed("Failed to build libssl paths: \{error}")
  }
  let crypto_paths = build_paths(lib_names_crypto()) catch {
    error => raise LoadFailed("Failed to build libcrypto paths: \{error}")
  }
  let dl_ssl = match load_library(ssl_paths) {
    Some(dl) => dl
    None =>
      raise LoadFailed(
        "Could not load libssl library, tried paths: \{ssl_paths}",
      )
  }
  let dl_crypto = match load_library(crypto_paths) {
    Some(dl) => dl
    None =>
      raise LoadFailed(
        "Could not load libcrypto library, tried paths: \{crypto_paths}",
      )
  }
  let init_ssl : FuncRef[(UInt64, @c.Pointer[Unit]) -> Int] = dl_ssl.funcref(
    "OPENSSL_init_ssl",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let tls_client_method : FuncRef[() -> SslMethod] = dl_ssl.funcref(
    "TLS_client_method",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let tls_server_method : FuncRef[() -> SslMethod] = dl_ssl.funcref(
    "TLS_server_method",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_new : FuncRef[(SslMethod) -> SslCtx] = dl_ssl.funcref(
    "SSL_CTX_new",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_set_cert_store : FuncRef[(SslCtx, X509Store) -> Unit] = dl_ssl.funcref(
    "SSL_CTX_set_cert_store",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_set_verify : FuncRef[(SslCtx, Int) -> Unit] = dl_ssl.funcref(
    "SSL_CTX_set_verify",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_ctrl : FuncRef[(SslCtx, Int, Int64, @c.Pointer[Unit]) -> Int64] = dl_ssl.funcref(
    "SSL_CTX_ctrl",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctrl : FuncRef[(Ssl, Int, Int64, @c.Pointer[Unit]) -> Int64] = dl_ssl.funcref(
    "SSL_ctrl",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_set_options : FuncRef[(SslCtx, UInt64) -> UInt64] = dl_ssl.funcref(
    "SSL_CTX_set_options",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_clear_options : FuncRef[(SslCtx, UInt64) -> UInt64] = dl_ssl.funcref(
    "SSL_CTX_clear_options",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_get_options : FuncRef[(SslCtx) -> UInt64] = dl_ssl.funcref(
    "SSL_CTX_get_options",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_set_options : FuncRef[(Ssl, UInt64) -> UInt64] = dl_ssl.funcref(
    "SSL_set_options",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_clear_options : FuncRef[(Ssl, UInt64) -> UInt64] = dl_ssl.funcref(
    "SSL_clear_options",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_get_options : FuncRef[(Ssl) -> UInt64] = dl_ssl.funcref(
    "SSL_get_options",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_set_default_verify_paths : FuncRef[(SslCtx) -> Int] = dl_ssl.funcref(
    "SSL_CTX_set_default_verify_paths",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_set_cipher_list : FuncRef[(SslCtx, @c.Pointer[Byte]) -> Int] = dl_ssl.funcref(
    "SSL_CTX_set_cipher_list",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_set_cipher_list : FuncRef[(Ssl, @c.Pointer[Byte]) -> Int] = dl_ssl.funcref(
    "SSL_set_cipher_list",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_set_ciphersuites : FuncRef[(SslCtx, @c.Pointer[Byte]) -> Int] = dl_ssl.funcref(
    "SSL_CTX_set_ciphersuites",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_set_ciphersuites : FuncRef[(Ssl, @c.Pointer[Byte]) -> Int] = dl_ssl.funcref(
    "SSL_set_ciphersuites",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_use_certificate : FuncRef[(SslCtx, X509) -> Int] = dl_ssl.funcref(
    "SSL_CTX_use_certificate",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_use_private_key : FuncRef[(SslCtx, EvpPkey) -> Int] = dl_ssl.funcref(
    "SSL_CTX_use_PrivateKey",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_free : FuncRef[(SslCtx) -> Unit] = dl_ssl.funcref("SSL_CTX_free") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_new : FuncRef[(SslCtx) -> Ssl] = dl_ssl.funcref("SSL_new") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_set_fd : FuncRef[(Ssl, Int) -> Int] = dl_ssl.funcref("SSL_set_fd") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_set1_host : FuncRef[(Ssl, @c.Pointer[Byte]) -> Int] = dl_ssl.funcref(
    "SSL_set1_host",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_set_accept_state : FuncRef[(Ssl) -> Unit] = dl_ssl.funcref(
    "SSL_set_accept_state",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_do_handshake : FuncRef[(Ssl) -> Int] = dl_ssl.funcref(
    "SSL_do_handshake",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_connect : FuncRef[(Ssl) -> Int] = dl_ssl.funcref("SSL_connect") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_accept : FuncRef[(Ssl) -> Int] = dl_ssl.funcref("SSL_accept") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_shutdown : FuncRef[(Ssl) -> Int] = dl_ssl.funcref("SSL_shutdown") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_free : FuncRef[(Ssl) -> Unit] = dl_ssl.funcref("SSL_free") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_read : FuncRef[(Ssl, @c.Pointer[Byte], Int) -> Int] = dl_ssl.funcref(
    "SSL_read",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_write : FuncRef[(Ssl, @c.Pointer[Byte], Int) -> Int] = dl_ssl.funcref(
    "SSL_write",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_get_error : FuncRef[(Ssl, Int) -> SslError] = dl_ssl.funcref(
    "SSL_get_error",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_get_version : FuncRef[(Ssl) -> @c.Pointer[Byte]] = dl_ssl.funcref(
    "SSL_get_version",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_version : FuncRef[(Ssl) -> Int] = dl_ssl.funcref("SSL_version") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_client_version : FuncRef[(Ssl) -> Int] = dl_ssl.funcref(
    "SSL_client_version",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_get0_peer_certificate : FuncRef[(Ssl) -> @c.Pointer[Unit]] = dl_ssl.funcref(
    "SSL_get0_peer_certificate",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_get1_peer_certificate : FuncRef[(Ssl) -> @c.Pointer[Unit]] = dl_ssl.funcref(
    "SSL_get1_peer_certificate",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_get_verify_result : FuncRef[(Ssl) -> Int64] = dl_ssl.funcref(
    "SSL_get_verify_result",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_set_bio : FuncRef[(Ssl, Bio, Bio) -> Unit] = dl_ssl.funcref(
    "SSL_set_bio",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_use_private_key_file : FuncRef[
    (SslCtx, @c.Pointer[Byte], Int) -> Int,
  ] = dl_ssl.funcref("SSL_CTX_use_PrivateKey_file") catch {
    error => raise SymbolMissing(error)
  }
  let ssl_ctx_use_certificate_file : FuncRef[
    (SslCtx, @c.Pointer[Byte], Int) -> Int,
  ] = dl_ssl.funcref("SSL_CTX_use_certificate_file") catch {
    error => raise SymbolMissing(error)
  }
  let x509_store_new : FuncRef[() -> X509Store] = dl_crypto.funcref(
    "X509_STORE_new",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let x509_store_free : FuncRef[(X509Store) -> Unit] = dl_crypto.funcref(
    "X509_STORE_free",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let x509_store_add_cert : FuncRef[(X509Store, X509) -> Int] = dl_crypto.funcref(
    "X509_STORE_add_cert",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let x509_free : FuncRef[(X509) -> Unit] = dl_crypto.funcref("X509_free") catch {
    error => raise SymbolMissing(error)
  }
  let x509_get_subject_name : FuncRef[(X509) -> X509Name] = dl_crypto.funcref(
    "X509_get_subject_name",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let x509_get_issuer_name : FuncRef[(X509) -> X509Name] = dl_crypto.funcref(
    "X509_get_issuer_name",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let pem_read_bio_x509 : FuncRef[(Bio) -> X509] = dl_crypto.funcref(
    "PEM_read_bio_X509",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let bio_new_mem_buf : FuncRef[(@c.Pointer[Byte], Int) -> Bio] = dl_crypto.funcref(
    "BIO_new_mem_buf",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let bio_free : FuncRef[(Bio) -> Int] = dl_crypto.funcref("BIO_free") catch {
    error => raise SymbolMissing(error)
  }
  let pem_read_bio_private_key : FuncRef[(Bio) -> EvpPkey] = dl_crypto.funcref(
    "PEM_read_bio_PrivateKey",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let evp_pkey_free : FuncRef[(EvpPkey) -> Unit] = dl_crypto.funcref(
    "EVP_PKEY_free",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let bio_s_mem : FuncRef[() -> BioMethod] = dl_crypto.funcref("BIO_s_mem") catch {
    error => raise SymbolMissing(error)
  }
  let bio_new : FuncRef[(BioMethod) -> Bio] = dl_crypto.funcref("BIO_new") catch {
    error => raise SymbolMissing(error)
  }
  let bio_read : FuncRef[(Bio, @c.Pointer[Byte], Int) -> Int] = dl_crypto.funcref(
    "BIO_read",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let bio_read_ex : FuncRef[
    (Bio, @c.Pointer[Byte], UInt64, @c.Pointer[UInt64]) -> Int,
  ] = dl_crypto.funcref("BIO_read_ex") catch {
    error => raise SymbolMissing(error)
  }
  let bio_write : FuncRef[(Bio, @c.Pointer[Byte], Int) -> Int] = dl_crypto.funcref(
    "BIO_write",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let bio_write_ex : FuncRef[
    (Bio, @c.Pointer[Byte], UInt64, @c.Pointer[UInt64]) -> Int,
  ] = dl_crypto.funcref("BIO_write_ex") catch {
    error => raise SymbolMissing(error)
  }
  let bio_ctrl : FuncRef[(Bio, Int, Int64, @c.Pointer[Unit]) -> Int64] = dl_crypto.funcref(
    "BIO_ctrl",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let bio_ctrl_pending : FuncRef[(Bio) -> UInt64] = dl_crypto.funcref(
    "BIO_ctrl_pending",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let bio_ctrl_wpending : FuncRef[(Bio) -> UInt64] = dl_crypto.funcref(
    "BIO_ctrl_wpending",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let err_get_error : FuncRef[() -> UInt64] = dl_crypto.funcref("ERR_get_error") catch {
    error => raise SymbolMissing(error)
  }
  let err_peek_error : FuncRef[() -> UInt64] = dl_crypto.funcref(
    "ERR_peek_error",
  ) catch {
    error => raise SymbolMissing(error)
  }
  let err_error_string_n : FuncRef[(UInt64, @c.Pointer[Byte], Int) -> Unit] = dl_crypto.funcref(
    "ERR_error_string_n",
  ) catch {
    error => raise SymbolMissing(error)
  }
  {
    dl_ssl,
    dl_crypto,
    init_ssl,
    tls_client_method,
    tls_server_method,
    ssl_ctx_new,
    ssl_ctx_set_cert_store,
    ssl_ctx_set_verify,
    ssl_ctx_ctrl,
    ssl_ctrl,
    ssl_ctx_set_options,
    ssl_ctx_clear_options,
    ssl_ctx_get_options,
    ssl_set_options,
    ssl_clear_options,
    ssl_get_options,
    ssl_ctx_set_default_verify_paths,
    ssl_ctx_set_cipher_list,
    ssl_set_cipher_list,
    ssl_ctx_set_ciphersuites,
    ssl_set_ciphersuites,
    ssl_ctx_use_certificate,
    ssl_ctx_use_private_key,
    ssl_ctx_free,
    ssl_new,
    ssl_set_fd,
    ssl_set1_host,
    ssl_set_accept_state,
    ssl_do_handshake,
    ssl_connect,
    ssl_accept,
    ssl_shutdown,
    ssl_free,
    ssl_read,
    ssl_write,
    ssl_get_error,
    ssl_get_version,
    ssl_version,
    ssl_client_version,
    ssl_get0_peer_certificate,
    ssl_get1_peer_certificate,
    ssl_get_verify_result,
    ssl_set_bio,
    ssl_ctx_use_private_key_file,
    ssl_ctx_use_certificate_file,
    x509_store_new,
    x509_store_free,
    x509_store_add_cert,
    x509_free,
    x509_get_subject_name,
    x509_get_issuer_name,
    pem_read_bio_x509,
    bio_new_mem_buf,
    bio_free,
    pem_read_bio_private_key,
    evp_pkey_free,
    bio_s_mem,
    bio_new,
    bio_read,
    bio_read_ex,
    bio_write,
    bio_write_ex,
    bio_ctrl,
    bio_ctrl_pending,
    bio_ctrl_wpending,
    err_get_error,
    err_peek_error,
    err_error_string_n,
  }
}
