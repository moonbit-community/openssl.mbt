///|
pub const INIT_LOAD_SSL_STRINGS : UInt64 = 0x00200000UL

///|
pub const INIT_LOAD_CRYPTO_STRINGS : UInt64 = 0x00000002UL

///|
pub extern "c" fn init_ssl(opts : UInt64) -> Int = "moonbit_OPENSSL_init_ssl"

///|
pub type Tls

///|
pub extern "c" fn Tls::client_method() -> SslMethod = "moonbit_TLS_client_method"

///|
pub extern "c" fn Tls::server_method() -> SslMethod = "moonbit_TLS_server_method"

///|
#external
type SslMethod

///|
#external
type SslCtx

///|
pub extern "c" fn SslCtx::new(method_ : SslMethod) -> SslCtx = "moonbit_SSL_CTX_new"

///|
pub extern "c" fn SslCtx::set_cert_store(ctx : SslCtx, store : X509Store) = "moonbit_SSL_CTX_set_cert_store"

///|
pub extern "c" fn SslCtx::use_certificate(ctx : SslCtx, cert : X509) -> Int = "moonbit_SSL_CTX_use_certificate"

///|
pub extern "c" fn SslCtx::use_PrivateKey(ctx : SslCtx, key : EvpPkey) -> Int = "moonbit_SSL_CTX_use_PrivateKey"

///|
pub extern "c" fn SslCtx::free(ctx : SslCtx) = "moonbit_SSL_CTX_free"

///|
#external
type Ssl

///|
pub extern "c" fn Ssl::new(ctx : SslCtx) -> Ssl = "moonbit_SSL_new"

///|
pub extern "c" fn Ssl::set_fd(self : Ssl, fd : Int) -> Int = "moonbit_SSL_set_fd"

///|
pub extern "c" fn Ssl::set_accept_state(self : Ssl) = "moonbit_SSL_set_accept_state"

///|
pub extern "c" fn Ssl::connect(self : Ssl) -> Int = "moonbit_SSL_connect"

///|
pub extern "c" fn Ssl::accept(self : Ssl) -> Int = "moonbit_SSL_accept"

///|
pub extern "c" fn Ssl::free(self : Ssl) = "moonbit_SSL_free"

///|
#borrow(buf)
pub extern "c" fn Ssl::read(
  ssl : Ssl,
  buf : Bytes,
  off : Int,
  num : Int,
) -> Int = "moonbit_SSL_read"

///|
#borrow(buf)
pub extern "c" fn Ssl::write(
  self : Ssl,
  buf : Bytes,
  off : Int,
  num : Int,
) -> Int = "moonbit_SSL_write"

///|
pub enum SslError {
  None = 0
  ZeroReturn = 6
  WantRead = 2
  WantWrite = 3
  Syscall = 5
  Ssl = 1
} derive(Show)

///|
fn init {
  ignore(None)
  ignore(ZeroReturn)
  ignore(WantRead)
  ignore(WantWrite)
  ignore(Syscall)
  ignore(Ssl)
}

///|
pub extern "c" fn Ssl::get_error(ssl : Ssl, ret : Int) -> SslError = "moonbit_SSL_get_error"

///|
#external
type X509Store

///|
pub extern "c" fn X509Store::new() -> X509Store = "moonbit_X509_STORE_new"

///|
#external
type X509

///|
pub extern "c" fn X509::free(cert : X509) = "moonbit_X509_free"

///|
pub type Pem

///|
pub extern "c" fn Pem::read_bio_x509(bio : Bio) -> X509 = "moonbit_PEM_read_bio_X509"

///|
pub extern "c" fn X509Store::free(store : X509Store) = "moonbit_X509_STORE_free"

///|
pub extern "c" fn X509Store::add_cert(store : X509Store, cert : X509) -> Int = "moonbit_X509_STORE_add_cert"

///|
#external
type Bio

///|
#borrow(buf)
pub extern "c" fn Bio::new_mem_buf(buf : Bytes, len : Int) -> Bio = "moonbit_BIO_new_mem_buf"

///|
pub extern "c" fn Bio::free(bio : Bio) -> Int = "moonbit_BIO_free"

///|
#external
type EvpPkey

///|
pub extern "c" fn Pem::read_bio_PrivateKey(bio : Bio) -> EvpPkey = "moonbit_PEM_read_bio_PrivateKey"

///|
pub(all) enum X509Filetype {
  Pem = 1
  Asn1 = 2
  Default = 3
}

///|
pub typealias X509Filetype as SslFiletype

///|
#borrow(file)
pub extern "c" fn SslCtx::use_PrivateKey_file(
  ctx : SslCtx,
  file : Bytes,
  type_ : X509Filetype,
) -> Int = "moonbit_SSL_CTX_use_PrivateKey_file"

///|
#borrow(file)
pub extern "c" fn SslCtx::use_certificate_file(
  ctx : SslCtx,
  file : Bytes,
  type_ : X509Filetype,
) -> Int = "moonbit_SSL_CTX_use_certificate_file"
