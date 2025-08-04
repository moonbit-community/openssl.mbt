///|
pub const INIT_LOAD_SSL_STRINGS : UInt64 = 0x00200000UL

///|
pub const INIT_LOAD_CRYPTO_STRINGS : UInt64 = 0x00000002UL

///|
pub extern "c" fn init_ssl(opts : UInt64, settings : @c.Pointer[Unit]) -> Int = "OPENSSL_init_ssl"

///|
pub type Tls

///|
pub extern "c" fn Tls::client_method() -> SslMethod = "TLS_client_method"

///|
#external
type SslMethod

///|
#external
type SslCtx

///|
pub extern "c" fn SslCtx::new(method_ : SslMethod) -> SslCtx = "SSL_CTX_new"

///|
pub extern "c" fn SslCtx::set_cert_store(
  ctx : SslCtx,
  store : X509Store,
) -> Int = "SSL_CTX_set_cert_store"

///|
pub extern "c" fn SslCtx::free(ctx : SslCtx) = "SSL_CTX_free"

///|
#external
type Ssl

///|
pub extern "c" fn Ssl::new(ctx : SslCtx) -> Ssl = "SSL_new"

///|
pub extern "c" fn Ssl::set_fd(self : Ssl, fd : Int) -> Int = "SSL_set_fd"

///|
pub extern "c" fn Ssl::connect(self : Ssl) -> Int = "SSL_connect"

///|
pub extern "c" fn Ssl::free(self : Ssl) = "SSL_free"

///|
#borrow(buf)
pub extern "c" fn Ssl::read(ssl : Ssl, buf : Bytes, num : Int) -> Int = "SSL_read"

///|
#borrow(buf)
pub extern "c" fn Ssl::write(self : Ssl, buf : Bytes, num : Int) -> Int = "SSL_write"

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
pub extern "c" fn Ssl::get_error(ssl : Ssl, ret : Int) -> SslError = "SSL_get_error"

///|
#external
type X509Store

///|
pub extern "c" fn X509Store::new() -> X509Store = "X509_STORE_new"

///|
#external
type X509

///|
pub extern "c" fn X509::free(cert : X509) = "X509_free"

///|
pub type Pem

///|
pub extern "c" fn Pem::read_bio_x509(
  bio : Bio,
  x509 : @c.Nullable[X509],
  cb : @c.Pointer[Unit],
  u : @c.Pointer[Unit],
) -> X509 = "PEM_read_bio_X509"

///|
pub extern "c" fn X509Store::free(store : X509Store) = "X509_STORE_free"

///|
pub extern "c" fn X509Store::add_cert(store : X509Store, cert : X509) -> Int = "X509_STORE_add_cert"

///|
#external
type Bio

///|
#borrow(buf)
pub extern "c" fn Bio::new_mem_buf(buf : Bytes, len : Int) -> Bio = "BIO_new_mem_buf"

///|
pub extern "c" fn Bio::free(bio : Bio) = "BIO_free"
