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
struct SslVerify(Int)

///|
pub fn SslVerify::none() -> SslVerify {
  SslVerify(0x00)
}

///|
pub fn SslVerify::peer(
  fail_if_no_peer_cert? : Bool = false,
  client_once? : Bool = false,
  post_handshake? : Bool = false,
) -> SslVerify {
  let mut mode = 0x01
  if fail_if_no_peer_cert {
    mode = mode | 0x02
  }
  if client_once {
    mode = mode | 0x04
  }
  if post_handshake {
    mode = mode | 0x08
  }
  SslVerify(mode)
}

///|
pub extern "c" fn SslCtx::set_verify(ctx : SslCtx, mode : SslVerify) = "moonbit_SSL_CTX_set_verify"

///|
pub extern "c" fn SslCtx::set_min_proto_version(
  ctx : SslCtx,
  version : Int,
) -> Int = "moonbit_SSL_CTX_set_min_proto_version"

///|
pub extern "c" fn SslCtx::set_max_proto_version(
  ctx : SslCtx,
  version : Int,
) -> Int = "moonbit_SSL_CTX_set_max_proto_version"

///|
pub extern "c" fn SslCtx::get_min_proto_version(ctx : SslCtx) -> Int = "moonbit_SSL_CTX_get_min_proto_version"

///|
pub extern "c" fn SslCtx::get_max_proto_version(ctx : SslCtx) -> Int = "moonbit_SSL_CTX_get_max_proto_version"

///|
pub extern "c" fn Ssl::set_min_proto_version(ssl : Ssl, version : Int) -> Int = "moonbit_SSL_set_min_proto_version"

///|
pub extern "c" fn Ssl::set_max_proto_version(ssl : Ssl, version : Int) -> Int = "moonbit_SSL_set_max_proto_version"

///|
pub extern "c" fn Ssl::get_min_proto_version(ssl : Ssl) -> Int = "moonbit_SSL_get_min_proto_version"

///|
pub extern "c" fn Ssl::get_max_proto_version(ssl : Ssl) -> Int = "moonbit_SSL_get_max_proto_version"

///|
pub extern "c" fn SslCtx::set_options(ctx : SslCtx, options : UInt64) -> UInt64 = "moonbit_SSL_CTX_set_options"

///|
pub extern "c" fn SslCtx::clear_options(
  ctx : SslCtx,
  options : UInt64,
) -> UInt64 = "moonbit_SSL_CTX_clear_options"

///|
pub extern "c" fn SslCtx::get_options(ctx : SslCtx) -> UInt64 = "moonbit_SSL_CTX_get_options"

///|
pub extern "c" fn Ssl::set_options(ssl : Ssl, options : UInt64) -> UInt64 = "moonbit_SSL_set_options"

///|
pub extern "c" fn Ssl::clear_options(ssl : Ssl, options : UInt64) -> UInt64 = "moonbit_SSL_clear_options"

///|
pub extern "c" fn Ssl::get_options(ssl : Ssl) -> UInt64 = "moonbit_SSL_get_options"

///|
pub extern "c" fn SslCtx::set_default_verify_paths(ctx : SslCtx) = "moonbit_SSL_CTX_set_default_verify_paths"

///|
#borrow(str)
pub extern "c" fn SslCtx::set_cipher_list(ctx : SslCtx, str : Bytes) -> Int = "moonbit_SSL_CTX_set_cipher_list"

///|
#borrow(str)
pub extern "c" fn Ssl::set_cipher_list(ssl : Ssl, str : Bytes) -> Int = "moonbit_SSL_set_cipher_list"

///|
#borrow(str)
pub extern "c" fn SslCtx::set_ciphersuites(ctx : SslCtx, str : Bytes) -> Int = "moonbit_SSL_CTX_set_ciphersuites"

///|
#borrow(str)
pub extern "c" fn Ssl::set_ciphersuites(ssl : Ssl, str : Bytes) -> Int = "moonbit_SSL_set_ciphersuites"

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
#borrow(name)
pub extern "c" fn Ssl::set_tlsext_host_name(self : Ssl, name : Bytes) -> Int = "moonbit_SSL_set_tlsext_host_name"

///|
#borrow(name)
pub extern "c" fn Ssl::set1_host(self : Ssl, name : Bytes) -> Int = "moonbit_SSL_set1_host"

///|
pub extern "c" fn Ssl::set_accept_state(self : Ssl) = "moonbit_SSL_set_accept_state"

///|
pub extern "c" fn Ssl::do_handshake(self : Ssl) -> Int = "moonbit_SSL_do_handshake"

///|
pub extern "c" fn Ssl::connect(self : Ssl) -> Int = "moonbit_SSL_connect"

///|
pub extern "c" fn Ssl::accept(self : Ssl) -> Int = "moonbit_SSL_accept"

///|
pub extern "c" fn Ssl::shutdown(self : Ssl) -> Int = "moonbit_SSL_shutdown"

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
extern "c" fn moonbit_SSL_get_version(ssl : Ssl) -> @c.Pointer[Byte] = "moonbit_SSL_get_version"

///|
pub fn Ssl::get_version(ssl : Ssl) -> Bytes {
  let ptr = moonbit_SSL_get_version(ssl)
  if ptr.is_null() {
    return ""
  }
  let buffer = @buffer.new()
  for i = 0; ptr[i] != 0; i = i + 1 {
    buffer.write_byte(ptr[i])
  }
  buffer.contents()
}

///|
pub extern "c" fn Ssl::version(ssl : Ssl) -> Int = "moonbit_SSL_version"

///|
pub extern "c" fn Ssl::client_version(ssl : Ssl) -> Int = "moonbit_SSL_client_version"

///|
pub extern "c" fn Ssl::get0_peer_certificate(ssl : Ssl) -> X509? = "moonbit_SSL_get0_peer_certificate"

///|
pub extern "c" fn Ssl::get1_peer_certificate(ssl : Ssl) -> X509? = "moonbit_SSL_get1_peer_certificate"

///|
pub extern "c" fn Ssl::get_verify_result(ssl : Ssl) -> Int64 = "moonbit_SSL_get_verify_result"

///|
// X509 Verification Result Constants
pub const X509_V_OK : Int64 = 0L

///|
pub const X509_V_ERR_UNSPECIFIED : Int64 = 1L

///|
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT : Int64 = 2L

///|
pub const X509_V_ERR_UNABLE_TO_GET_CRL : Int64 = 3L

///|
pub const X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE : Int64 = 4L

///|
pub const X509_V_ERR_CERT_SIGNATURE_FAILURE : Int64 = 7L

///|
pub const X509_V_ERR_CERT_NOT_YET_VALID : Int64 = 9L

///|
pub const X509_V_ERR_CERT_HAS_EXPIRED : Int64 = 10L

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
#external
type X509Name

///|
pub extern "c" fn X509::get_subject_name(cert : X509) -> X509Name = "moonbit_X509_get_subject_name"

///|
pub extern "c" fn X509::get_issuer_name(cert : X509) -> X509Name = "moonbit_X509_get_issuer_name"

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
pub extern "c" fn EvpPkey::free(pkey : EvpPkey) = "moonbit_EVP_PKEY_free"

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

///|
#external
type BioMethod

///|
pub extern "c" fn Bio::s_mem() -> BioMethod = "moonbit_BIO_s_mem"

///|
pub extern "c" fn Bio::new(ty : BioMethod) -> Bio = "moonbit_BIO_new"

///|
#borrow(buf)
pub extern "c" fn Bio::read(
  bio : Bio,
  buf : Bytes,
  off : Int,
  len : Int,
) -> Int = "moonbit_BIO_read"

///|
#borrow(data, readbytes)
pub extern "c" fn Bio::read_ex(
  bio : Bio,
  data : Bytes,
  offset : UInt64,
  length : UInt64,
  readbytes : Ref[UInt64],
) -> Int = "moonbit_BIO_read_ex"

///|
#borrow(buf)
pub extern "c" fn Bio::write(
  bio : Bio,
  buf : Bytes,
  off : Int,
  len : Int,
) -> Int = "moonbit_BIO_write"

///|
#borrow(data, written)
pub extern "c" fn Bio::write_ex(
  bio : Bio,
  data : Bytes,
  offset : UInt64,
  length : UInt64,
  written : Ref[UInt64],
) -> Int = "moonbit_BIO_write_ex"

///|
pub extern "c" fn Ssl::set_bio(ssl : Ssl, rbio : Bio, wbio : Bio) -> Int = "moonbit_SSL_set_bio"

///|
pub extern "c" fn Bio::pending(bio : Bio) -> Int = "moonbit_BIO_pending"

///|
pub extern "c" fn Bio::wpending(bio : Bio) -> Int = "moonbit_BIO_wpending"

///|
pub extern "c" fn Bio::ctrl_pending(bio : Bio) -> UInt64 = "moonbit_BIO_ctrl_pending"

///|
pub extern "c" fn Bio::ctrl_wpending(bio : Bio) -> UInt64 = "moonbit_BIO_ctrl_wpending"

///|
pub extern "c" fn Bio::reset(bio : Bio) -> Int = "moonbit_BIO_reset"

///|
pub extern "c" fn Bio::flush(bio : Bio) -> Int = "moonbit_BIO_flush"

///|
pub extern "c" fn Bio::eof(bio : Bio) -> Int = "moonbit_BIO_eof"

///|
pub extern "c" fn Bio::set_tfo(bio : Bio, onoff : Int) -> Int = "moonbit_BIO_set_tfo"

///|
pub extern "c" fn Bio::get_conn_mode(bio : Bio) -> Int = "moonbit_BIO_get_conn_mode"

///|
pub extern "c" fn Bio::set_conn_mode(bio : Bio, mode : Int) -> Int = "moonbit_BIO_set_conn_mode"

///|
#external
pub type Err

///|
pub extern "c" fn Err::get_error() -> UInt64 = "moonbit_ERR_get_error"

///|
pub extern "c" fn Err::peek_error() -> UInt64 = "moonbit_ERR_peek_error"

///|
#borrow(buf)
pub extern "c" fn Err::error_string_n(err : UInt64, buf : Bytes, len : Int) = "moonbit_ERR_error_string_n"

///|
// SSL Protocol Version Constants
pub const SSL3_VERSION : Int = 0x0300

///|
pub const TLS1_VERSION : Int = 0x0301

///|
pub const TLS1_1_VERSION : Int = 0x0302

///|
pub const TLS1_2_VERSION : Int = 0x0303

///|
pub const TLS1_3_VERSION : Int = 0x0304

///|
pub const DTLS1_VERSION : Int = 0xFEFF

///|
pub const DTLS1_2_VERSION : Int = 0xFEFD

///|
pub const DTLS1_BAD_VER : Int = 0x0100

///|
// SSL Option Constants (based on SSL_OP_BIT macros)
pub const SSL_OP_NO_EXTENDED_MASTER_SECRET : UInt64 = 0x1UL // SSL_OP_BIT(0)

///|
pub const SSL_OP_CLEANSE_PLAINTEXT : UInt64 = 0x2UL // SSL_OP_BIT(1)

///|
pub const SSL_OP_LEGACY_SERVER_CONNECT : UInt64 = 0x4UL // SSL_OP_BIT(2)

///|
pub const SSL_OP_ENABLE_KTLS : UInt64 = 0x8UL // SSL_OP_BIT(3)

///|
pub const SSL_OP_TLSEXT_PADDING : UInt64 = 0x10UL // SSL_OP_BIT(4)

///|
pub const SSL_OP_SAFARI_ECDHE_ECDSA_BUG : UInt64 = 0x40UL // SSL_OP_BIT(6)

///|
pub const SSL_OP_IGNORE_UNEXPECTED_EOF : UInt64 = 0x80UL // SSL_OP_BIT(7)

///|
pub const SSL_OP_ALLOW_CLIENT_RENEGOTIATION : UInt64 = 0x100UL // SSL_OP_BIT(8)

///|
pub const SSL_OP_DISABLE_TLSEXT_CA_NAMES : UInt64 = 0x200UL // SSL_OP_BIT(9)

///|
pub const SSL_OP_ALLOW_NO_DHE_KEX : UInt64 = 0x400UL // SSL_OP_BIT(10)

///|
pub const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS : UInt64 = 0x800UL // SSL_OP_BIT(11)

///|
pub const SSL_OP_NO_QUERY_MTU : UInt64 = 0x1000UL // SSL_OP_BIT(12)

///|
pub const SSL_OP_COOKIE_EXCHANGE : UInt64 = 0x2000UL // SSL_OP_BIT(13)

///|
pub const SSL_OP_NO_TICKET : UInt64 = 0x4000UL // SSL_OP_BIT(14)

///|
pub const SSL_OP_CISCO_ANYCONNECT : UInt64 = 0x8000UL // SSL_OP_BIT(15)

///|
pub const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION : UInt64 = 0x10000UL // SSL_OP_BIT(16)

///|
pub const SSL_OP_NO_COMPRESSION : UInt64 = 0x20000UL // SSL_OP_BIT(17)

///|
pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION : UInt64 = 0x40000UL // SSL_OP_BIT(18)

///|
pub const SSL_OP_NO_ENCRYPT_THEN_MAC : UInt64 = 0x80000UL // SSL_OP_BIT(19)

///|
pub const SSL_OP_ENABLE_MIDDLEBOX_COMPAT : UInt64 = 0x100000UL // SSL_OP_BIT(20)

///|
pub const SSL_OP_PRIORITIZE_CHACHA : UInt64 = 0x200000UL // SSL_OP_BIT(21)

///|
pub const SSL_OP_CIPHER_SERVER_PREFERENCE : UInt64 = 0x400000UL // SSL_OP_BIT(22)

///|
pub const SSL_OP_TLS_ROLLBACK_BUG : UInt64 = 0x800000UL // SSL_OP_BIT(23)

///|
pub const SSL_OP_NO_ANTI_REPLAY : UInt64 = 0x1000000UL // SSL_OP_BIT(24)

///|
pub const SSL_OP_NO_RENEGOTIATION : UInt64 = 0x40000000UL // SSL_OP_BIT(30)

///|
pub const SSL_OP_CRYPTOPRO_TLSEXT_BUG : UInt64 = 0x80000000UL // SSL_OP_BIT(31)

///|
pub const SSL_OP_NO_SSLv3 : UInt64 = 0x2000000UL // SSL_OP_BIT(25)

///|
pub const SSL_OP_NO_TLSv1 : UInt64 = 0x4000000UL // SSL_OP_BIT(26)

///|
pub const SSL_OP_NO_TLSv1_1 : UInt64 = 0x10000000UL // SSL_OP_BIT(28)

///|
pub const SSL_OP_NO_TLSv1_2 : UInt64 = 0x8000000UL // SSL_OP_BIT(27)

///|
pub const SSL_OP_NO_TLSv1_3 : UInt64 = 0x20000000UL // SSL_OP_BIT(29)

///|
pub const SSL_OP_NO_DTLSv1 : UInt64 = 0x4000000UL // SSL_OP_BIT(26)

///|
pub const SSL_OP_NO_DTLSv1_2 : UInt64 = 0x8000000UL // SSL_OP_BIT(27)

///|
// Combined SSL_OP_ALL constant (based on OpenSSL definition)
pub const SSL_OP_ALL : UInt64 = 0x80000850UL // SSL_OP_CRYPTOPRO_TLSEXT_BUG | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS | SSL_OP_TLSEXT_PADDING | SSL_OP_SAFARI_ECDHE_ECDSA_BUG

///|
// BIO Socket Connection Mode Constants
pub const BIO_SOCK_REUSEADDR : Int = 0x01

///|
pub const BIO_SOCK_V6_ONLY : Int = 0x02

///|
pub const BIO_SOCK_KEEPALIVE : Int = 0x04

///|
pub const BIO_SOCK_NONBLOCK : Int = 0x08

///|
pub const BIO_SOCK_NODELAY : Int = 0x10

///|
pub const BIO_SOCK_TFO : Int = 0x20
