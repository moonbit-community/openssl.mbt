///|
pub const INIT_LOAD_SSL_STRINGS : UInt64 = 0x00200000UL

///|
pub const INIT_LOAD_CRYPTO_STRINGS : UInt64 = 0x00000002UL

///|
pub fn init_ssl(opts : UInt64) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.init_ssl)(opts, @c.null())
}

///|
pub type Tls

///|
pub fn Tls::client_method() -> SslMethod raise OpenSslError {
  let api = ensure_openssl()
  (api.tls_client_method)()
}

///|
pub fn Tls::server_method() -> SslMethod raise OpenSslError {
  let api = ensure_openssl()
  (api.tls_server_method)()
}

///|
#external
type SslMethod

///|
#external
type SslCtx

///|
pub fn SslCtx::new(method_ : SslMethod) -> SslCtx raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_new)(method_)
}

///|
pub fn SslCtx::set_cert_store(ctx : SslCtx, store : X509Store) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_set_cert_store)(ctx, store)
}

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
pub fn SslCtx::set_verify(ctx : SslCtx, mode : SslVerify) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  let SslVerify(value) = mode
  (api.ssl_ctx_set_verify)(ctx, value)
}

///|
pub fn SslCtx::set_min_proto_version(
  ctx : SslCtx,
  version : Int,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_set_min_proto_version)(ctx, version)
}

///|
pub fn SslCtx::set_max_proto_version(
  ctx : SslCtx,
  version : Int,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_set_max_proto_version)(ctx, version)
}

///|
pub fn SslCtx::get_min_proto_version(ctx : SslCtx) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_get_min_proto_version)(ctx)
}

///|
pub fn SslCtx::get_max_proto_version(ctx : SslCtx) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_get_max_proto_version)(ctx)
}

///|
pub fn Ssl::set_min_proto_version(ssl : Ssl, version : Int) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_set_min_proto_version)(ssl, version)
}

///|
pub fn Ssl::set_max_proto_version(ssl : Ssl, version : Int) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_set_max_proto_version)(ssl, version)
}

///|
pub fn Ssl::get_min_proto_version(ssl : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_get_min_proto_version)(ssl)
}

///|
pub fn Ssl::get_max_proto_version(ssl : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_get_max_proto_version)(ssl)
}

///|
pub fn SslCtx::set_options(ctx : SslCtx, options : UInt64) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_set_options)(ctx, options)
}

///|
pub fn SslCtx::clear_options(
  ctx : SslCtx,
  options : UInt64,
) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_clear_options)(ctx, options)
}

///|
pub fn SslCtx::get_options(ctx : SslCtx) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_get_options)(ctx)
}

///|
pub fn Ssl::set_options(ssl : Ssl, options : UInt64) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_set_options)(ssl, options)
}

///|
pub fn Ssl::clear_options(ssl : Ssl, options : UInt64) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_clear_options)(ssl, options)
}

///|
pub fn Ssl::get_options(ssl : Ssl) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_get_options)(ssl)
}

///|
pub fn SslCtx::set_default_verify_paths(ctx : SslCtx) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  ignore((api.ssl_ctx_set_default_verify_paths)(ctx))
}

///|
pub fn SslCtx::set_cipher_list(ctx : SslCtx, str : Bytes) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(str, ptr => (api.ssl_ctx_set_cipher_list)(ctx, ptr))
}

///|
pub fn Ssl::set_cipher_list(ssl : Ssl, str : Bytes) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(str, ptr => (api.ssl_set_cipher_list)(ssl, ptr))
}

///|
pub fn SslCtx::set_ciphersuites(ctx : SslCtx, str : Bytes) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(str, ptr => (api.ssl_ctx_set_ciphersuites)(ctx, ptr))
}

///|
pub fn Ssl::set_ciphersuites(ssl : Ssl, str : Bytes) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(str, ptr => (api.ssl_set_ciphersuites)(ssl, ptr))
}

///|
pub fn SslCtx::use_certificate(ctx : SslCtx, cert : X509) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_use_certificate)(ctx, cert)
}

///|
pub fn SslCtx::use_PrivateKey(ctx : SslCtx, key : EvpPkey) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_use_private_key)(ctx, key)
}

///|
pub fn SslCtx::free(ctx : SslCtx) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_ctx_free)(ctx)
}

///|
#external
type Ssl

///|
pub fn Ssl::new(ctx : SslCtx) -> Ssl raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_new)(ctx)
}

///|
pub fn Ssl::set_fd(self : Ssl, fd : Int) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_set_fd)(self, fd)
}

///|
pub fn Ssl::set_tlsext_host_name(self : Ssl, name : Bytes) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(name, ptr => (api.ssl_set_tlsext_host_name)(self, ptr))
}

///|
pub fn Ssl::set1_host(self : Ssl, name : Bytes) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(name, ptr => (api.ssl_set1_host)(self, ptr))
}

///|
pub fn Ssl::set_accept_state(self : Ssl) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_set_accept_state)(self)
}

///|
pub fn Ssl::do_handshake(self : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_do_handshake)(self)
}

///|
pub fn Ssl::connect(self : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_connect)(self)
}

///|
pub fn Ssl::accept(self : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_accept)(self)
}

///|
pub fn Ssl::shutdown(self : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_shutdown)(self)
}

///|
pub fn Ssl::free(self : Ssl) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_free)(self)
}

///|
pub fn Ssl::read(
  ssl : Ssl,
  buf : Bytes,
  off : Int,
  num : Int,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(buf, ptr => {
    let offset = @c.Size::from_uint64(off.to_uint64())
    (api.ssl_read)(ssl, ptr.byte_add(offset), num)
  })
}

///|
pub fn Ssl::write(
  self : Ssl,
  buf : Bytes,
  off : Int,
  num : Int,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(buf, ptr => {
    let offset = @c.Size::from_uint64(off.to_uint64())
    (api.ssl_write)(self, ptr.byte_add(offset), num)
  })
}

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
pub fn Ssl::get_error(ssl : Ssl, ret : Int) -> SslError raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_get_error)(ssl, ret)
}

///|
pub fn Ssl::get_version(ssl : Ssl) -> Bytes raise OpenSslError {
  let api = ensure_openssl()
  let ptr = (api.ssl_get_version)(ssl)
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
pub fn Ssl::version(ssl : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_version)(ssl)
}

///|
pub fn Ssl::client_version(ssl : Ssl) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_client_version)(ssl)
}

///|
pub fn Ssl::get0_peer_certificate(ssl : Ssl) -> X509? raise OpenSslError {
  let api = ensure_openssl()
  let ptr = (api.ssl_get0_peer_certificate)(ssl)
  if ptr.is_null() {
    return None
  }
  Some(ptr.unsafe_into())
}

///|
pub fn Ssl::get1_peer_certificate(ssl : Ssl) -> X509? raise OpenSslError {
  let api = ensure_openssl()
  let ptr = (api.ssl_get1_peer_certificate)(ssl)
  if ptr.is_null() {
    return None
  }
  Some(ptr.unsafe_into())
}

///|
pub fn Ssl::get_verify_result(ssl : Ssl) -> Int64 raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_get_verify_result)(ssl)
}

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
pub fn X509Store::new() -> X509Store raise OpenSslError {
  let api = ensure_openssl()
  (api.x509_store_new)()
}

///|
#external
type X509

///|
pub fn X509::free(cert : X509) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  (api.x509_free)(cert)
}

///|
#external
type X509Name

///|
pub fn X509::get_subject_name(cert : X509) -> X509Name raise OpenSslError {
  let api = ensure_openssl()
  (api.x509_get_subject_name)(cert)
}

///|
pub fn X509::get_issuer_name(cert : X509) -> X509Name raise OpenSslError {
  let api = ensure_openssl()
  (api.x509_get_issuer_name)(cert)
}

///|
pub type Pem

///|
pub fn Pem::read_bio_x509(bio : Bio) -> X509 raise OpenSslError {
  let api = ensure_openssl()
  (api.pem_read_bio_x509)(bio)
}

///|
pub fn X509Store::free(store : X509Store) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  (api.x509_store_free)(store)
}

///|
pub fn X509Store::add_cert(store : X509Store, cert : X509) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.x509_store_add_cert)(store, cert)
}

///|
#external
type Bio

///|
pub fn Bio::new_mem_buf(buf : Bytes, len : Int) -> Bio raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(buf, ptr => (api.bio_new_mem_buf)(ptr, len))
}

///|
pub fn Bio::free(bio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_free)(bio)
}

///|
#external
type EvpPkey

///|
pub fn Pem::read_bio_PrivateKey(bio : Bio) -> EvpPkey raise OpenSslError {
  let api = ensure_openssl()
  (api.pem_read_bio_private_key)(bio)
}

///|
pub fn EvpPkey::free(pkey : EvpPkey) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  (api.evp_pkey_free)(pkey)
}

///|
#alias(SslFiletype)
pub(all) enum X509Filetype {
  Pem = 1
  Asn1 = 2
  Default = 3
}

///|
pub fn SslCtx::use_PrivateKey_file(
  ctx : SslCtx,
  file : Bytes,
  type_ : X509Filetype,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  let type_val = match type_ {
    Pem => 1
    Asn1 => 2
    Default => 3
  }
  @c.borrow_bytes(file, ptr =>
    (api.ssl_ctx_use_private_key_file)(ctx, ptr, type_val)
  )
}

///|
pub fn SslCtx::use_certificate_file(
  ctx : SslCtx,
  file : Bytes,
  type_ : X509Filetype,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  let type_val = match type_ {
    Pem => 1
    Asn1 => 2
    Default => 3
  }
  @c.borrow_bytes(file, ptr =>
    (api.ssl_ctx_use_certificate_file)(ctx, ptr, type_val)
  )
}

///|
#external
type BioMethod

///|
pub fn Bio::s_mem() -> BioMethod raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_s_mem)()
}

///|
pub fn Bio::new(ty : BioMethod) -> Bio raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_new)(ty)
}

///|
pub fn Bio::read(
  bio : Bio,
  buf : Bytes,
  off : Int,
  len : Int,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(buf, ptr => {
    let offset = @c.Size::from_uint64(off.to_uint64())
    (api.bio_read)(bio, ptr.byte_add(offset), len)
  })
}

///|
pub fn Bio::read_ex(
  bio : Bio,
  data : Bytes,
  offset : UInt64,
  length : UInt64,
  readbytes : Ref[UInt64],
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(data, ptr =>
    @c.borrow_ref(readbytes, out_ptr => {
      let data_ptr = ptr.byte_add(@c.Size::from_uint64(offset))
      (api.bio_read_ex)(bio, data_ptr, length, out_ptr)
    })
  )
}

///|
pub fn Bio::write(
  bio : Bio,
  buf : Bytes,
  off : Int,
  len : Int,
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(buf, ptr => {
    let offset = @c.Size::from_uint64(off.to_uint64())
    (api.bio_write)(bio, ptr.byte_add(offset), len)
  })
}

///|
pub fn Bio::write_ex(
  bio : Bio,
  data : Bytes,
  offset : UInt64,
  length : UInt64,
  written : Ref[UInt64],
) -> Int raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(data, ptr =>
    @c.borrow_ref(written, out_ptr => {
      let data_ptr = ptr.byte_add(@c.Size::from_uint64(offset))
      (api.bio_write_ex)(bio, data_ptr, length, out_ptr)
    })
  )
}

///|
pub fn Ssl::set_bio(ssl : Ssl, rbio : Bio, wbio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.ssl_set_bio)(ssl, rbio, wbio)
  1
}

///|
pub fn Bio::pending(bio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_pending)(bio)
}

///|
pub fn Bio::wpending(bio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_wpending)(bio)
}

///|
pub fn Bio::ctrl_pending(bio : Bio) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_ctrl_pending)(bio)
}

///|
pub fn Bio::ctrl_wpending(bio : Bio) -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_ctrl_wpending)(bio)
}

///|
pub fn Bio::reset(bio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_reset)(bio)
}

///|
pub fn Bio::flush(bio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_flush)(bio)
}

///|
pub fn Bio::eof(bio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_eof)(bio)
}

///|
pub fn Bio::set_tfo(bio : Bio, onoff : Int) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_set_tfo)(bio, onoff)
}

///|
pub fn Bio::get_conn_mode(bio : Bio) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_get_conn_mode)(bio)
}

///|
pub fn Bio::set_conn_mode(bio : Bio, mode : Int) -> Int raise OpenSslError {
  let api = ensure_openssl()
  (api.bio_set_conn_mode)(bio, mode)
}

///|
#external
pub type Err

///|
pub fn Err::get_error() -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.err_get_error)()
}

///|
pub fn Err::peek_error() -> UInt64 raise OpenSslError {
  let api = ensure_openssl()
  (api.err_peek_error)()
}

///|
pub fn Err::error_string_n(err : UInt64, buf : Bytes, len : Int) -> Unit raise OpenSslError {
  let api = ensure_openssl()
  @c.borrow_bytes(buf, ptr => (api.err_error_string_n)(err, ptr, len))
}

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
