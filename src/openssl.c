#include <moonbit.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#endif

MOONBIT_FFI_EXPORT
int32_t
moonbit_OPENSSL_init_ssl(uint64_t opts) {
  return OPENSSL_init_ssl(opts, NULL);
}

MOONBIT_FFI_EXPORT
const SSL_METHOD *
moonbit_TLS_client_method(void) {
  return TLS_client_method();
}

MOONBIT_FFI_EXPORT
const SSL_METHOD *
moonbit_TLS_server_method(void) {
  return TLS_server_method();
}

MOONBIT_FFI_EXPORT
SSL_CTX *
moonbit_SSL_CTX_new(const SSL_METHOD *method) {
  return SSL_CTX_new(method);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store) {
  return SSL_CTX_set_cert_store(ctx, store);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x509) {
  return SSL_CTX_use_certificate(ctx, x509);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey) {
  return SSL_CTX_use_PrivateKey(ctx, pkey);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int32_t version) {
  return SSL_CTX_set_min_proto_version(ctx, version);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int32_t version) {
  return SSL_CTX_set_max_proto_version(ctx, version);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_get_min_proto_version(SSL_CTX *ctx) {
  return SSL_CTX_get_min_proto_version(ctx);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_get_max_proto_version(SSL_CTX *ctx) {
  return SSL_CTX_get_max_proto_version(ctx);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set_min_proto_version(SSL *ssl, int32_t version) {
  return SSL_set_min_proto_version(ssl, version);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set_max_proto_version(SSL *ssl, int32_t version) {
  return SSL_set_max_proto_version(ssl, version);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_get_min_proto_version(SSL *ssl) {
  return SSL_get_min_proto_version(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_get_max_proto_version(SSL *ssl) {
  return SSL_get_max_proto_version(ssl);
}

MOONBIT_FFI_EXPORT
X509_NAME *
moonbit_X509_get_subject_name(const X509 *cert) {
  return X509_get_subject_name(cert);
}

MOONBIT_FFI_EXPORT
X509_NAME *
moonbit_X509_get_issuer_name(const X509 *cert) {
  return X509_get_issuer_name(cert);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_SSL_CTX_set_options(SSL_CTX *ctx, uint64_t options) {
  return SSL_CTX_set_options(ctx, options);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_SSL_CTX_clear_options(SSL_CTX *ctx, uint64_t options) {
  return SSL_CTX_clear_options(ctx, options);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_SSL_CTX_get_options(const SSL_CTX *ctx) {
  return SSL_CTX_get_options(ctx);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_SSL_set_options(SSL *ssl, uint64_t options) {
  return SSL_set_options(ssl, options);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_SSL_clear_options(SSL *ssl, uint64_t options) {
  return SSL_clear_options(ssl, options);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_SSL_get_options(const SSL *ssl) {
  return SSL_get_options(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_pending(BIO *bio) {
  return BIO_pending(bio);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_wpending(BIO *bio) {
  return BIO_wpending(bio);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_BIO_ctrl_pending(BIO *bio) {
  return BIO_ctrl_pending(bio);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_BIO_ctrl_wpending(BIO *bio) {
  return BIO_ctrl_wpending(bio);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_reset(BIO *bio) {
  return BIO_reset(bio);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_flush(BIO *bio) {
  return BIO_flush(bio);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_eof(BIO *bio) {
  return BIO_eof(bio);
}



MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_ctrl(SSL_CTX *ctx, int32_t cmd, int32_t larg, void *parg) {
  return SSL_CTX_ctrl(ctx, cmd, larg, parg);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) {
  return SSL_CTX_set_default_verify_paths(ctx);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_CTX_set_verify(SSL_CTX *ctx, int32_t mode) {
  return SSL_CTX_set_verify(ctx, mode, NULL);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_CTX_free(SSL_CTX *ctx) {
  return SSL_CTX_free(ctx);
}

MOONBIT_FFI_EXPORT
SSL *
moonbit_SSL_new(SSL_CTX *ctx) {
  return SSL_new(ctx);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_free(SSL *ssl) {
  return SSL_free(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set_tlsext_host_name(SSL *ssl, const char *name) {
  return SSL_set_tlsext_host_name(ssl, name);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_ctrl(SSL *ssl, int32_t cmd, int32_t larg, void *parg) {
  return SSL_ctrl(ssl, cmd, larg, parg);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_do_handshake(SSL *ssl) {
  return SSL_do_handshake(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set1_host(SSL *ssl, const char *name) {
  return SSL_set1_host(ssl, name);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set_fd(SSL *ssl, int fd) {
  return SSL_set_fd(ssl, fd);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_accept(SSL *ssl) {
  return SSL_accept(ssl);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_set_accept_state(SSL *ssl) {
  return SSL_set_accept_state(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_connect(SSL *ssl) {
  int32_t result = SSL_connect(ssl);
  if (result <= 0) {
    ERR_print_errors_fp(stderr);
  }
  return result;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_read(SSL *ssl, uint8_t *buf, int32_t off, int32_t num) {
  int32_t result = SSL_read(ssl, buf + off, num);
  if (result <= 0) {
    ERR_print_errors_fp(stderr);
  }
  return result;
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_write(SSL *ssl, const uint8_t *buf, int32_t off, int32_t num) {
  return SSL_write(ssl, buf + off, num);
}

MOONBIT_FFI_EXPORT
int
moonbit_SSL_shutdown(SSL *ssl) {
  return SSL_shutdown(ssl);
}

MOONBIT_FFI_EXPORT
int
moonbit_SSL_get_error(const SSL *ssl, int ret_code) {
  return SSL_get_error(ssl, ret_code);
}

MOONBIT_FFI_EXPORT
X509_STORE *
moonbit_X509_STORE_new(void) {
  return X509_STORE_new();
}

MOONBIT_FFI_EXPORT
void
moonbit_X509_STORE_free(X509_STORE *store) {
  return X509_STORE_free(store);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_X509_STORE_add_cert(X509_STORE *store, X509 *x509) {
  return X509_STORE_add_cert(store, x509);
}

MOONBIT_FFI_EXPORT
X509 *
moonbit_X509_new(void) {
  return X509_new();
}

MOONBIT_FFI_EXPORT
void
moonbit_X509_free(X509 *x509) {
  return X509_free(x509);
}

MOONBIT_FFI_EXPORT
const char *
moonbit_X509_get_default_cert_file() {
  return X509_get_default_cert_file();
}

MOONBIT_FFI_EXPORT
void
moonbit_EVP_PKEY_free(EVP_PKEY *pkey) {
  return EVP_PKEY_free(pkey);
}

MOONBIT_FFI_EXPORT
BIO *
moonbit_BIO_new_mem_buf(const void *buf, int len) {
  return BIO_new_mem_buf(buf, len);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_free(BIO *bio) {
  return BIO_free(bio);
}

MOONBIT_FFI_EXPORT
X509 *
moonbit_PEM_read_bio_X509(BIO *bp) {
  return PEM_read_bio_X509(bp, NULL, NULL, NULL);
}

MOONBIT_FFI_EXPORT
EVP_PKEY *
moonbit_PEM_read_bio_PrivateKey(BIO *bp) {
  return PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_use_PrivateKey_file(
  SSL_CTX *ctx,
  const char *file,
  int32_t type
) {
  return SSL_CTX_use_PrivateKey_file(ctx, file, type);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_use_certificate_file(
  SSL_CTX *ctx,
  const char *file,
  int32_t type
) {
  return SSL_CTX_use_certificate_file(ctx, file, type);
}

MOONBIT_FFI_EXPORT
const BIO_METHOD *
moonbit_BIO_s_mem() {
  return BIO_s_mem();
}

MOONBIT_FFI_EXPORT
BIO *
moonbit_BIO_new(const BIO_METHOD *type) {
  return BIO_new(type);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_read(BIO *bio, void *buf, int32_t off, int32_t len) {
  return BIO_read(bio, buf + off, len);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_write(BIO *bio, const void *buf, int32_t off, int32_t len) {
  return BIO_write(bio, buf + off, len);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio) {
  return SSL_set_bio(ssl, rbio, wbio);
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_ERR_get_error(void) {
  return ERR_get_error();
}

MOONBIT_FFI_EXPORT
uint64_t
moonbit_ERR_peek_error(void) {
  return ERR_peek_error();
}

MOONBIT_FFI_EXPORT
void
moonbit_ERR_error_string_n(uint64_t e, char *buf, int32_t len) {
  return ERR_error_string_n(e, buf, len);
}

MOONBIT_FFI_EXPORT
const char *
moonbit_SSL_get_version(const SSL *ssl) {
  return SSL_get_version(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_version(const SSL *ssl) {
  return SSL_version(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_client_version(const SSL *ssl) {
  return SSL_client_version(ssl);
}

MOONBIT_FFI_EXPORT
X509 *
moonbit_SSL_get0_peer_certificate(const SSL *ssl) {
  return SSL_get0_peer_certificate(ssl);
}

MOONBIT_FFI_EXPORT
X509 *
moonbit_SSL_get1_peer_certificate(const SSL *ssl) {
  return SSL_get1_peer_certificate(ssl);
}

MOONBIT_FFI_EXPORT
int64_t
moonbit_SSL_get_verify_result(const SSL *ssl) {
  return SSL_get_verify_result(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
  return SSL_CTX_set_cipher_list(ctx, str);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set_cipher_list(SSL *ssl, const char *str) {
  return SSL_set_cipher_list(ssl, str);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str) {
  return SSL_CTX_set_ciphersuites(ctx, str);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set_ciphersuites(SSL *ssl, const char *str) {
  return SSL_set_ciphersuites(ssl, str);
}
