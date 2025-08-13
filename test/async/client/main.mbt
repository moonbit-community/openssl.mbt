///|
fn resolve(uv : @uv.Loop, host : Bytes, port : Bytes) -> Bytes raise {
  let errors = []
  let hints = @uv.AddrInfoHints::new()
  let mut addr = None
  uv.getaddrinfo(
    infos => for info in infos {
      addr = Some(info.addr())
    },
    error => errors.push(error),
    host,
    port,
    hints~,
  )
  |> ignore()
  uv.run(Default)
  for error in errors {
    raise error
  }
  guard addr is Some(addr) else {
    fail("Failed to resolve address for \{host}:\{port}")
  }
  addr.ip_name()
}

///|
fn bytes_to_fixed_array_byte(bytes : Bytes) -> FixedArray[Byte] = "%identity"

///|
fn fixed_array_byte_to_bytes(fixed_array : FixedArray[Byte]) -> Bytes = "%identity"

///|
let request : Bytes = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"

///|
async fn Ssl::send(self : Ssl) -> Unit raise {
  let len = self.wbio.read(self.bytes, 0, self.bytes.length())
  self.tcp.send(self.bytes, offset=0, len~)
}

///|
async fn Ssl::recv(self : Ssl) -> Unit raise {
  let bytes = bytes_to_fixed_array_byte(self.bytes)
  let len = self.tcp.recv(bytes, offset=0, max_len=bytes.length())
  let bytes = fixed_array_byte_to_bytes(bytes)
  if self.rbio.write(bytes, 0, len) < len {
    fail("Failed to write to SSL BIO")
  }
}

///|
struct Ssl {
  tcp : @socket.TCP
  ssl : @openssl.Ssl
  rbio : @openssl.Bio
  wbio : @openssl.Bio
  bytes : Bytes
}

///|
fn Ssl::new(
  ctx : @openssl.SslCtx,
  tcp : @socket.TCP,
  host~ : Bytes,
) -> Ssl raise {
  let ssl = @openssl.Ssl::new(ctx)
  let bio_s_mem = @openssl.Bio::s_mem()
  let rbio = @openssl.Bio::new(bio_s_mem)
  let wbio = @openssl.Bio::new(bio_s_mem)
  if ssl.set_bio(rbio, wbio) != 1 {
    fail("Failed to set BIO for SSL")
  }
  if ssl.set_tlsext_host_name(host) != 1 {
    fail("Failed to set TLS SNI hostname")
  }
  if ssl.set1_host(host) != 1 {
    fail("Failed to set TLS host")
  }
  let bytes = Bytes::make(4096, 0)
  { tcp, ssl, rbio, wbio, bytes }
}

///|
async fn Ssl::connect(self : Ssl) -> Unit raise {
  loop self.ssl.get_error(self.ssl.connect()) {
    None => ()
    ZeroReturn => ()
    WantRead => {
      self.send()
      self.recv()
      continue self.ssl.get_error(self.ssl.connect())
    }
    WantWrite => {
      self.send()
      continue self.ssl.get_error(self.ssl.connect())
    }
    error => fail("SSL connect error: \{error}")
  }
}

///|
async fn Ssl::write_all(
  self : Ssl,
  buffer : Bytes,
  offset : Int,
  length : Int,
) -> Unit raise {
  let written = self.ssl.write(buffer, offset, length)
  match self.ssl.get_error(written) {
    None =>
      if written < length {
        self.write_all(buffer, offset + written, length - written)
      }
    ZeroReturn => ()
    WantRead => {
      self.send()
      self.recv()
      self.write_all(buffer, offset, length)
    }
    WantWrite => {
      self.send()
      self.write_all(buffer, offset, length)
    }
    error => fail("SSL write error: \{error}")
  }
}

///|
async fn Ssl::read_all(self : Ssl, buffer : @buffer.T) -> Unit raise {
  let read = self.ssl.read(self.bytes, 0, self.bytes.length())
  match self.ssl.get_error(read) {
    None => buffer.write_bytesview(self.bytes[:read])
    ZeroReturn => ()
    WantRead => {
      self.send()
      self.recv()
      self.read_all(buffer)
    }
    WantWrite => {
      self.send()
      self.read_all(buffer)
    }
    error => fail("SSL read error: \{error}")
  }
}

///|
fn main {
  try {
    let ssl_opts = @openssl.INIT_LOAD_SSL_STRINGS |
      @openssl.INIT_LOAD_CRYPTO_STRINGS
    if @openssl.init_ssl(ssl_opts) != 1 {
      fail("Failed to initialize OpenSSL")
    }
    let uv = @uv.Loop::new()
    let host : Bytes = "www.example.com"
    let port : Bytes = "443"
    let addr : Bytes = resolve(uv, host, port)
    let addr : String = @encoding.decode(addr, encoding=UTF8)
    let port : String = @encoding.decode(port, encoding=UTF8)
    let ssl_ctx = @openssl.SslCtx::new(@openssl.Tls::client_method())
    ssl_ctx.set_default_verify_paths()
    @async.with_event_loop(_ => {
      let addr = @socket.Addr::parse("\{addr}:\{port}")
      let tcp = @socket.TCP::new()
      defer tcp.close()
      tcp.connect(addr)
      let ssl = Ssl::new(ssl_ctx, tcp, host~)
      ssl.connect()
      ssl.write_all(request, 0, request.length())
      let response = @buffer.new()
      ssl.read_all(response)
      println(response.contents() |> @encoding.decode(encoding=UTF8))
    })
  } catch {
    error => println("Error: \{error}")
  }
}
