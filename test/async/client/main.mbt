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
let request : Bytes = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"

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
      let ssl = @ssl.Ssl::new(ssl_ctx, tcp)
      if ssl.ssl.set_tlsext_host_name(host) != 1 {
        fail("Failed to set TLS SNI hostname")
      }
      if ssl.ssl.set1_host(host) != 1 {
        fail("Failed to set TLS host")
      }
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
