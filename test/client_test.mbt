///|
let request : Bytes = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"

///|
fn on_poll(
  poll : @uv.Poll,
  events : @uv.PollEvent,
  tcp : @uv.Tcp,
  ssl : @openssl.Ssl,
  errors : Array[Error],
  buffer : @buffer.T,
) -> Unit {
  if events.is_readable() {
    let bytes = Bytes::make(4096, 0)
    let read = ssl.read(bytes, 0, bytes.length())
    match ssl.get_error(read) {
      None => {
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.close(() => ())
        buffer.write_bytesview(bytes[:read])
        tcp.close(() => ())
      }
      WantRead => ()
      WantWrite => ()
      error => {
        println("SSL read error: \{error}")
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.close(() => ())
      }
    }
  } else if events.is_writable() {
    let written = ssl.write(request, 0, request.length())
    match ssl.get_error(written) {
      None => {
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.start(
          @uv.PollEvent::readable(),
          (_, events) => on_poll(poll, events, tcp, ssl, errors, buffer),
          (_, e) => errors.push(e),
        ) catch {
          e => errors.push(e)
        }
      }
      WantRead => ()
      WantWrite => ()
      error => {
        println("SSL read error: \{error}")
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.close(() => ())
      }
    }
  }
}

///|
fn client_poll_connect(
  poll : @uv.Poll,
  events : @uv.PollEvent,
  ssl : @openssl.Ssl,
  errors : Array[Error],
) -> Unit {
  if events.is_readable() || events.is_writable() {
    match ssl.get_error(ssl.connect()) {
      None => poll.stop() catch { error => errors.push(error) }
      WantRead =>
        poll.start(
          @uv.PollEvent::readable(),
          (_, events) => client_poll_connect(poll, events, ssl, errors),
          (_, error) => errors.push(error),
        ) catch {
          error => errors.push(error)
        }
      WantWrite =>
        poll.start(
          @uv.PollEvent::writable(),
          (_, events) => client_poll_connect(poll, events, ssl, errors),
          (_, error) => errors.push(error),
        ) catch {
          error => errors.push(error)
        }
      error => errors.push(Failure("SSL connect error: \{error}"))
    }
  }
}

///|
test {
  let uv = @uv.Loop::new()
  let host : Bytes = "www.example.com"
  let port : Bytes = "443"
  let hints = @uv.AddrInfoHints::new()
  let mut addr = None
  let _ = uv.getaddrinfo(
    infos => for info in infos {
      addr = Some(info.addr())
    },
    error => println("Error: \{(error : Error)}"),
    host,
    port,
    hints~,
  )
  uv.run(Default)
  guard addr is Some(addr) else {
    println("Failed to resolve address for \{host}:\{port}")
    return
  }
  let client = @uv.Tcp::new(uv)
  client.connect(addr, () => println("Connected to server"), error => println(
    "Connect error: \{(error : Error)}",
  ))
  |> ignore()
  uv.run(Default)
  if @openssl.init_ssl(
      @openssl.INIT_LOAD_SSL_STRINGS | @openssl.INIT_LOAD_CRYPTO_STRINGS,
    ) !=
    1 {
    println("Failed to initialize OpenSSL")
    return
  }
  println("OpenSSL initialized successfully")
  let store = @openssl.X509Store::new()
  {
    let bio = @openssl.Bio::new_mem_buf(
      @test.mozilla_ca_bundle,
      @test.mozilla_ca_bundle.length(),
    )
    defer ignore(bio.free())
    let cert = @openssl.Pem::read_bio_x509(bio)
    defer cert.free()
    store.add_cert(cert) |> ignore()
  }
  let method_ = @openssl.Tls::client_method()
  let ctx = @openssl.SslCtx::new(method_)
  defer ctx.free()
  ctx.set_default_verify_paths()
  let socket = client.os_sock()
  println("Socket created with fd: \{socket.to_int()}")
  let ssl = @openssl.Ssl::new(ctx)
  defer ssl.free()
  let result = ssl.set_fd(socket.to_int())
  println("SSL set fd result: \{result}")
  let result = ssl.set_tlsext_host_name(host)
  println("SSL set TLS extension host name result: \{result}")
  let result = ssl.set1_host(host)
  println("SSL set 1 host result: \{result}")
  let poller = @uv.Poll::socket(uv, socket)
  let errors = []
  match ssl.get_error(ssl.connect()) {
    WantRead => {
      println("SSL connect: WantRead")
      poller.start(
        @uv.PollEvent::readable(),
        (_, events) => client_poll_connect(poller, events, ssl, errors),
        (_, error) => errors.push(error),
      )
    }
    WantWrite => {
      println("SSL connect: WantRead")
      poller.start(
        @uv.PollEvent::writable(),
        (_, events) => client_poll_connect(poller, events, ssl, errors),
        (_, error) => errors.push(error),
      )
    }
    error => println("SSL connect error: \{error}")
  }
  uv.run(Default)
  println("SSL connect completed")
  let written = ssl.write(request, 0, request.length())
  println("SSL written: \{written}")
  let buffer = @buffer.new()
  match @openssl.Ssl::get_error(ssl, written) {
    None => {
      poller.start(
        @uv.PollEvent::readable() | @uv.PollEvent::writable(),
        (_, events) => on_poll(poller, events, client, ssl, errors, buffer),
        (_, e) => errors.push(e),
      )
      uv.run(Default)
      let string = @encoding.decode_lossy(buffer.contents(), encoding=UTF8)
      println("Response: \{string}")
      uv.close()
    }
    error => {
      println("SSL error: \{error}")
      return
    }
  }
}
