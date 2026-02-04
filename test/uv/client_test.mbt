///|
let request : Bytes = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"

///|
fn client_poll_read(
  poll : @uv.Poll,
  ssl : @openssl.Ssl,
  buffer : @buffer.Buffer,
  errors : Array[Error],
) -> Unit {
  let bytes = Bytes::make(4096, 0)
  let read = try ssl.read(bytes, 0, bytes.length()) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      return
    }
  } noraise {
    value => value
  }
  let ssl_error = try ssl.get_error(read) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      return
    }
  } noraise {
    value => value
  }
  match ssl_error {
    None => {
      poll.stop() catch {
        e => errors.push(e)
      }
      buffer.write_bytesview(bytes[:read])
    }
    WantRead =>
      poll.start(
        @uv.PollEvent::readable(),
        (_, _) => client_poll_read(poll, ssl, buffer, errors),
        (_, error) => errors.push(error),
      ) catch {
        error => errors.push(error)
      }
    WantWrite =>
      poll.start(
        @uv.PollEvent::writable(),
        (_, _) => client_poll_read(poll, ssl, buffer, errors),
        (_, error) => errors.push(error),
      ) catch {
        error => errors.push(error)
      }
    error => {
      errors.push(@builtin.Failure("SSL read error: \{error}"))
      poll.stop() catch {
        e => errors.push(e)
      }
    }
  }
}

///|
fn client_poll_connect(
  poll : @uv.Poll,
  ssl : @openssl.Ssl,
  errors : Array[Error],
) -> Unit {
  let connect_result = try ssl.connect() catch {
    error => {
      errors.push(error)
      return
    }
  } noraise {
    value => value
  }
  let ssl_error = try ssl.get_error(connect_result) catch {
    error => {
      errors.push(error)
      return
    }
  } noraise {
    value => value
  }
  match ssl_error {
    None => {
      println("SSL connect: None")
      poll.stop() catch {
        error => errors.push(error)
      }
    }
    WantRead => {
      println("SSL connect: WantRead")
      poll.start(
        @uv.PollEvent::readable(),
        (_, _) => client_poll_connect(poll, ssl, errors),
        (_, error) => errors.push(error),
      ) catch {
        error => errors.push(error)
      }
    }
    WantWrite => {
      println("SSL connect: WantWrite")
      poll.start(
        @uv.PollEvent::writable(),
        (_, _) => client_poll_connect(poll, ssl, errors),
        (_, error) => errors.push(error),
      ) catch {
        error => errors.push(error)
      }
    }
    error => errors.push(@builtin.Failure("SSL connect error: \{error}"))
  }
}

///|
fn resolve(uv : @uv.Loop, host : Bytes, port : Bytes) -> @uv.Sockaddr raise {
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
    fail("Failed to resolve address for \{host}:\{port}")
  }
  addr
}

///|
fn connect_tcp(uv : @uv.Loop, addr : @uv.Sockaddr) -> @uv.Tcp raise @uv.Errno {
  let client = @uv.Tcp::new(uv)
  let errors : Array[@uv.Errno] = []
  client.connect(addr, () => (), error => errors.push(error)) |> ignore()
  uv.run(Default)
  for error in errors {
    raise error
  }
  client
}

///|
fn setup_ssl_ctx() -> @openssl.SslCtx raise {
  let ctx = @openssl.SslCtx::new(@openssl.Tls::client_method())
  ctx.set_default_verify_paths()
  ctx
}

///|
fn client_connect_ssl(
  uv : @uv.Loop,
  ctx : @openssl.SslCtx,
  tcp : @uv.Tcp,
  poll : @uv.Poll,
  host : Bytes,
) -> @openssl.Ssl raise {
  let tcp_os_sock = tcp.os_sock()
  let ssl = @openssl.Ssl::new(ctx)
  let result = ssl.set_fd(tcp_os_sock.to_int())
  println("SSL set fd result: \{result}")
  let result = ssl.set_tlsext_host_name(host)
  println("SSL set TLS extension host name result: \{result}")
  let result = ssl.set1_host(host)
  println("SSL set 1 host result: \{result}")
  match ssl.get_error(ssl.connect()) {
    WantRead => {
      println("SSL connect: WantRead")
      let errors = []
      poll.start(
        @uv.PollEvent::readable(),
        (_, _) => client_poll_connect(poll, ssl, errors),
        (_, error) => errors.push(error),
      )
      uv.run(Default)
      for error in errors {
        raise error
      }
    }
    WantWrite => {
      println("SSL connect: WantWrite")
      let errors = []
      poll.start(
        @uv.PollEvent::writable(),
        (_, _) => client_poll_connect(poll, ssl, errors),
        (_, error) => errors.push(error),
      )
      uv.run(Default)
      for error in errors {
        raise error
      }
    }
    error => fail("SSL connect error: \{error}")
  }
  ssl
}

///|
fn client_poll_write(
  poll : @uv.Poll,
  ssl : @openssl.Ssl,
  buf : BytesView,
  errors : Array[Error],
) -> Unit {
  let written = try ssl.write(buf.data(), buf.start_offset(), buf.length()) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      return
    }
  } noraise {
    value => value
  }
  println("SSL write: \{written}")
  let ssl_error = try ssl.get_error(written) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      return
    }
  } noraise {
    value => value
  }
  match ssl_error {
    None if written == buf.length() =>
      poll.stop() catch {
        error => errors.push(error)
      }
    WantWrite | None => ()
    error => {
      errors.push(@builtin.Failure("SSL write error: \{error}"))
      poll.stop() catch {
        error => errors.push(error)
      }
    }
  }
}

///|
fn client_ssl_write_all(
  uv : @uv.Loop,
  ssl : @openssl.Ssl,
  buf : BytesView,
  poll : @uv.Poll,
) -> Unit raise {
  let written = ssl.write(buf.data(), buf.start_offset(), buf.length())
  println("SSL written: \{written}")
  match ssl.get_error(written) {
    None if written == buf.length() => return
    WantWrite => {
      println("SSL write: WantWrite")
      let errors = []
      poll.start(
        @uv.PollEvent::writable(),
        (_, _) => client_poll_write(poll, ssl, buf, []),
        (_, error) => errors.push(error),
      )
      uv.run(Default)
      for error in errors {
        raise error
      }
    }
    WantRead => {
      println("SSL write: WantRead")
      let errors = []
      poll.start(
        @uv.PollEvent::readable(),
        (_, _) => client_poll_write(poll, ssl, buf, []),
        (_, error) => errors.push(error),
      )
      uv.run(Default)
      for error in errors {
        raise error
      }
    }
    error => fail("SSL write error: \{error}")
  }
}

///|
fn client_ssl_read_all(
  uv : @uv.Loop,
  ssl : @openssl.Ssl,
  buf : @buffer.Buffer,
  poll : @uv.Poll,
) -> Unit raise {
  let errors = []
  let bytes = Bytes::make(4096, 0)
  let read = ssl.read(bytes, 0, bytes.length())
  match ssl.get_error(read) {
    None => buf.write_bytesview(bytes[:read])
    WantRead =>
      poll.start(
        @uv.PollEvent::readable(),
        (_, _) => client_poll_read(poll, ssl, buf, errors),
        (_, error) => errors.push(error),
      )
    WantWrite =>
      poll.start(
        @uv.PollEvent::writable(),
        (_, _) => client_poll_read(poll, ssl, buf, errors),
        (_, error) => errors.push(error),
      )
    error => {
      errors.push(@builtin.Failure("SSL read error: \{error}"))
      poll.stop() catch {
        error => errors.push(error)
      }
    }
  }
  uv.run(Default)
  for error in errors {
    raise error
  }
}

///|
fn run_client_test() -> Unit raise {
  let uv = @uv.Loop::new()
  let host : Bytes = "www.example.com"
  let port : Bytes = "443"
  let addr = resolve(uv, host, port)
  let tcp = connect_tcp(uv, addr)
  if @openssl.init_ssl(
      @openssl.INIT_LOAD_SSL_STRINGS | @openssl.INIT_LOAD_CRYPTO_STRINGS,
    ) !=
    1 {
    println("Failed to initialize OpenSSL")
    return
  }
  println("OpenSSL initialized successfully")
  let ctx = setup_ssl_ctx()
  defer ignore(try? ctx.free())
  let poll = @uv.Poll::socket(uv, tcp.os_sock())
  let ssl = client_connect_ssl(uv, ctx, tcp, poll, host)
  defer ignore(try? ssl.free())
  println("SSL connect completed")
  client_ssl_write_all(uv, ssl, request, poll)
  println("SSL write completed")
  let buffer = @buffer.new()
  client_ssl_read_all(uv, ssl, buffer, poll)
  let string = @encoding/utf8.decode_lossy(buffer.contents())
  println("Response: \{string}")
  poll.close(() => ())
  tcp.close(() => ())
  uv.run(Default)
  uv.close()
}

///|
test {
  run_client_test() catch {
    error => fail("Client SSL test failed: \{error}")
  }
}
