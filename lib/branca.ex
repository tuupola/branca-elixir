defmodule Branca do
  @moduledoc """
  Branca allows you to generate and verify encrypted API tokens (IETF
  XChaCha20-Poly1305 AEAD). [Branca specification](https://github.com/tuupola/branca-spec)
  defines the external format and encryption scheme of the token to help
  interoperability between userland implementations. Branca is closely based
  on [Fernet](https://github.com/fernet/spec/blob/master/Spec.md).

  Payload in Branca token is an arbitrary sequence of bytes. This means
  payload can be for example a JSON object, plain text string or even binary
  data serialized by [MessagePack](http://msgpack.org/) or [Protocol Buffers](https://developers.google.com/protocol-buffers/).
  """
  alias Salty.Aead.Xchacha20poly1305Ietf, as: Xchacha20
  alias Branca.Token, as: Token

  @version 0xBA
  @alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  @base62 BaseX.prepare_module("Base62", @alphabet, 127)
  @key Application.get_env(:branca, :key)

  @doc """
  Returns base62 encoded encrypted token with given payload.

  by default Token will use current timestamp and generated random nonce. This
  is what you almost always want to use.

      iex> token = Branca.encode("Hello world!")
      875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a

  Optionally you can pass `timestamp` and `nonce`. You could for example opt-out
  from sending `timestamp` by setting it to `0`. Clock skew can be adjusted by setting
  the timestamp few seconds to future.

      iex> token = Branca.encode("Hello world!", timestamp: 123206400)
      875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a

  Manual `nonce` is mostly used for unit testing. If you generate `nonce` yourself
  make sure not to reuse the it between tokens.

      iex> nonce = Salty.Random.buf(24)
      iex> token = Branca.encode("Hello world!", timestamp: 123206400, nonce: nonce)
      87x85fNayA1e3Zd0mv0nJao0QE3oNUGTuj9gVdEcrX4RKMQ7a9VGziHec52jgMWYobXwsc4mrRM0A
  """
  def encode(payload, options \\ [])

  def encode(payload, options) when is_list(options) do
    encode(payload, Map.new(options))
  end

  def encode(payload, options) do
    %Token{payload: payload}
      |> add_timestamp(options)
      |> add_nonce(options)
      |> add_header
      |> seal
      |> base62_encode
  end

  @doc """
  Decrypts and verifies the token and returns the original payload on success.

      iex> token = Branca.encode("Hello world!");
      iex> Branca.decode(token)
      {:ok, "Hello world!"}

  Optionally you can make sure tokens are valid only `ttl` seconds after
  they have been generated or timestamped.

      iex> token = Branca.encode("Hello world!", timestamp: 123206400);
      iex> Branca.decode(token)
      {:ok, "Hello world!"}
      iex> Branca.decode(token, ttl: 60)
      {:error, :expired}
  """
  def decode(token, options \\ [])

  def decode(token, options) when is_list(options) do
    decode(token, Map.new(options))
  end

  def decode(token, %{:ttl => ttl}) when is_integer(ttl) do
    token = explode_token(token)
    {_, payload} = unseal(token)

    future = token.timestamp + ttl
    unixtime = DateTime.utc_now() |> DateTime.to_unix()

    cond do
      future < unixtime -> {:error, :expired}
      true -> {:ok, payload}
    end
  end

  def decode(token, %{}) do
    token = explode_token(token)

    cond do
      @version == token.version -> unseal(token)
      true -> {:error, :wrong_version}
    end
  end

  defp add_timestamp(token, %{timestamp: timestamp}) when is_integer(timestamp) do
    timestamp = :binary.encode_unsigned(timestamp, :big)
    %Token{token | timestamp: timestamp}
  end

  defp add_timestamp(token, %{}) do
    timestamp =
      DateTime.utc_now()
      |> DateTime.to_unix()
      |> :binary.encode_unsigned(:big)

    %Token{token | timestamp: timestamp}
  end

  defp add_nonce(token, %{nonce: nonce}) when is_binary(nonce) do
    %Token{token | nonce: nonce}
  end

  defp add_nonce(token, %{}) do
    {_, nonce} = Salty.Random.buf(Xchacha20.npubbytes())
    %Token{token | nonce: nonce}
  end

  defp add_header(token) do
    header = <<@version>> <> token.timestamp <> token.nonce
    %Token{token | header: header}
  end

  defp base62_decode(encoded) do
    binary = @base62.decode(encoded)
    %Token{binary: binary}
  end

  defp base62_encode(token) do
    @base62.encode(token.header <> token.ciphertext)
  end

  defp explode_binary(token) do
    %Token{binary: binary} = token
    << header::binary - size(29), data::binary >> = binary
    %Token{token | header: header, data: data}
  end

  defp explode_header(token) do
    %Token{header: header} = token
    << version::8, timestamp::32, nonce::binary - size(24) >> = header
    %Token{token | version: version, timestamp: timestamp, nonce: nonce}
  end

  defp explode_data(token) do
    %Token{data: data} = token
    size = byte_size(data) - 16
    << ciphertext::binary - size(size), tag::binary - size(16) >> = data
    %Token{token | ciphertext: ciphertext, tag: tag}
  end

  defp explode_token(encoded) do
    encoded
      |> base62_decode
      |> explode_binary
      |> explode_header
      |> explode_data
  end

  defp seal(token) do
    {_, ciphertext} = Xchacha20.encrypt(token.payload, token.header, nil, token.nonce, @key)
    %Token{token | ciphertext: ciphertext}
  end

  defp unseal(token) do
    Xchacha20.decrypt_detached(nil, token.ciphertext, token.tag, token.header, token.nonce, @key)
  end
end

