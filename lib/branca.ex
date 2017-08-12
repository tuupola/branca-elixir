defmodule Branca do
  @moduledoc """
  Documentation for Branca.
  """
  alias Salty.Aead.Xchacha20poly1305Ietf, as: Xchacha20

  @version 0xBA
  @alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  @base62 BaseX.prepare_module("Base62", @alphabet, 127)
  @key Application.get_env(:branca, :key)

  def encode(message) do
    nonce = generate_nonce()
    header = generate_header(nonce)
    {_status, ciphertext} = Xchacha20.encrypt(message, header, nil, nonce, @key)
    @base62.encode(header <> ciphertext)
  end

  def encode(message, timestamp) do
    nonce = generate_nonce()
    header = generate_header(nonce, timestamp)
    {_status, ciphertext} = Xchacha20.encrypt(message, header, nil, nonce, @key)
    @base62.encode(header <> ciphertext)
  end

  def encode(message, timestamp, nonce) do
    header = generate_header(nonce, timestamp)
    {_status, ciphertext} = Xchacha20.encrypt(message, header, nil, nonce, @key)
    @base62.encode(header <> ciphertext)
  end

  def decode(token) do
    "Hello world!"
  end

  defp generate_header(nonce) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    generate_header(nonce, timestamp)
  end

  defp generate_header(nonce, timestamp) do
    timestamp = timestamp |> :binary.encode_unsigned(:big)

    <<@version>> <> timestamp <> nonce
  end

  defp generate_nonce do
    {_status, binary} = Salty.Random.buf(Xchacha20.npubbytes())
    binary
  end
end

