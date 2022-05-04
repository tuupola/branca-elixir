defmodule BrancaTest do
  use ExUnit.Case
  # doctest Branca, except: [:moduledoc, encode: 1, encode: 2, encode: 3]

  @token "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"
  @forged "87x8H26DuLJfzToSrJwLLUnritpp2nUQe2bgoiUbx3wGWGbfNibpJOLqNqjvfsIMkKnqClPeJtFp6"
  @version "8AenkwdktKeVVe9e6uIEi0GwL72HMrPF3cFRsqF2DtxJYb0EZ1jDxdu40XgLY6swS9HleC2oAwvn4"

  @nonce String.duplicate(
           <<0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C>>,
           2
         )
  @payload "Hello world!"

  test "Should encode payload" do
    {:ok, token} = Branca.encode(@payload)
    assert Branca.decode(token) == {:ok, @payload}

    token = Branca.encode!(@payload)
    assert Branca.decode!(token) == @payload
  end

  test "Should encode payload and timestamp" do
    {:ok, token} = Branca.encode(@payload, timestamp: 123_206_400)
    assert Branca.decode(token) == {:ok, @payload}

    token = Branca.encode!(@payload, timestamp: 123_206_400)
    assert Branca.decode!(token) == @payload
  end

  test "Should encode and decode payload, timestamp and nonce" do
    assert Branca.encode(@payload, timestamp: 123_206_400, nonce: @nonce) == {:ok, @token}
    assert Branca.decode(@token) == {:ok, @payload}

    assert Branca.encode!(@payload, timestamp: 123_206_400, nonce: @nonce) == @token
    assert Branca.decode!(@token) == @payload
  end

  test "Should fail with expired" do
    assert Branca.encode(@payload, timestamp: 123_206_400, nonce: @nonce) == {:ok, @token}
    assert Branca.decode(@token, %{:ttl => 3600}) == {:error, :expired}

    assert_raise RuntimeError, "Token is expired.", fn ->
      Branca.decode!(@token, %{:ttl => 3600})
    end
  end

  test "Should encode with ttl" do
    {:ok, token} = Branca.encode(@payload)
    assert Branca.decode(token, %{:ttl => 3600}) == {:ok, @payload}
    assert Branca.decode!(token, %{:ttl => 3600}) == @payload
  end

  test "Should fail with forged token" do
    assert Branca.decode(@forged, nonce: @nonce) == {:error, :forged}

    assert_raise RuntimeError, "Invalid token.", fn ->
      Branca.decode!(@forged, nonce: @nonce) == {:error, :forged}
    end
  end

  test "Should fail with wrong wrong version" do
    assert Branca.decode(@version) == {:error, :unknown_version}

    assert_raise RuntimeError, "Unknown token version.", fn ->
      Branca.decode!(@version) == {:error, :unknown_version}
    end
  end

  test "Should fail with invalid nonce" do
    assert Branca.encode(@payload, nonce: "invalid") == {:error, :invalid_argument}

    assert_raise RuntimeError, "Invalid arguments passed to Libsodium.", fn ->
      Branca.encode!(@payload, nonce: "invalid") == {:error, :invalid_argument}
    end
  end
end
