defmodule Branca.Token do
  @moduledoc false

  defstruct binary: nil,
            header: nil,
            data: nil,
            version: nil,
            timestamp: nil,
            nonce: nil,
            ciphertext: nil,
            tag: nil,
            payload: nil
end
