defmodule Branca.Mixfile do
  use Mix.Project

  def project do
    [
      app: :branca,
      version: "0.2.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      name: "Branca",
      source_url: "https://github.com/tuupola/branca-elixir"
    ]
  end

  def application do
    []
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:libsalty2, "~> 0.3.0"},
      {:basex, "~> 1.0"},
      {:ex_doc, "~> 0.16.2", only: :dev}
    ]
  end

  defp description do
    """
    Authenticated Encrypted API Tokens (IETF XChaCha20-Poly1305 AEAD)
    """
  end

  defp package do
    [
      name: :branca,
      files: ["lib", "mix.exs", "README*", "LICENSE*"],
      maintainers: ["Mika Tuupola"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/tuupola/branca-elixir",
        "Specification" => "https://github.com/tuupola/branca-spec"
      }
    ]
  end
end
