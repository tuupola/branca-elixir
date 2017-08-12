defmodule Branca.Mixfile do
  use Mix.Project

  def project do
    [
      app: :branca,
      version: "0.0.1",
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
      {:salty, "~> 0.1.1", hex: :libsalty},
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
        "Spec" => "https://github.com/tuupola/branca-spec"
      }
    ]
  end
end
