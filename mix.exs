defmodule BlsEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :bls_ex,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {BlsEx.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:extism, "~> 1.0"},
      {:jason, "~> 1.4"},
      {:stream_data, "~> 1.1", only: [:test]}
    ]
  end
end
