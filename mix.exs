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
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:extism, "~> 1.0"},
      # {:jason, "~> 1.4"},
      {:stream_data, "~> 1.1", only: [:test]},
      {:ex_doc, "~> 0.34.1", only: :dev, runtime: false},
      {:benchee, "~> 1.3", only: :test},
      {:rustler, ">= 0.0.0", optional: true},
      {:rustler_precompiled, "~> 0.4"}
    ]
  end
end
