defmodule BlsEx.Native do
  @moduledoc false

  @version Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :bls_ex,
    crate: "bls",
    base_url: "https://github.com/archethic-foundation/bls_ex/releases/download/#{@version}",
    force_build: System.get_env("BLS_EX_BUILD") in ["1", "true"],
    targets:
      Enum.uniq(["aarch64-unknown-linux-musl" | RustlerPrecompiled.Config.default_targets()]),
    version: @version

  def get_public_key(_secret_key), do: :erlang.nif_error(:nif_not_loaded)
  def sign(_secret_key, _data), do: :erlang.nif_error(:nif_not_loaded)
  def verify_signature(_public_key, _message, _signature), do: :erlang.nif_error(:nif_not_loaded)
  def aggregate_signatures(_signatures, _public_keys), do: :erlang.nif_error(:nif_not_loaded)
  def aggregate_public_keys(_public_keys), do: :erlang.nif_error(:nif_not_loaded)
end
