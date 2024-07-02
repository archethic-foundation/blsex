defmodule BlsEx do
  @moduledoc """
  BlsEx provides utility to leverage BLS signatures

  BLS scheme supports aggregation of public keys and aggregation of signatures.

  Here an full example of aggregated signature verification

      iex> seed = :crypto.hash(:sha512, "myseed")
      iex> public_key1 = BlsEx.get_public_key(seed)
      iex> signature1 = BlsEx.sign(seed, "hello")
      iex> seed2 = :crypto.hash(:sha512, "myseed2")
      iex> public_key2 = BlsEx.get_public_key(seed2)
      iex> signature2 = BlsEx.sign(seed2, "hello")
      iex> aggregated_signature = BlsEx.aggregate_signatures([signature1, signature2], [public_key1, public_key2])
      iex> aggregated_public_key = BlsEx.aggregate_public_keys([public_key1, public_key2])
      iex> BlsEx.verify_signature(aggregated_public_key, "hello", aggregated_signature)
      true
  """

  @version Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :bls_ex,
    crate: "bls",
    base_url: "https://github.com/archethic-foundation/bls_ex/releases/download/#{@version}",
    force_build: System.get_env("BLS_EX_BUILD") in ["1", "true"],
    targets:
      Enum.uniq(["aarch64-unknown-linux-musl" | RustlerPrecompiled.Config.default_targets()]),
    version: @version

  @type secret_key :: <<_::512>>
  @type signature :: <<_::96>>
  @type public_key :: <<_::48>>

  @doc """
  Generate a public key from a secret key
  """
  @spec get_public_key(secret_key :: secret_key()) :: public_key()
  def get_public_key(secret_key) when is_binary(secret_key) and byte_size(secret_key) == 512,
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Sign a message using the given secret key
  """
  @spec sign(secret_key :: secret_key(), message :: binary()) :: signature()
  def sign(secret_key, data)
      when is_binary(secret_key) and byte_size(secret_key) == 512 and is_binary(data),
      do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Verifies a single BLS signature
  """
  @spec verify_signature(
          public_key :: public_key(),
          message :: binary(),
          signature :: signature()
        ) ::
          boolean()
  def verify_signature(public_key, message, signature)
      when is_binary(public_key) and byte_size(public_key) == 48 and is_binary(message) and
             is_binary(signature) and byte_size(signature) == 96,
      do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Aggregate a list of signatures
  """
  @spec aggregate_signatures(list(signature()), list(public_key())) :: signature()
  def aggregate_signatures(signatures, public_keys)
      when is_list(signatures) and is_list(public_keys) and
             length(signatures) == length(public_keys),
      do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Aggregate a list of public keys
  """
  @spec aggregate_public_keys(list(public_key())) :: public_key()
  def aggregate_public_keys(public_keys) when is_list(public_keys),
    do: :erlang.nif_error(:nif_not_loaded)
end
