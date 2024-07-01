defmodule BlsEx.StandaloneWasm do
  @moduledoc false
  use GenServer

  @wasm_path Application.compile_env!(:bls_ex, :wasm_path)

  def start_link(arg \\ []) do
    GenServer.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @doc """
  Verifies a BLS signature
  """
  @spec verify_signature(public_key :: binary(), message :: binary(), signature :: binary()) ::
          {:ok, boolean()} | {:error, any()}
  def verify_signature(public_key, message, signature) do
    GenServer.call(__MODULE__, {:verify, public_key, message, signature})
  end

  @doc """
  Aggregate BLS signatures
  """
  @spec aggregate_signatures(signatures :: list(binary()), public_keys :: list(binary())) ::
          {:ok, binary()} | {:error, any()}
  def aggregate_signatures(signatures, public_keys) do
    GenServer.call(__MODULE__, {:aggregate_signatures, signatures, public_keys})
  end

  @doc """
  Aggregate BLS public keys
  """
  @spec aggregated_public_keys(public_keys :: list(binary())) ::
          {:ok, binary()} | {:error, any()}
  def aggregated_public_keys(public_keys) do
    GenServer.call(__MODULE__, {:aggregate_public_keys, public_keys})
  end

  @doc """
  Verifies an aggregated BLS signature
  """
  @spec verify_aggregated_signature(list(binary()), binary(), binary()) ::
          {:ok, boolean()} | {:error, any()}
  def verify_aggregated_signature(public_keys, message, signature) do
    GenServer.call(__MODULE__, {:verify_aggregated_signature, public_keys, message, signature})
  end

  def init(_arg) do
    bytes = File.read!(@wasm_path) |> Base.encode64()

    manifest = %{
      wasm: [
        %{
          data: bytes
        }
      ]
    }

    {:ok, plugin} = Extism.Plugin.new(manifest)
    {:ok, %{plugin: plugin}}
  end

  def handle_call(
        {:verify, public_key, message, signature},
        _from,
        state = %{plugin: plugin}
      ) do
    case Extism.Plugin.call(
           plugin,
           "verifySignature",
           Jason.encode!(%{
             public_key: Base.encode16(public_key),
             data: message,
             signature: Base.encode16(signature)
           })
         ) do
      {:ok, "true"} ->
        {:reply, {:ok, true}, state}

      {:ok, "false"} ->
        {:reply, {:ok, false}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(
        {:aggregate_signatures, signatures, public_keys},
        _from,
        state = %{plugin: plugin}
      ) do
    case Extism.Plugin.call(
           plugin,
           "aggregateSignatures",
           Jason.encode!(%{
             signatures: Enum.map(signatures, &Base.encode16/1),
             public_keys: Enum.map(public_keys, &Base.encode16/1)
           })
         ) do
      {:ok, aggregate_signature} ->
        {:reply, {:ok, Base.decode16!(aggregate_signature, case: :mixed)}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(
        {:aggregate_public_keys, public_keys},
        _from,
        state = %{plugin: plugin}
      ) do
    case Extism.Plugin.call(
           plugin,
           "aggregatePublicKeys",
           Jason.encode!(%{
             public_keys: Enum.map(public_keys, &Base.encode16/1)
           })
         ) do
      {:ok, aggregated_public_keys} ->
        {:reply, {:ok, aggregated_public_keys}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(
        {:verify_aggregated_signature, public_keys, message, signature},
        _from,
        state = %{plugin: plugin}
      ) do
    case Extism.Plugin.call(
           plugin,
           "verifyAggregatedSignature",
           Jason.encode!(%{
             data: message,
             signature: Base.encode16(signature),
             public_keys: Enum.map(public_keys, &Base.encode16/1)
           })
         ) do
      {:ok, "true"} ->
        {:reply, {:ok, true}, state}

      {:ok, "false"} ->
        {:reply, {:ok, false}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end
end
