defmodule BlsEx.Application do
  def start(_, _) do
    Supervisor.start_link(
      [
        BlsEx.StandaloneWasm
      ],
      strategy: :one_for_one,
      name: __MODULE__
    )
  end
end
