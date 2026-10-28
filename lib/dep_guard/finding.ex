defmodule DepGuard.Finding do
  @moduledoc """
  One result from a check.

  Findings are data, never printed by the check itself. `kind` decides whether the
  finding gates the build:

    * `:security` / `:integrity` / `:policy` - gate when the severity is at or
      above `--fail-on`
    * `:operational` - the check could not be completed; the CLI exits 2
    * `:notice` - informational only, never gates

  `severity: :unknown` is treated as `:high` when gating: an advisory whose
  severity cannot be read must not pass silently.
  """

  @enforce_keys [:check, :kind, :severity, :message]
  defstruct [
    :id,
    :check,
    :kind,
    :severity,
    :message,
    :package,
    :version,
    :remediation,
    :path,
    :rule,
    :waived,
    aliases: [],
    sources: []
  ]

  @type kind :: :security | :integrity | :policy | :operational | :notice
  @type severity :: :critical | :high | :medium | :low | :info | :unknown
  @type waiver :: map()
  @type t :: %__MODULE__{
          id: String.t() | nil,
          check: atom(),
          kind: kind(),
          severity: severity(),
          message: String.t(),
          package: String.t() | nil,
          version: String.t() | nil,
          remediation: String.t() | nil,
          path: String.t() | nil,
          rule: atom() | nil,
          waived: waiver() | nil,
          aliases: [String.t()],
          sources: [String.t()]
        }

  @doc "Builds a finding from a keyword list or map."
  @spec new(keyword() | map()) :: t()
  def new(attrs) do
    attrs = Map.new(attrs)

    %__MODULE__{
      id: attrs[:id],
      check: attrs[:check],
      kind: Map.get(attrs, :kind, :security),
      severity: attrs[:severity] || :unknown,
      message: attrs[:message],
      package: attrs[:package],
      version: attrs[:version],
      remediation: attrs[:remediation],
      path: attrs[:path],
      rule: attrs[:rule],
      waived: attrs[:waived],
      aliases: List.wrap(attrs[:aliases]),
      sources: List.wrap(attrs[:sources])
    }
  end

  @doc false
  @spec rank(severity()) :: 1..5
  def rank(:critical), do: 5
  def rank(:high), do: 4
  def rank(:unknown), do: 4
  def rank(:medium), do: 3
  def rank(:low), do: 2
  def rank(:info), do: 1

  @doc "True when the finding gates at the given threshold and is not waived."
  @spec gating?(t(), :any | :low | :medium | :high | :critical) :: boolean()
  def gating?(%__MODULE__{kind: :notice}, _threshold), do: false
  def gating?(%__MODULE__{kind: :operational}, _threshold), do: true
  def gating?(%__MODULE__{waived: waived}, _threshold) when not is_nil(waived), do: false
  def gating?(%__MODULE__{severity: severity}, threshold), do: rank(severity) >= threshold_rank(threshold)

  defp threshold_rank(:any), do: 1
  defp threshold_rank(:low), do: 2
  defp threshold_rank(:medium), do: 3
  defp threshold_rank(:high), do: 4
  defp threshold_rank(:critical), do: 5

  @doc "Parses severity strings from Hex/OSV/mix_audit sources."
  @spec severity_from_string(term()) :: severity()
  def severity_from_string(value) when is_binary(value) do
    case String.downcase(String.trim(value)) do
      "critical" -> :critical
      "high" -> :high
      "moderate" -> :medium
      "medium" -> :medium
      "low" -> :low
      "info" -> :info
      "informational" -> :info
      _ -> :unknown
    end
  end

  def severity_from_string(_other), do: :unknown

  @doc "Stable identity used for deduplication across sources."
  @spec key(t()) :: term()
  def key(%__MODULE__{id: id}) when is_binary(id) and id != "", do: {:advisory, id}

  def key(%__MODULE__{} = f) do
    {:other, f.check, f.package, f.version, f.message}
  end

  @doc """
  Merges a duplicate finding into an existing one: keeps the highest severity,
  unions aliases and sources, and keeps the first message/remediation.
  """
  @spec merge(t(), t()) :: t()
  def merge(%__MODULE__{} = a, %__MODULE__{} = b) do
    %{
      a
      | severity: max_severity(a.severity, b.severity),
        aliases: Enum.uniq(a.aliases ++ b.aliases),
        sources: Enum.uniq(a.sources ++ b.sources),
        remediation: a.remediation || b.remediation,
        waived: a.waived || b.waived
    }
  end

  defp max_severity(a, b), do: if(rank(a) >= rank(b), do: a, else: b)
end
