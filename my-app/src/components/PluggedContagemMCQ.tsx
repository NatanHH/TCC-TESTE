"use client";
import React, { useEffect, useState, useMemo } from "react";

type Alternative = {
  id: string;
  label: string;
  value: number;
  correct?: boolean;
};

type Instance = {
  cards: number[];
  bits: number[];
  decimal: number;
  alternatives: Alternative[];
  seed?: number;
};

type InstancePayload = {
  meta: {
    titulo: string;
    descricao?: string;
    tipo?: string;
    isStatic?: boolean;
    source?: string;
  };
  instance: Instance;
};

type RespostaContagem = {
  alternativa: string;
  contador: number;
};

type Props = {
  // tornar `respostas` opcional para corresponder a importações dinâmicas/usos
  respostas?: RespostaContagem[];
  fetchEndpoint?: string;
  saveEndpoint?: string;
  autoSave?: boolean; // default false: student must click "Enviar atividade"
  initialLoad?: boolean;
  alunoId?: number | null;
  atividadeId?: number | null;
  turmaId?: number | null;
};

export default function PluggedContagemMCQ({
  fetchEndpoint = "/api/atividades/plugged/contagem-instance",
  saveEndpoint = "/api/respostas/plugged",
  autoSave = false,
  initialLoad = true,
  alunoId = null,
  atividadeId = null,
  turmaId = null,
  respostas = [],
}: Props) {
  const [payload, setPayload] = useState<InstancePayload | null>(null);
  const [loading, setLoading] = useState<boolean>(!!initialLoad);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [answered, setAnswered] = useState(false);
  const [score, setScore] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [lastCorrectValue, setLastCorrectValue] = useState<number | null>(null);
  const [derivedAtividadeId, setDerivedAtividadeId] = useState<number | null>(
    null
  );
  const [availableAtividades, setAvailableAtividades] = useState<
    { idAtividade: number; titulo: string }[] | null
  >(null);
  const [loadingAtividades, setLoadingAtividades] = useState(false);

  useEffect(() => {
    if (initialLoad) fetchInstance();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function fetchInstance() {
    setLoading(true);
    setError(null);
    setSelectedId(null);
    setAnswered(false);
    setScore(null);
    setLastCorrectValue(null);
    try {
      const r = await fetch(fetchEndpoint);
      if (!r.ok) {
        const text = await r.text().catch(() => "");
        throw new Error(`HTTP ${r.status} ${text}`);
      }
      const body = (await r.json().catch(() => null)) as unknown;
      if (!body || typeof body !== "object") {
        throw new Error("Resposta inválida do servidor");
      }
      setPayload(body as InstancePayload);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("fetchInstance error:", msg);
      setError(msg || "Não foi possível carregar a instância.");
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmitAttempt() {
    if (!payload || selectedId === null) {
      return;
    }
    setSaving(true);
    try {
      const selected = payload.instance.alternatives.find(
        (a) => a.id === selectedId
      );
      const payloadToSend = {
        // use derivedAtividadeId as fallback quando a prop não for fornecida
        idAtividade: atividadeId ?? derivedAtividadeId ?? null,
        idAluno: alunoId ?? null,
        idTurma: turmaId ?? null,
        seed: payload.instance.seed ?? null,
        selectedValue: selected?.value,
      };

      if (!payloadToSend.idAtividade) {
        alert(
          "Erro: id da atividade não definido. Selecione uma atividade antes de enviar."
        );
        setSaving(false);
        return;
      }

      const r = await fetch(saveEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payloadToSend),
      });
      const j = (await r.json().catch(() => null)) as unknown;
      if (!r.ok) {
        const errMsg =
          j && typeof j === "object"
            ? String(
                (j as Record<string, unknown>).error ??
                  (j as Record<string, unknown>).message ??
                  `HTTP ${r.status}`
              )
            : `HTTP ${r.status}`;
        console.error("save response error body:", errMsg);
        throw new Error(errMsg);
      }

      // show result briefly then generate a new instance automatically
      setAnswered(true);
      setScore(
        j && typeof j === "object" && (j as Record<string, unknown>).correta
          ? 1
          : 0
      );
      setLastCorrectValue(
        j &&
          typeof j === "object" &&
          "correctValue" in (j as Record<string, unknown>)
          ? ((j as Record<string, unknown>).correctValue as number)
          : payload.instance.decimal ?? null
      );

      // allow student to see result for a short moment, then load a fresh instance
      setTimeout(async () => {
        await fetchInstance();
      }, 1200);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("submit attempt error:", msg);
      alert(msg || "Erro ao enviar tentativa.");
    } finally {
      setSaving(false);
    }
  }

  // selection only marks choice (no autosave on select)
  function handleSelect(alt: Alternative) {
    if (answered) return;
    setSelectedId(alt.id);
    // if autoSave prop is true (rare), trigger submit immediately
    if (autoSave) {
      // fire-and-forget
      void handleSubmitAttempt();
    }
  }

  useEffect(() => {
    // se não temos atividadeId nem conseguimos derivar, carregue lista para seleção manual
    if ((atividadeId ?? derivedAtividadeId) == null) {
      setLoadingAtividades(true);
      void fetch("/api/atividades")
        .then((r) => (r.ok ? r.json() : Promise.reject(r)))
        .then((j: unknown) => {
          // adapte ao shape real do seu endpoint; aqui assumimos array { idAtividade, titulo }
          if (Array.isArray(j)) {
            setAvailableAtividades(
              j as { idAtividade: number; titulo: string }[]
            );
          } else if (
            j &&
            typeof j === "object" &&
            Array.isArray((j as Record<string, unknown>).atividades)
          ) {
            setAvailableAtividades(
              (j as Record<string, unknown>).atividades as {
                idAtividade: number;
                titulo: string;
              }[]
            );
          } else {
            setAvailableAtividades([]);
          }
        })
        .catch((e: unknown) => {
          const msg = e instanceof Error ? e.message : String(e);
          console.warn("failed to load atividades list:", msg);
          setAvailableAtividades([]);
        })
        .finally(() => setLoadingAtividades(false));
    }
  }, [atividadeId, derivedAtividadeId]);

  // helper para quando usuário escolhe uma atividade manualmente
  function escolherAtividade(id: number) {
    setDerivedAtividadeId(id);
    // opcional: recarregar instância agora que temos atividadeId
    void fetchInstance();
  }

  const total = useMemo(
    () => respostas.reduce((s, r) => s + (r.contador ?? 0), 0),
    [respostas]
  );

  if (loading)
    return <div style={{ color: "#fff" }}>Carregando atividade...</div>;
  if (error) return <div style={{ color: "salmon" }}>{error}</div>;
  if (!payload && loading)
    return <div style={{ color: "#fff" }}>Carregando atividade...</div>;

  // se não houver atividade definida ainda, renderiza caixa de seleção para escolher
  if ((atividadeId ?? derivedAtividadeId) == null) {
    return (
      <div
        style={{ maxWidth: 680, margin: "0 auto", padding: 20, color: "#fff" }}
      >
        <h3>Selecione a atividade</h3>
        {loadingAtividades && <div>Carregando atividades...</div>}
        {!loadingAtividades &&
          availableAtividades &&
          availableAtividades.length === 0 && (
            <div>
              Nenhuma atividade disponível. Peça ao professor para criar ou
              associe a turma/atividade.
            </div>
          )}
        {!loadingAtividades &&
          availableAtividades &&
          availableAtividades.length > 0 && (
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <select
                onChange={(e) => {
                  const v = Number(e.target.value);
                  if (!Number.isNaN(v)) escolherAtividade(v);
                }}
                defaultValue=""
                style={{ padding: 8, borderRadius: 6 }}
              >
                <option value="" disabled>
                  Escolha uma atividade...
                </option>
                {availableAtividades.map((a) => (
                  <option key={a.idAtividade} value={a.idAtividade}>
                    {a.titulo} (id:{a.idAtividade})
                  </option>
                ))}
              </select>
              <button
                onClick={() => {
                  // se quiser recarregar lista manualmente
                  setLoadingAtividades(true);
                  void fetch("/api/atividades")
                    .then((r) => (r.ok ? r.json() : Promise.reject(r)))
                    .then((j: unknown) => {
                      if (Array.isArray(j)) {
                        setAvailableAtividades(
                          j as { idAtividade: number; titulo: string }[]
                        );
                      } else if (
                        j &&
                        typeof j === "object" &&
                        Array.isArray((j as Record<string, unknown>).atividades)
                      ) {
                        setAvailableAtividades(
                          (j as Record<string, unknown>).atividades as {
                            idAtividade: number;
                            titulo: string;
                          }[]
                        );
                      } else {
                        setAvailableAtividades([]);
                      }
                    })
                    .catch((e: unknown) => {
                      const msg = e instanceof Error ? e.message : String(e);
                      console.warn("failed to load atividades list:", msg);
                      setAvailableAtividades([]);
                    })
                    .finally(() => setLoadingAtividades(false));
                }}
                className="btn"
                type="button"
              >
                Atualizar lista
              </button>
            </div>
          )}
        <div style={{ marginTop: 12, color: "#cfc6e6" }}>
          Se você é professor: passe atividadeId e turmaId ao componente ao
          renderizá-lo.
        </div>
      </div>
    );
  }

  if (!payload) return null;
  const { meta, instance } = payload;
  const { cards, bits, decimal, alternatives } = instance;

  return (
    <div
      style={{
        maxWidth: 840,
        margin: "0 auto",
        background: "#352846",
        padding: 20,
        borderRadius: 12,
        color: "#fff",
        boxShadow: "0 20px 40px rgba(0,0,0,0.6)",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 12,
        }}
      >
        <div>
          <h3 style={{ margin: 0 }}>{meta.titulo}</h3>
          {meta.isStatic && (
            <span
              style={{
                background: "#ff9800",
                color: "#042027",
                padding: "4px 8px",
                borderRadius: 6,
                marginLeft: 8,
                fontWeight: 700,
              }}
            >
              Estática
            </span>
          )}
          <div style={{ marginTop: 8, color: "#cfc6e6", fontSize: 14 }}>
            {meta.descricao}
          </div>
        </div>
        <div style={{ textAlign: "right", color: "#cfc6e6" }}>
          <div style={{ fontSize: 12 }}>Seed</div>
          <div style={{ fontWeight: 700 }}>{instance.seed ?? "-"}</div>
        </div>
      </div>

      <div style={{ marginTop: 16 }}>
        <div
          style={{
            display: "flex",
            gap: 12,
            justifyContent: "center",
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          {cards.map((val, idx) => {
            const on = bits[idx] === 1;
            return (
              <div
                key={idx}
                aria-hidden
                style={{
                  width: 84,
                  height: 84,
                  borderRadius: 10,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: on ? "#00bcd4" : "#2c2138",
                  color: on ? "#042027" : "#fff",
                  fontWeight: 700,
                  boxShadow: on
                    ? "inset 0 -6px 0 rgba(0,0,0,0.15)"
                    : "0 8px 18px rgba(0,0,0,0.35)",
                }}
              >
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 18 }}>{val}</div>
                  <div style={{ fontSize: 12, marginTop: 6 }}>
                    {on ? "1" : "0"}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ marginTop: 12, textAlign: "center", color: "#cfc6e6" }}>
          <div>
            Bits (esquerda → direita):{" "}
            <strong style={{ color: "#fff" }}>{bits.join("")}</strong>
          </div>
        </div>
      </div>

      <div
        style={{
          marginTop: 18,
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: 12,
        }}
      >
        {alternatives.map((alt) => {
          const chosen = selectedId === alt.id;
          const isCorrect = alt.correct || alt.value === decimal;
          const showCorrect = answered && isCorrect;
          const showWrong = answered && chosen && !isCorrect;
          return (
            <button
              key={alt.id}
              onClick={() => handleSelect(alt)}
              disabled={answered}
              style={{
                padding: "12px 14px",
                borderRadius: 8,
                background: showCorrect
                  ? "#8bc34a"
                  : showWrong
                  ? "#f44336"
                  : "#3a3360",
                color: showCorrect || showWrong ? "#042027" : "#fff",
                fontWeight: 700,
                border: chosen ? "2px solid #00bcd4" : "2px solid transparent",
                cursor: answered ? "default" : "pointer",
                minHeight: 56,
              }}
              aria-pressed={chosen}
            >
              <div style={{ textAlign: "center" }}>
                <div
                  style={{
                    fontSize: 24,
                    fontWeight: 700,
                    color: showCorrect || showWrong ? "#042027" : "#fff",
                  }}
                >
                  {alt.label}
                </div>
                <div style={{ fontSize: 18, marginTop: 4 }}>{alt.value}</div>
              </div>
            </button>
          );
        })}
      </div>

      <div
        style={{
          marginTop: 16,
          display: "flex",
          gap: 10,
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <button
          onClick={handleSubmitAttempt}
          disabled={saving || selectedId === null || answered}
          style={{
            padding: "8px 12px",
            borderRadius: 8,
            background:
              saving || selectedId === null || answered ? "#555" : "#2196f3",
            color: "#fff",
            border: "none",
            cursor:
              saving || selectedId === null || answered ? "default" : "pointer",
          }}
          className="btn"
          type="button"
        >
          Enviar atividade
        </button>

        {answered && (
          <div
            style={{
              color: score === 1 ? "#8bc34a" : "#f44336",
              fontWeight: 700,
            }}
          >
            {score === 1 ? "Correto ✓" : "Incorreto ✕"}
          </div>
        )}

        {answered && lastCorrectValue !== null && (
          <div style={{ color: "#cfc6e6" }}>
            Valor correto:{" "}
            <strong style={{ color: "#fff", marginLeft: 8 }}>
              {lastCorrectValue}
            </strong>
          </div>
        )}

        {saving && <div style={{ color: "#cfc6e6" }}>Enviando...</div>}
      </div>

      <div>
        <h3>Contagem MCQ</h3>
        <ul>
          {respostas.map((r) => (
            <li key={r.alternativa}>
              {r.alternativa} — {r.contador} (
              {total ? ((r.contador / total) * 100).toFixed(1) : "0"}%)
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
