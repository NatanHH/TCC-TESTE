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

  // ✅ Estado para indicar modo teste (professor testando sem salvar)
  const [isTestMode, setIsTestMode] = useState<boolean>(false);

  // ✅ OTIMIZAÇÃO: Cache de instâncias para reduzir latência
  const [instanceCache, setInstanceCache] = useState<InstancePayload[]>([]);

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
      // ✅ OTIMIZAÇÃO: Usar cache se disponível (latência ~0ms)
      if (instanceCache.length > 0) {
        const cached = instanceCache[0];
        setInstanceCache((prev) => prev.slice(1));
        setPayload(cached);
        setLoading(false);
        return;
      }

      // Fetch normal
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

      // ✅ OTIMIZAÇÃO: Pre-fetch próximas 3 instâncias em background
      Promise.all([
        fetch(fetchEndpoint).then((r) => (r.ok ? r.json() : null)),
        fetch(fetchEndpoint).then((r) => (r.ok ? r.json() : null)),
        fetch(fetchEndpoint).then((r) => (r.ok ? r.json() : null)),
      ])
        .then((instances) => {
          const valid = instances.filter(
            (i) => i !== null
          ) as InstancePayload[];
          setInstanceCache(valid);
        })
        .catch((err) => {
          console.warn("Pre-fetch failed:", err);
        });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("fetchInstance error:", msg);
      setError(msg || "Não foi possível carregar a instância.");
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmitAttempt() {
    // ✅ OTIMIZAÇÃO: Prevenir múltiplos cliques (spam)
    if (saving) return;

    if (!payload || selectedId === null) {
      alert("Escolha uma alternativa antes de enviar.");
      return;
    }
    setSaving(true);
    try {
      const selected = payload.instance.alternatives.find(
        (a) => a.id === selectedId
      );
      const payloadToSend = {
        idAtividade: atividadeId ?? null,
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

      // ✅ Detectar modo teste
      const testMode = !!(
        j &&
        typeof j === "object" &&
        (j as Record<string, unknown>).testMode === true
      );
      setIsTestMode(testMode);

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

  const total = useMemo(
    () => respostas.reduce((s, r) => s + (r.contador ?? 0), 0),
    [respostas]
  );

  if (loading)
    return <div style={{ color: "#fff" }}>Carregando atividade...</div>;
  if (error) return <div style={{ color: "salmon" }}>{error}</div>;
  if (!payload && loading)
    return <div style={{ color: "#fff" }}>Carregando atividade...</div>;

  // ✅ Se não houver atividade definida, não mostrar seleção (alunos sempre recebem atividadeId)
  if (atividadeId == null) {
    return (
      <div
        style={{ maxWidth: 680, margin: "0 auto", padding: 20, color: "#fff" }}
      >
        <div style={{ color: "#cfc6e6" }}>
          Atividade não disponível. Entre em contato com seu professor.
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
          <div style={{ marginTop: 8 }}>
            Calcule o valor decimal correspondente e escolha a alternativa
            correta.
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
              <div style={{ textAlign: "left" }}>
                <div
                  style={{
                    fontSize: 13,
                    color: showCorrect || showWrong ? "#042027" : "#cfc6e6",
                  }}
                >
                  {alt.label}
                </div>
                <div style={{ fontSize: 18 }}>{alt.value}</div>
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
            {/* ✅ Indicador de modo teste */}
            {isTestMode && (
              <span
                style={{
                  marginLeft: 12,
                  fontSize: "0.85em",
                  color: "#ff9800",
                  backgroundColor: "rgba(255, 152, 0, 0.1)",
                  padding: "2px 8px",
                  borderRadius: 4,
                  border: "1px solid #ff9800",
                }}
              >
                (Modo Teste - Não Salvo)
              </span>
            )}
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
