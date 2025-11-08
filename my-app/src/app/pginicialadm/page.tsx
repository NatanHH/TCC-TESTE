"use client";
import React, { useState, useEffect, ChangeEvent } from "react";
import styles from "./page.module.css";
import Image from "next/image";

/**
 * PainelAdm (com CRUD completo de Atividades e CRUD básico de Professores)
 *
 * - Lida com criação/edição/exclusão de atividades (PLUGGED/UNPLUGGED) e professores.
 * - Para criação UNPLUGGED usa /api/atividades/atividade-com-upload (multipart).
 * - Para atualizar arquivos de uma atividade existente usa /api/atividades/upload-files (multipart, replace=true).
 *
 * Cole este arquivo no lugar do seu painel ADM. Ajuste paths de API se necessário.
 */

type Professor = { idProfessor: number; nome: string; email: string };
type Alt = { texto: string; id?: number };

// --- new lightweight types (não alteram comportamento em runtime) ---
type ArquivoResumo = {
  idArquivo: number;
  url: string;
  nomeArquivo?: string | null;
  tipoArquivo?: string | null;
};

type Atividade = {
  idAtividade: number;
  titulo: string;
  descricao?: string | null;
  tipo?: string | null;
  nota?: number | null;
  script?: string | null;
  linguagem?: string | null;
  arquivos?: ArquivoResumo[];
  alternativas?: Alt[];
};

type AtividadePayload = {
  titulo: string;
  descricao?: string | null;
  tipo: string;
  nota?: number;
  script?: string | null;
  linguagem?: string | null;
  alternativas?: Alt[] | null;
};
// --- end new types ---

export default function PainelAdm() {
  // Professores
  const [professores, setProfessores] = useState<Professor[]>([]);
  const [funcaoSelecionada, setFuncaoSelecionada] = useState<string | null>(
    null
  );
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    nome: "",
    email: "",
    senha: "",
    confirmarSenha: "",
  });
  const [editingProfessor, setEditingProfessor] = useState<null | Professor>(
    null
  );
  const [editFormData, setEditFormData] = useState({
    nome: "",
    senha: "",
    confirmarSenha: "",
  });
  const [popupAberto, setPopupAberto] = useState(false);
  const [loading, setLoading] = useState(false);

  // Atividades
  const [atividades, setAtividades] = useState<Atividade[]>([]);
  const [loadingAtividades, setLoadingAtividades] = useState(false);
  const [formAtividade, setFormAtividade] = useState({
    titulo: "",
    descricao: "",
    tipo: "UNPLUGGED",
    nota: 10,
    script: "",
    linguagem: "assemblyscript",
  });
  const [arquivos, setArquivos] = useState<File[]>([]);
  const [arquivosPreviews, setArquivosPreviews] = useState<string[]>([]);

  // Edit mode for Activities
  const [editingAtividadeId, setEditingAtividadeId] = useState<number | null>(
    null
  );

  // Optionally let user decide whether new files replace existing ones (only relevant when editing)
  const [replaceFilesOnUpdate, setReplaceFilesOnUpdate] = useState(true);

  // ---------------------- Professores CRUD (frontend) ----------------------
  useEffect(() => {
    if (funcaoSelecionada === "Professores") fetchProfessores();
  }, [funcaoSelecionada, showForm, editingProfessor]);

  async function fetchProfessores() {
    setLoading(true);
    try {
      const res = await fetch("/api/professores/professor");
      const text = await res.text().catch(() => "");
      let data: unknown = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = null;
      }
      if (res.ok) {
        if (Array.isArray(data)) setProfessores(data as Professor[]);
        else if (data && typeof data === "object") {
          const maybe = data as Record<string, unknown>;
          if (Array.isArray(maybe.professores))
            setProfessores(maybe.professores as Professor[]);
          else setProfessores([]);
        } else setProfessores([]);
      } else {
        setProfessores([]);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("Erro fetching professores:", msg);
      setProfessores([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (formData.senha !== formData.confirmarSenha) {
      alert("As senhas não coincidem!");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/professores/professor", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nome: formData.nome,
          email: formData.email,
          senha: formData.senha,
        }),
      });
      const text = await res.text().catch(() => "");
      const data = (() => {
        try {
          return JSON.parse(text);
        } catch {
          return null;
        }
      })();
      if (res.ok) {
        alert("Professor criado!");
        setShowForm(false);
        setFormData({ nome: "", email: "", senha: "", confirmarSenha: "" });
        await fetchProfessores();
      } else {
        alert(data?.error || `Erro ao criar professor (status ${res.status}).`);
      }
    } catch (err) {
      console.error("Erro ao criar professor:", err);
      alert("Erro ao criar professor (ver console).");
    } finally {
      setLoading(false);
    }
  }

  async function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (editFormData.senha !== editFormData.confirmarSenha) {
      alert("As senhas não coincidem!");
      return;
    }
    try {
      const res = await fetch("/api/professores/professor", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          idProfessor: editingProfessor?.idProfessor,
          nome: editFormData.nome,
          senha: editFormData.senha,
        }),
      });
      const text = await res.text().catch(() => "");
      const data = (() => {
        try {
          return JSON.parse(text);
        } catch {
          return null;
        }
      })();
      if (res.ok) {
        alert("Professor atualizado!");
        setEditingProfessor(null);
        await fetchProfessores();
      } else {
        alert(data?.error || "Erro ao atualizar professor.");
      }
    } catch (err) {
      console.error("Erro ao atualizar professor:", err);
      alert("Erro ao atualizar professor.");
    }
  }

  async function handleExcluirProfessor(id: number) {
    if (!confirm("Tem certeza que deseja excluir este professor?")) return;
    try {
      const res = await fetch("/api/professores/professor", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idProfessor: id }),
      });
      const text = await res.text().catch(() => "");
      const data = (() => {
        try {
          return JSON.parse(text);
        } catch {
          return null;
        }
      })();
      if (res.ok) {
        await fetchProfessores();
      } else {
        alert(data?.error || "Erro ao excluir professor.");
      }
    } catch (err) {
      console.error("Erro ao excluir professor:", err);
      alert("Erro ao excluir professor.");
    }
  }

  function handleShowForm() {
    setShowForm(true);
    setFormData({ nome: "", email: "", senha: "", confirmarSenha: "" });
    setEditingProfessor(null);
  }

  // ---------------------- Atividades CRUD (frontend) ----------------------
  useEffect(() => {
    if (funcaoSelecionada === "Atividades") fetchAtividades();
  }, [funcaoSelecionada]);

  async function fetchAtividades() {
    setLoadingAtividades(true);
    try {
      const res = await fetch("/api/atividades");
      const text = await res.text().catch(() => "");
      let data: unknown = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = null;
      }
      if (res.ok) {
        if (Array.isArray(data)) setAtividades(data as Atividade[]);
        else if (data && typeof data === "object") {
          const maybe = data as Record<string, unknown>;
          if (Array.isArray(maybe.atividades))
            setAtividades(maybe.atividades as Atividade[]);
          else setAtividades([]);
        } else setAtividades([]);
      } else {
        setAtividades([]);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("Erro fetching atividades:", msg);
      setAtividades([]);
    } finally {
      setLoadingAtividades(false);
    }
  }

  function selecionarFuncao(funcao: string) {
    setFuncaoSelecionada(funcao);
    setShowForm(false);
    setEditingProfessor(null);
    setEditingAtividadeId(null);
  }

  function voltarMenu() {
    setFuncaoSelecionada(null);
    setShowForm(false);
    setEditingProfessor(null);
    setEditingAtividadeId(null);
  }

  function toggleUserPopup() {
    setPopupAberto((p) => !p);
  }

  // Atividade form handlers
  function handleFormAtividadeChange(
    e: React.ChangeEvent<
      HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
    >
  ) {
    setFormAtividade({ ...formAtividade, [e.target.name]: e.target.value });
  }

  function handleArquivosChange(e: ChangeEvent<HTMLInputElement>) {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      setArquivos(files);
      const previews = files.map((f) => URL.createObjectURL(f));
      setArquivosPreviews((prev) => {
        prev.forEach((u) => URL.revokeObjectURL(u));
        return previews;
      });
    }
  }

  // Start editing an existing activity - populates form with data
  function startEditAtividade(atividade: Atividade) {
    setEditingAtividadeId(atividade.idAtividade);
    setFormAtividade({
      titulo: atividade.titulo || "",
      descricao: atividade.descricao || "",
      tipo: atividade.tipo || "UNPLUGGED",
      nota: atividade.nota ?? 10,
      script: atividade.script ?? "",
      linguagem: atividade.linguagem ?? "assemblyscript",
    });
    // set previews for existing arquivos (URLs)
    const previews = (atividade.arquivos || []).map(
      (f: ArquivoResumo) => f.url
    );
    setArquivosPreviews(previews);
    setArquivos([]); // new files not selected yet
  }

  // Delete activity
  async function handleDeleteAtividade(id: number) {
    if (!confirm("Deseja realmente excluir esta atividade?")) return;
    try {
      // chama a rota dinâmica correta: /api/atividades/:id
      const res = await fetch(
        `/api/atividades/${encodeURIComponent(String(id))}`,
        {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
        }
      );
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        console.error("Erro ao deletar atividade:", res.status, data);
        alert(data?.error || "Erro ao deletar atividade. Veja console.");
        return;
      }
      alert("Atividade removida");
      fetchAtividades();
    } catch (err) {
      console.error("Erro ao deletar atividade:", err);
      alert("Erro ao deletar atividade. Veja console.");
    }
  }

  // Delete file associated to activity
  async function handleDeleteArquivo(idArquivo: number) {
    if (!confirm("Remover este arquivo?")) return;
    try {
      const res = await fetch(`/api/atividades/arquivo/${idArquivo}`, {
        method: "DELETE",
      });
      const text = await res.text().catch(() => "");
      if (!res.ok) {
        console.error("Erro ao deletar arquivo:", res.status, text);
        alert("Erro ao deletar arquivo. Veja console.");
        return;
      }
      alert("Arquivo removido");
      fetchAtividades();
    } catch (err) {
      console.error("Erro ao deletar arquivo:", err);
      alert("Erro ao deletar arquivo. Veja console.");
    }
  }

  // Submit handler: Create or Update activity
  async function handleFormAtividadeSubmit(
    e: React.FormEvent<HTMLFormElement>
  ) {
    e.preventDefault();

    // apenas UNPLUGGED suportado — sem validações de alternativas

    // payload for JSON operations
    const payload: AtividadePayload = {
      titulo: formAtividade.titulo,
      descricao: formAtividade.descricao,
      tipo: formAtividade.tipo,
      nota: formAtividade.nota,
      script: formAtividade.script || null,
      linguagem: formAtividade.linguagem || null,
    };

    try {
      if (editingAtividadeId) {
        // Update existing activity (PUT JSON)
        const res = await fetch(`/api/atividades/${editingAtividadeId}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...payload,
            alternativas: payload.alternativas,
          }),
        });
        const text = await res.text().catch(() => "");
        if (!res.ok) {
          console.error("Erro ao atualizar atividade:", res.status, text);
          alert("Erro ao atualizar atividade. Veja console.");
          return;
        }

        // If user selected new files, upload them and replace existing files on server
        if (arquivos.length > 0) {
          const fd = new FormData();
          fd.append("atividadeId", String(editingAtividadeId));
          fd.append("replace", replaceFilesOnUpdate ? "true" : "false");
          arquivos.forEach((f) => fd.append("arquivos", f));
          const upRes = await fetch("/api/atividades/upload-files", {
            method: "POST",
            body: fd,
          });
          const upText = await upRes.text().catch(() => "");
          if (!upRes.ok) {
            console.error(
              "Erro no upload ao atualizar atividade:",
              upRes.status,
              upText
            );
            alert(
              "Atividade atualizada, mas falha no upload dos novos arquivos. Veja console."
            );
            // continue; activity was already updated
          } else {
            console.log("Arquivos enviados/atualizados com sucesso.");
          }
        }

        alert("Atividade atualizada!");
      } else {
        // Create new activity
        if (formAtividade.tipo === "UNPLUGGED" && arquivos.length > 0) {
          // Use multipart endpoint that creates atividade + arquivos
          const fd = new FormData();
          fd.append("titulo", String(payload.titulo));
          fd.append("descricao", String(payload.descricao ?? ""));
          fd.append("tipo", String(payload.tipo));
          fd.append("nota", String(payload.nota ?? ""));
          if (payload.script) fd.append("script", String(payload.script));
          if (payload.linguagem)
            fd.append("linguagem", String(payload.linguagem));
          if (payload.alternativas)
            fd.append("alternativas", JSON.stringify(payload.alternativas));
          arquivos.forEach((f) => fd.append("arquivos", f));
          const res = await fetch("/api/atividades/atividade-com-upload", {
            method: "POST",
            body: fd,
          });
          const text = await res.text().catch(() => "");
          if (!res.ok) {
            console.error(
              "Erro criando atividade com upload:",
              res.status,
              text
            );
            alert("Erro ao criar atividade (upload). Veja console.");
            return;
          }
        } else {
          // PLUGGED or UNPLUGGED without files -> JSON endpoint
          const res = await fetch("/api/atividades", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          const text = await res.text().catch(() => "");
          if (!res.ok) {
            console.error("Erro criando atividade:", res.status, text);
            alert("Erro ao criar atividade. Veja console.");
            return;
          }
        }
        alert("Atividade criada!");
      }

      // reset form
      setEditingAtividadeId(null);
      setFormAtividade({
        titulo: "",
        descricao: "",
        tipo: "UNPLUGGED",
        nota: 10,
        script: "",
        linguagem: "assemblyscript",
      });
      arquivosPreviews.forEach((u) => {
        try {
          URL.revokeObjectURL(u);
        } catch {}
      });
      setArquivos([]);
      setArquivosPreviews([]);
      fetchAtividades();
    } catch (err) {
      console.error("Erro no submit atividade:", err);
      alert("Erro inesperado. Veja console.");
    }
  }

  // ---------------------- JSX ----------------------
  return (
    <div className={styles.paginaAlunoBody}>
      {/* Sidebar */}
      <aside className={styles.paginaAlunoAside}>
        <div className={styles.logoContainer}>
          <Image
            className={styles.logoImg}
            src="/images/logopng.png"
            alt="Logo Codemind"
            width={160}
            height={48}
          />
        </div>
        <h2>Minhas Funções</h2>
        <button
          className={`${styles.turmaBtn} ${
            funcaoSelecionada === "Professores" ? styles.turmaBtnActive : ""
          }`}
          onClick={() => selecionarFuncao("Professores")}
        >
          Professores
        </button>
        <button
          className={`${styles.turmaBtn} ${
            funcaoSelecionada === "Atividades" ? styles.turmaBtnActive : ""
          }`}
          onClick={() => selecionarFuncao("Atividades")}
        >
          Atividades
        </button>
      </aside>

      {/* Main */}
      <main className={styles.paginaAlunoMain}>
        <div className={styles.header}>
          <h1>
            ADM: <span className={styles.headerTitleSpan}>Funções do ADM</span>
          </h1>
          <div className={styles.userInfoWrapper}>
            <div
              className={styles.userInfo}
              onClick={toggleUserPopup}
              style={{ cursor: "pointer" }}
            >
              <Image
                className={styles.userAvatar}
                src="https://www.gravatar.com/avatar/?d=mp"
                alt="Avatar"
                width={40}
                height={40}
                unoptimized
              />
              <div className={styles.userDetails}>
                <span className={styles.userName}>ADM</span>
                <span className={styles.userEmail}>adm@exemplo.com</span>
              </div>
            </div>
            <div
              className={`${styles.userPopup} ${
                popupAberto ? styles.userPopupActive : ""
              }`}
            >
              <h3>Detalhes do ADM</h3>
              <p>
                <strong>Nome:</strong> ADM
              </p>
              <p>
                <strong>Email:</strong> adm@exemplo.com
              </p>
              <p>
                <strong>ID:</strong> A001
              </p>
              <button onClick={() => alert("Gerenciar conta clicado!")}>
                Gerenciar Conta
              </button>
              <button onClick={() => alert("Sair clicado!")}>Sair</button>
            </div>
          </div>
        </div>

        {/* Conteúdo */}
        {!funcaoSelecionada && (
          <div style={{ margin: "auto", color: "#fff", fontSize: "1.3rem" }}>
            <h2>Selecione uma Função</h2>
          </div>
        )}

        {/* Professores list / form */}
        {funcaoSelecionada === "Professores" &&
          !showForm &&
          !editingProfessor && (
            <div className={styles.card}>
              <h2>Professores</h2>
              {loading ? (
                <p>Carregando...</p>
              ) : (
                <div>
                  {professores.length === 0 && (
                    <p>Nenhum professor cadastrado.</p>
                  )}
                  {professores.map((prof) => (
                    <div
                      key={prof.idProfessor}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        background: "#2b1544",
                        borderRadius: 8,
                        marginBottom: 10,
                        padding: "10px 18px",
                      }}
                    >
                      <span>{prof.nome}</span>
                      <div style={{ display: "flex", gap: 8 }}>
                        <button
                          className={styles.turmaBtn}
                          style={{
                            background: "#00bcd4",
                            color: "#fff",
                            borderColor: "#00bcd4",
                          }}
                          onClick={() => {
                            setEditingProfessor(prof);
                            setEditFormData({
                              nome: prof.nome,
                              senha: "",
                              confirmarSenha: "",
                            });
                          }}
                        >
                          Editar
                        </button>
                        <button
                          className={styles.turmaBtn}
                          style={{
                            background: "#b71c1c",
                            color: "#fff",
                            borderColor: "#b71c1c",
                          }}
                          onClick={() =>
                            handleExcluirProfessor(prof.idProfessor)
                          }
                        >
                          Excluir
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              <div style={{ display: "flex", gap: 12, marginTop: 30 }}>
                <button
                  style={{ background: "#4caf50", color: "#fff" }}
                  className={styles.btn}
                  onClick={handleShowForm}
                >
                  Criar Professor
                </button>
                <button className={styles.btn} onClick={voltarMenu}>
                  Voltar
                </button>
              </div>
            </div>
          )}

        {/* Criar Professor */}
        {funcaoSelecionada === "Professores" && showForm && (
          <div className={styles.card}>
            <h2>Criar Professor</h2>
            <form
              onSubmit={handleSubmit}
              style={{ display: "flex", flexDirection: "column", gap: 16 }}
            >
              <input
                name="nome"
                type="text"
                placeholder="Nome"
                required
                value={formData.nome}
                onChange={(e) =>
                  setFormData({ ...formData, [e.target.name]: e.target.value })
                }
                className={styles.input}
              />
              <input
                name="email"
                type="email"
                placeholder="Email"
                required
                value={formData.email}
                onChange={(e) =>
                  setFormData({ ...formData, [e.target.name]: e.target.value })
                }
                className={styles.input}
              />
              <input
                name="senha"
                type="password"
                placeholder="Senha"
                required
                value={formData.senha}
                onChange={(e) =>
                  setFormData({ ...formData, [e.target.name]: e.target.value })
                }
                className={styles.input}
              />
              <input
                name="confirmarSenha"
                type="password"
                placeholder="Confirmar Senha"
                required
                value={formData.confirmarSenha}
                onChange={(e) =>
                  setFormData({ ...formData, [e.target.name]: e.target.value })
                }
                className={styles.input}
              />
              <div style={{ display: "flex", gap: 12, marginTop: 20 }}>
                <button
                  type="submit"
                  style={{ background: "#4caf50" }}
                  className={styles.btn}
                >
                  Criar Professor
                </button>
                <button
                  type="button"
                  onClick={() => setShowForm(false)}
                  className={styles.btn}
                >
                  Voltar
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Editar Professor */}
        {funcaoSelecionada === "Professores" && editingProfessor && (
          <div className={styles.card}>
            <h2>Editar Professor</h2>
            <form
              onSubmit={handleEditSubmit}
              style={{ display: "flex", flexDirection: "column", gap: 16 }}
            >
              <input
                name="nome"
                type="text"
                placeholder="Nome"
                required
                value={editFormData.nome}
                onChange={(e) =>
                  setEditFormData({
                    ...editFormData,
                    [e.target.name]: e.target.value,
                  })
                }
                className={styles.input}
              />
              <input
                name="email"
                type="email"
                placeholder="Email"
                value={editingProfessor.email}
                disabled
                className={styles.input}
                style={{ backgroundColor: "#eee", color: "#999" }}
              />
              <input
                name="senha"
                type="password"
                placeholder="Nova Senha"
                required
                value={editFormData.senha}
                onChange={(e) =>
                  setEditFormData({
                    ...editFormData,
                    [e.target.name]: e.target.value,
                  })
                }
                className={styles.input}
              />
              <input
                name="confirmarSenha"
                type="password"
                placeholder="Confirmar Nova Senha"
                required
                value={editFormData.confirmarSenha}
                onChange={(e) =>
                  setEditFormData({
                    ...editFormData,
                    [e.target.name]: e.target.value,
                  })
                }
                className={styles.input}
              />
              <div style={{ display: "flex", gap: 12, marginTop: 20 }}>
                <button
                  type="submit"
                  style={{ background: "#2196f3" }}
                  className={styles.btn}
                >
                  Salvar Alterações
                </button>
                <button
                  type="button"
                  onClick={() => setEditingProfessor(null)}
                  className={styles.btn}
                >
                  Cancelar
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Atividades CRUD */}
        {funcaoSelecionada === "Atividades" && (
          <div className={styles.card}>
            <h2>
              {editingAtividadeId ? "Editar Atividade" : "Criar Nova Atividade"}
            </h2>

            <form
              onSubmit={handleFormAtividadeSubmit}
              style={{ display: "flex", flexDirection: "column", gap: 12 }}
              encType={
                formAtividade.tipo === "UNPLUGGED"
                  ? "multipart/form-data"
                  : "application/json"
              }
            >
              <input
                name="titulo"
                type="text"
                placeholder="Título"
                required
                value={formAtividade.titulo}
                onChange={handleFormAtividadeChange}
                className={styles.input}
              />
              <textarea
                name="descricao"
                placeholder="Descrição"
                required
                value={formAtividade.descricao}
                onChange={handleFormAtividadeChange}
                className={styles.input}
              />
              <select
                name="tipo"
                value={formAtividade.tipo}
                onChange={handleFormAtividadeChange}
                className={styles.input}
              >
                <option value="PLUGGED">Plugged</option>
                <option value="UNPLUGGED">Unplugged</option>
              </select>
              <input
                name="nota"
                type="number"
                min={0}
                max={100}
                required
                value={formAtividade.nota}
                onChange={handleFormAtividadeChange}
                className={styles.input}
              />

              {/* Campos específicos de atividades PLUGGED removidos */}

              {/* campos UNPLUGGED (upload) */}
              <>
                <label>
                  Anexar arquivos (imagens ou PDFs):
                  <input
                    type="file"
                    name="arquivos"
                    multiple
                    accept="image/*,application/pdf"
                    onChange={handleArquivosChange}
                    className={styles.input}
                  />
                </label>
                {arquivos.length > 0 && (
                  <ul>
                    {arquivos.map((file, idx) => (
                      <li key={idx}>{file.name}</li>
                    ))}
                  </ul>
                )}
                {/* show previews of existing files when editing */}
                {arquivosPreviews.length > 0 && (
                  <div>
                    <strong>Previews / arquivos existentes:</strong>
                    <ul>
                      {arquivosPreviews.map((p, i) => (
                        <li key={i}>
                          <a href={p} target="_blank" rel="noreferrer">
                            {p}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {/* replace-files checkbox only visible when editing */}
                {editingAtividadeId && (
                  <div style={{ marginTop: 8 }}>
                    <label style={{ color: "#fff" }}>
                      <input
                        type="checkbox"
                        checked={replaceFilesOnUpdate}
                        onChange={(e) =>
                          setReplaceFilesOnUpdate(e.target.checked)
                        }
                      />{" "}
                      Substituir arquivos existentes ao salvar
                    </label>
                  </div>
                )}
              </>
              {/* fim campos UNPLUGGED */}

              <div style={{ display: "flex", gap: 12, marginTop: 8 }}>
                <button
                  type="submit"
                  style={{ background: "#4caf50", color: "#fff" }}
                  className={styles.btn}
                >
                  {editingAtividadeId ? "Salvar Alterações" : "Criar Atividade"}
                </button>
                <button
                  type="button"
                  className={styles.btn}
                  onClick={() => {
                    // cancel edit/create reset
                    setEditingAtividadeId(null);
                    setFormAtividade({
                      titulo: "",
                      descricao: "",
                      tipo: "UNPLUGGED",
                      nota: 10,
                      script: "",
                      linguagem: "assemblyscript",
                    });
                    setArquivos([]);
                    arquivosPreviews.forEach((u) => {
                      try {
                        URL.revokeObjectURL(u);
                      } catch {}
                    });
                    setArquivosPreviews([]);
                  }}
                >
                  Cancelar
                </button>
              </div>
            </form>

            <hr />
            <h2>Atividades Criadas</h2>
            {loadingAtividades ? (
              <p>Carregando atividades...</p>
            ) : (
              <ul>
                {atividades.length === 0 && (
                  <li>Nenhuma atividade cadastrada.</li>
                )}
                {atividades.map((a: Atividade) => (
                  <li key={a.idAtividade} style={{ marginBottom: 12 }}>
                    <strong>{a.titulo}</strong> ({a.tipo}) - Nota: {a.nota}
                    <br />
                    {a.descricao}
                    <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
                      <button
                        className={styles.btn}
                        onClick={() => startEditAtividade(a)}
                      >
                        Editar
                      </button>
                      <button
                        className={styles.btn}
                        onClick={() => handleDeleteAtividade(a.idAtividade)}
                        style={{ background: "#b71c1c", color: "#fff" }}
                      >
                        Excluir
                      </button>
                    </div>
                    {/* arquivos list + delete */}
                    {Array.isArray(a.arquivos) && a.arquivos.length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <strong>Arquivos:</strong>
                        <ul>
                          {a.arquivos!.map((f: ArquivoResumo) => (
                            <li
                              key={f.idArquivo}
                              style={{
                                display: "flex",
                                gap: 8,
                                alignItems: "center",
                              }}
                            >
                              <a href={f.url} target="_blank" rel="noreferrer">
                                {f.url}
                              </a>
                              <button
                                className={styles.btn}
                                style={{ background: "#ff8a65" }}
                                onClick={() => handleDeleteArquivo(f.idArquivo)}
                              >
                                Remover
                              </button>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
            <button className={styles.btn} onClick={voltarMenu}>
              Voltar
            </button>
          </div>
        )}
      </main>
    </div>
  );
}
