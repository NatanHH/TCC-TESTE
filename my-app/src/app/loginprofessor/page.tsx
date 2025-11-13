"use client";
import Image from "next/image";
import Link from "next/link";
import React, { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginProfessor() {
  const [email, setEmail] = useState("");
  const [senha, setSenha] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch("/api/professores/loginprofessor", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, senha }),
      });

      const data = await res.json().catch(() => null);

      const ok = res.ok && Boolean(data?.success || data?.ok);
      if (ok) {
        // salvar como string para evitar erros ao recuperar
        if (data?.idProfessor !== undefined)
          localStorage.setItem("idProfessor", String(data.idProfessor));
        if (data?.nome !== undefined)
          localStorage.setItem("nomeProfessor", String(data.nome));
        if (data?.email !== undefined)
          localStorage.setItem("emailProfessor", String(data.email));

        router.push("/pginicialprofessor");
        return;
      }

      alert(data?.error ?? "Email ou senha incorretos!");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("loginprofessor fetch error:", message);
      alert("Erro de rede. Veja o console para mais detalhes.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-container">
      <div className="card">
        <Image
          src="/images/logopng.png"
          alt="codemind logo"
          className="logo"
          width={224}
          height={224}
          priority
        />
        <h2>Login Professor</h2>

        <form onSubmit={handleSubmit}>
          <input
            name="email"
            type="email"
            placeholder="Email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail((e.target as HTMLInputElement).value)}
          />
          <input
            name="senha"
            type="password"
            placeholder="Senha"
            required
            autoComplete="current-password"
            value={senha}
            onChange={(e) => setSenha((e.target as HTMLInputElement).value)}
          />
          <button type="submit" disabled={loading}>
            {loading ? "Entrando..." : "Entrar"}
          </button>
        </form>

        <div className="link-aluno">
          <Link href="/loginaluno">Fazer login como aluno</Link>
        </div>
      </div>
    </div>
  );
}
