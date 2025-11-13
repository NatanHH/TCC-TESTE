"use client";
import React, { useState } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";

export default function LoginAluno() {
  const [email, setEmail] = useState<string>("");
  const [senha, setSenha] = useState<string>("");
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    try {
      const res = await fetch("/api/alunos/loginaluno", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, senha }),
      });
      if (res.ok) {
        const data = await res.json().catch(() => null);
        try {
          if (data && typeof window !== "undefined") {
            if (data.idAluno)
              localStorage.setItem("idAluno", String(data.idAluno));
            if (data.nome) localStorage.setItem("alunoNome", String(data.nome));
            if (data.email)
              localStorage.setItem("alunoEmail", String(data.email));
            if (data.turmas)
              localStorage.setItem(
                "initialTurmas",
                JSON.stringify(data.turmas)
              );
            if (data.atividades)
              localStorage.setItem(
                "initialAtividades",
                JSON.stringify(data.atividades)
              );
            // signal other tabs/components
            window.dispatchEvent(new Event("alunoUpdate"));
          }
        } catch {
          /* ignore storage errors */
        }
        router.push("/pginialuno");
      } else {
        console.error("Login falhou");
      }
    } catch (error) {
      console.error("Erro ao fazer login:", error);
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
        />
        <h2>Login aluno</h2>

        <form onSubmit={handleSubmit}>
          <input
            type="email"
            placeholder="Email"
            required
            value={email}
            onChange={(e) => setEmail((e.target as HTMLInputElement).value)}
          />
          <input
            type="password"
            placeholder="Senha"
            required
            value={senha}
            onChange={(e) => setSenha((e.target as HTMLInputElement).value)}
          />
          <button type="submit">Entrar</button>
        </form>

        <div className="link-aluno">
          <Link href="loginprofessor">Fazer login como professor</Link>
        </div>
      </div>
    </div>
  );
}
