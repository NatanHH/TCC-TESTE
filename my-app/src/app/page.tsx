"use client";

import Image from "next/image";
import Link from "next/link";
import React, { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginAdm() {
  const [email, setEmail] = useState("");
  const [senha, setSenha] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch("/api/loginadm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, senha }),
      });

      // parse JSON safely into unknown and then narrow
      let data: unknown = null;
      try {
        data = await res.json();
      } catch {
        // fallback: try text parse for more debug info
        try {
          const txt = await res.text();
          data = txt ? JSON.parse(txt) : null;
        } catch {
          data = null;
        }
      }

      console.log("loginadm response status:", res.status, "body:", data);

      const obj =
        typeof data === "object" && data !== null
          ? (data as Record<string, unknown>)
          : null;
      // aceitar ambos os formatos: { success: true } ou { ok: true }
      const logged = Boolean(
        obj && (obj["success"] === true || obj["ok"] === true)
      );

      if (res.ok && logged) {
        router.push("/pginicialadm");
        return;
      }

      const errMsg =
        obj && typeof obj["error"] === "string"
          ? (obj["error"] as string)
          : undefined;
      alert(errMsg ?? "Email ou senha incorretos!");
    } catch (err: unknown) {
      console.error("loginadm fetch error:", err);
      alert("Erro de rede. Veja console para mais detalhes.");
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
        />
        <h2>Login Administrador</h2>

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
          <button type="submit" disabled={loading}>
            {loading ? "Entrando..." : "Entrar"}
          </button>
        </form>

        <div className="link-professor">
          <Link href="/loginprofessor">Fazer login como professor</Link>
        </div>
        <div className="link-aluno">
          <Link href="/loginaluno">Fazer login como aluno</Link>
        </div>
      </div>
    </div>
  );
}
