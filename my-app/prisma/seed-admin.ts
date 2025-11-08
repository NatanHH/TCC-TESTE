import "dotenv/config"; // carrega .env automaticamente quando existir
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const prisma = new PrismaClient();

/**
 * Criar/atualizar administrador.
 *
 * Adapte os campos se seu schema usar nomes diferentes (por exemplo,
 * model `User` com campo `password` ou `isAdmin`/`role`).
 *
 * Execução (PowerShell):
 * 1) npx vercel env pull .env.production --environment=production
 * 2) Carregue as variáveis no PowerShell (veja README/instruções do projeto)
 * 3) npx prisma generate
 * 4) npx ts-node prisma/seed-admin.ts
 */
export async function createAdmin(): Promise<void> {
  const email = process.env.ADMIN_EMAIL ?? "admin@exemplo.com";
  const nome = process.env.ADMIN_NOME ?? "Administrador";
  let password = process.env.ADMIN_PASSWORD ?? process.env.ADMIN_SENHA ?? "";

  const generated = password.trim() === "";
  if (generated) password = cryptoRandomPassword();

  try {
    const hashed = await bcrypt.hash(password, 10);

    // -- ADAPTAR: Este bloco assume o model `Administrador` com campos `nome`, `email`, `senha`.
    // Se seu schema usar outro model (por ex. `User`) ou nomes diferentes, substitua
    // a chamada abaixo por `prisma.user.upsert({...})` ajustando campos para o seu schema.
    const adm = await prisma.administrador.upsert({
      where: { email },
      update: { nome, senha: hashed },
      create: { nome, email, senha: hashed },
    });

    console.log("Administrador criado/atualizado:", {
      id: adm.idAdm,
      email: adm.email,
    });
    if (generated) {
      console.log(
        "Senha gerada (anote-a agora e troque em seguida):",
        password
      );
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("Erro ao criar/atualizar administrador:", message);
    throw err;
  }
}

function cryptoRandomPassword(len = 16): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+";
  const buf = crypto.randomFillSync(Buffer.allocUnsafe(len));
  let out = "";
  for (let i = 0; i < len; i++) out += chars[buf[i] % chars.length];
  return out;
}

// Execução direta quando chamado com ts-node
(async () => {
  try {
    await createAdmin();
  } catch (err) {
    process.exitCode = 1;
  } finally {
    try {
      await prisma.$disconnect();
    } catch {}
  }
})();
