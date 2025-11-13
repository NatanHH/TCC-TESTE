import type { NextApiRequest, NextApiResponse } from "next";
import prisma from "../../../lib/prisma";

type ProfessorPayload = {
  nome: string;
  email: string;
  senha: string;
};

function isProfessorPayload(x: unknown): x is ProfessorPayload {
  if (!x || typeof x !== "object") return false;
  const r = x as Record<string, unknown>;
  return (
    typeof r.nome === "string" &&
    r.nome.trim().length > 0 &&
    typeof r.email === "string" &&
    r.email.trim().length > 0 &&
    typeof r.senha === "string" &&
    r.senha.length > 0
  );
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method === "GET") {
    try {
      const professores = await prisma.professor.findMany();
      return res.status(200).json(professores);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("GET /api/professores/professor error:", msg);
      return res.status(500).json({ error: "Erro ao listar professores" });
    }
  }

  if (req.method === "POST") {
    const payload: unknown = req.body;
    if (!isProfessorPayload(payload)) {
      return res
        .status(400)
        .json({ error: "Dados obrigatórios ausentes ou inválidos." });
    }
    const nome = payload.nome.trim();
    const email = payload.email.trim();
    const senha = payload.senha; // aplicar hashing se necessário

    try {
      const novoProfessor = await prisma.professor.create({
        data: {
          nome,
          email,
          senha,
        },
      });
      return res.status(201).json(novoProfessor);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      // Prisma unique constraint (email) -> P2002
      if ((err as Record<string, unknown>)?.code === "P2002") {
        return res.status(409).json({ error: "Email já cadastrado" });
      }
      console.error("POST /api/professores/professor error:", msg);
      return res.status(400).json({ error: msg });
    }
  }

  if (req.method === "PUT") {
    const payload: unknown = req.body;
    if (!payload || typeof payload !== "object") {
      return res.status(400).json({ error: "Payload inválido" });
    }
    const body = payload as Record<string, unknown>;

    // Exigir identEmail e senhaAtual para validação de identidade
    const identEmail =
      typeof body.identEmail === "string" && body.identEmail.trim()
        ? body.identEmail.trim()
        : undefined;
    const senhaAtual =
      typeof body.senhaAtual === "string" && body.senhaAtual.length > 0
        ? body.senhaAtual
        : undefined;

    if (!identEmail || !senhaAtual) {
      return res.status(400).json({
        error:
          "identEmail e senhaAtual são obrigatórios para editar professor.",
      });
    }

    try {
      // Buscar professor pelo email
      const professor = await prisma.professor.findUnique({
        where: { email: identEmail },
        select: { idProfessor: true, senha: true, email: true, nome: true },
      });

      if (!professor) {
        return res.status(404).json({
          error: "Professor não encontrado com este email.",
        });
      }

      // Validar senha atual
      if (professor.senha !== senhaAtual) {
        return res.status(401).json({
          error: "Senha atual incorreta. Não é possível editar.",
        });
      }

      // Preparar dados para atualização
      const updateData: Record<string, unknown> = {};
      if (typeof body.nome === "string" && body.nome.trim().length > 0)
        updateData.nome = body.nome.trim();
      if (typeof body.email === "string" && body.email.trim().length > 0)
        updateData.email = body.email.trim();
      if (typeof body.senha === "string" && body.senha.length > 0)
        updateData.senha = body.senha;

      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ error: "Nenhum campo para atualizar." });
      }

      const professorAtualizado = await prisma.professor.update({
        where: { idProfessor: professor.idProfessor },
        data: updateData,
      });
      return res.status(200).json(professorAtualizado);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("PUT /api/professores/professor error:", msg);
      return res.status(400).json({ error: msg });
    }
  }

  if (req.method === "DELETE") {
    const payload: unknown = req.body;
    if (!payload || typeof payload !== "object") {
      return res.status(400).json({ error: "Payload inválido" });
    }
    const body = payload as Record<string, unknown>;

    // Exigir apenas identEmail para identificar o professor
    const identEmail =
      typeof body.identEmail === "string" && body.identEmail.trim()
        ? body.identEmail.trim()
        : undefined;

    if (!identEmail) {
      return res.status(400).json({
        error: "identEmail é obrigatório para excluir professor.",
      });
    }

    try {
      // Buscar professor pelo email
      const professor = await prisma.professor.findUnique({
        where: { email: identEmail },
        select: { idProfessor: true, email: true, nome: true },
      });

      if (!professor) {
        return res.status(404).json({
          error: "Professor não encontrado com este email.",
        });
      }

      // Excluir em cascata - primeiro as relações, depois o professor
      const profId = professor.idProfessor;

      // 1. Deletar AtividadeProfessor (relação professor-atividade)
      await prisma.atividadeProfessor.deleteMany({
        where: { idProfessor: profId },
      });

      // 2. Deletar AtividadeTurma (aplicações de atividades nas turmas do professor)
      await prisma.atividadeTurma.deleteMany({
        where: { idProfessor: profId },
      });

      // 3. Para cada turma do professor, deletar TurmaAluno e depois a Turma
      const turmas = await prisma.turma.findMany({
        where: { professorId: profId },
        select: { idTurma: true },
      });

      for (const turma of turmas) {
        // Deletar alunos da turma
        await prisma.turmaAluno.deleteMany({
          where: { idTurma: turma.idTurma },
        });

        // Deletar relações AtividadeTurma desta turma
        await prisma.atividadeTurma.deleteMany({
          where: { idTurma: turma.idTurma },
        });
      }

      // 4. Deletar as turmas do professor
      await prisma.turma.deleteMany({
        where: { professorId: profId },
      });

      // 5. Remover professorId das atividades (deixar null)
      await prisma.atividade.updateMany({
        where: { professorId: profId },
        data: { professorId: null },
      });

      // 6. Finalmente, deletar o professor
      await prisma.professor.delete({
        where: { idProfessor: profId },
      });

      return res.status(204).end();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("DELETE /api/professores/professor error:", msg);

      // Se for erro de constraint (professor tem turmas), retornar mensagem clara
      if (msg.includes("Foreign key constraint")) {
        return res.status(400).json({
          error:
            "Não é possível excluir este professor pois ele possui turmas vinculadas. Delete as turmas primeiro.",
        });
      }

      return res.status(400).json({ error: msg });
    }
  }

  return res.status(405).json({ error: "Método não permitido" });
}
