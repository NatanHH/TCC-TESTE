import type { NextApiRequest, NextApiResponse } from "next";
import prisma from "../../../lib/prisma";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method === "GET") {
    try {
      const { atividadeId, alunoId, turmaId, page, perPage } = req.query;

      const where: Record<string, unknown> = {};
      if (atividadeId !== undefined) {
        const v = Number(String(atividadeId));
        if (!Number.isNaN(v)) where.idAtividade = v;
      }
      if (alunoId !== undefined) {
        const v = Number(String(alunoId));
        if (!Number.isNaN(v)) where.idAluno = v;
      }

      // pagination
      const p = Math.max(1, Number.isFinite(Number(page)) ? Number(page) : 1);
      const pp = Math.max(
        1,
        Math.min(1000, Number.isFinite(Number(perPage)) ? Number(perPage) : 200)
      );
      const skip = (p - 1) * pp;

      // If turmaId provided, filter respostas by alunos that belong to the turma
      let respostas;
      const turmaIdNum = turmaId !== undefined ? Number(String(turmaId)) : NaN;
      if (!Number.isNaN(turmaIdNum)) {
        // find respostas where the related aluno has a TurmaAluno entry with this idTurma
        respostas = await prisma.respostaAlunoAtividade.findMany({
          where: {
            ...where,
            aluno: { turmas: { some: { idTurma: turmaIdNum } } },
          },
          include: {
            aluno: { select: { idAluno: true, nome: true, email: true } },
          },
          orderBy: { dataAplicacao: "desc" },
          skip,
          take: pp,
        });
      } else {
        respostas = await prisma.respostaAlunoAtividade.findMany({
          where,
          include: {
            aluno: { select: { idAluno: true, nome: true, email: true } },
          },
          orderBy: { dataAplicacao: "desc" },
          skip,
          take: pp,
        });
      }

      return res.status(200).json({ respostas });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("GET /api/respostas error:", msg);
      return res.status(500).json({ error: msg || "Erro interno" });
    }
  }

  if (req.method === "POST") {
    const payload: unknown = req.body;
    if (typeof payload !== "object" || payload === null) {
      return res.status(400).json({ error: "Invalid body" });
    }
    const body = payload as {
      alunoId?: number;
      atividadeId?: number;
      respostas?: unknown[];
    };
    // normalize/validate respostas array
    const rawRespostas = Array.isArray(body.respostas) ? body.respostas : [];
    const _respostas = rawRespostas.map((r) => {
      const rec = (r ?? {}) as Record<string, unknown>;
      return {
        perguntaId:
          rec.perguntaId !== undefined ? Number(rec.perguntaId) : undefined,
        alternativaId:
          rec.alternativaId !== undefined
            ? Number(rec.alternativaId)
            : undefined,
        texto: rec.texto !== undefined ? String(rec.texto) : undefined,
      };
    });
    // TODO: implement creation logic for bulk respostas if needed.
    return res.status(201).json({ ok: true, created: [] });
  }

  return res.status(405).json({ error: "Method not allowed" });
}
