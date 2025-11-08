import type { NextApiRequest, NextApiResponse } from "next";
import prisma from "../../lib/prisma";
import type {
  AtividadeTurma,
  Atividade as PrismaAtividade,
  AtividadeArquivo,
  Turma,
  Professor,
} from "@prisma/client";

// Narrowed shape for atividadeTurma when `include` is used in queries below.
type AplicacaoWithIncludes = AtividadeTurma & {
  atividade: PrismaAtividade & { arquivos: AtividadeArquivo[] };
  turma: Turma | null;
  professor: Professor | null;
};

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "GET")
    return res.status(405).json({ error: "Method not allowed" });

  try {
    const alunoIdRaw = req.query.alunoId;
    const alunoId = alunoIdRaw !== undefined ? Number(String(alunoIdRaw)) : NaN;

    // If alunoId provided and valid, return activities applied to the aluno's turma(s)
    if (!Number.isNaN(alunoId)) {
      // get turma ids for the aluno
      const turmaLinks = await prisma.turmaAluno.findMany({
        where: { idAluno: alunoId },
        select: { idTurma: true },
      });
      const turmaIds = turmaLinks.map((t) => t.idTurma);

      // If no direct turma links were found, attempt a tolerant lookup by
      // searching AtividadeTurma where the turma has the aluno in its alunos relation.
      // This guards against cases where the turmaAluno lookup unexpectedly returns
      // nothing due to data inconsistencies or subtle type differences.
      let aplicacoes: AplicacaoWithIncludes[] = [];
      if (turmaIds.length > 0) {
        aplicacoes = await prisma.atividadeTurma.findMany({
          where: { idTurma: { in: turmaIds } },
          include: {
            atividade: { include: { arquivos: true } },
            turma: true,
            professor: true,
          },
          orderBy: { dataAplicacao: "desc" },
        });
      } else {
        // fallback: try to find atividadeTurma where the turma contains the aluno
        console.warn(
          `GET /api/listaratividades: no turma links for aluno ${alunoId}, trying nested turma.alunos lookup`
        );
        aplicacoes = await prisma.atividadeTurma.findMany({
          where: {
            turma: {
              alunos: {
                some: {
                  idAluno: alunoId,
                },
              },
            },
          },
          include: {
            atividade: { include: { arquivos: true } },
            turma: true,
            professor: true,
          },
          orderBy: { dataAplicacao: "desc" },
        });
      }

      // map to atividade summary shape expected by the client
      const resultados = aplicacoes.map((ap: AplicacaoWithIncludes) => {
        const at = ap.atividade;
        return {
          idAtividade: at.idAtividade,
          titulo: at.titulo,
          descricao: at.descricao ?? null,
          tipo: at.tipo,
          nota: at.nota ?? null,
          dataAplicacao: ap.dataAplicacao
            ? ap.dataAplicacao.toISOString()
            : null,
          turma: ap.turma
            ? { idTurma: ap.turma.idTurma, nome: ap.turma.nome }
            : null,
          arquivos: (at.arquivos || []).map((f: AtividadeArquivo) => ({
            idArquivo: f.idArquivo,
            url: f.url,
            tipoArquivo: f.tipoArquivo ?? null,
            nomeArquivo: null,
          })),
        };
      });

      return res.status(200).json(resultados);
    }

    // fallback: return all atividades (legacy behavior)
    const atividades = await prisma.atividade.findMany({
      include: { arquivos: true },
    });
    const mapped = atividades.map((at) => ({
      idAtividade: at.idAtividade,
      titulo: at.titulo,
      descricao: at.descricao ?? null,
      tipo: at.tipo,
      nota: at.nota ?? null,
      dataAplicacao: null,
      turma: null,
      arquivos: (at.arquivos || []).map((f: AtividadeArquivo) => ({
        idArquivo: f.idArquivo,
        url: f.url,
        tipoArquivo: f.tipoArquivo ?? null,
        nomeArquivo: null,
      })),
    }));

    return res.status(200).json(mapped);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("GET /api/listaratividades error:", msg);
    return res.status(500).json({ error: msg || "Erro interno" });
  }
}
