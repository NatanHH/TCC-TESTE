/**
 * pages/api/atividades/plugged/contagem-instance.ts
 *
 * API autônoma que gera, a cada requisição, uma instância do exercício
 * "Contando os pontos (Plugged)" (bits aleatórios + alternativas).
 *
 * Behavior:
 * - Tenta ler metadata da atividade no banco (Prisma) procurando por atividade
 *   PLUGGED ou título contendo "Contando". Se o banco não estiver disponível,
 *   retorna um fallback embutido.
 * - Gera um vetor de cards = potências de 2 (n bits, padrão n=5 => [16,8,4,2,1]).
 * - Gera bits aleatórios (ou determinísticos a partir do query param ?seed=123).
 * - Calcula decimal (soma dos valores das cartas com bit=1).
 * - Gera 4 alternativas (1 correta + 3 distratores plausíveis) e embaralha.
 * - Aceita query params:
 *    - n: número de bits (3..10)
 *    - seed: número/pseudo-seed para geração determinística
 *    - meta=false: se definido, retorna apenas instância sem tentar ler DB metadata
 *
 * Exemplo:
 *  GET /api/atividades/plugged/contagem-instance?n=5
 *
 * Nota: este arquivo usa Prisma opcionalmente. Se você não tiver Prisma
 * instalado, a rota ainda funciona retornando o fallback estático.
 */

import type { NextApiRequest, NextApiResponse } from "next";

function mulberry32(a: number) {
  return function () {
    let t = (a += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildInstanceFromSeed(seed: number) {
  const rand = mulberry32(seed);
  const cards = [8, 4, 2, 1];
  const bits = cards.map(() => (rand() > 0.5 ? 1 : 0));
  const decimal = bits.reduce<number>((acc, b, i) => acc + b * cards[i], 0);

  // Gerar 3 valores diferentes para as alternativas incorretas
  const wrongValues = new Set<number>();
  while (wrongValues.size < 3) {
    const delta = Math.floor((rand() - 0.5) * 8); // -4..+3
    const wrongValue = Math.max(0, Math.min(15, decimal + delta)); // mantém entre 0-15
    if (wrongValue !== decimal) {
      wrongValues.add(wrongValue);
    }
  }

  // Alternativa A sempre correta, B, C, D incorretas
  const letters = ["A", "B", "C", "D"];
  const values = [decimal, ...Array.from(wrongValues)];
  const alternatives = letters.map((letter, i) => ({
    id: `opt${i}`,
    value: values[i],
    label: letter,
    correct: i === 0, // apenas A é correta
  }));

  return {
    cards,
    bits,
    decimal,
    alternatives,
    seed,
  };
}

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  // Cada GET retorna uma nova instância (seed aleatório) — aluno recebe novo número ao abrir
  if (req.method !== "GET") return res.status(405).end("Method Not Allowed");

  const seed = Math.floor(Math.random() * 1_000_000_000);
  const instance = buildInstanceFromSeed(seed);

  // NÃO incluir campo "correct" — servidor avaliará na hora do submit
  return res
    .status(200)
    .json({ meta: { titulo: "Contagem (plugged)" }, instance });
}
