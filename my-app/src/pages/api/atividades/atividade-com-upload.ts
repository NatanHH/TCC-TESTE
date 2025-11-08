import type { NextApiRequest, NextApiResponse } from "next";
import multer from "multer";
import {
  v2 as cloudinaryV2,
  UploadApiResponse,
  UploadApiErrorResponse,
} from "cloudinary";
import crypto from "crypto";
import prisma from "../../../lib/prisma";
import type { Prisma, TipoAtividade } from "@prisma/client";

export const config = { api: { bodyParser: false } };

// use memory storage and upload directly to Cloudinary (no local filesystem)
const storage = multer.memoryStorage();

// configure cloudinary from CLOUDINARY_URL or individual env vars
try {
  if (process.env.CLOUDINARY_URL) {
    cloudinaryV2.config({ cloudinary_url: process.env.CLOUDINARY_URL });
  } else {
    cloudinaryV2.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
    });
  }
} catch {
  // ignore - config will be validated at upload time
}

function uploadBufferToCloudinary(
  buffer: Buffer,
  _originalName: string
): Promise<UploadApiResponse> {
  return new Promise<UploadApiResponse>((resolve, reject) => {
    const publicId = `atividades/${Date.now()}-${crypto
      .randomBytes(6)
      .toString("hex")}`;
    const stream = cloudinaryV2.uploader.upload_stream(
      { folder: "atividades", resource_type: "auto", public_id: publicId },
      (
        error: UploadApiErrorResponse | undefined,
        result: UploadApiResponse | undefined
      ) => {
        if (error) return reject(error);
        if (!result)
          return reject(new Error("No result returned from Cloudinary"));
        resolve(result);
      }
    );
    stream.end(buffer);
  });
}

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const allowedMimes = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "application/pdf",
];

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
});

// helper to run middleware
function runMiddleware(req: NextApiRequest, res: NextApiResponse, fn: unknown) {
  return new Promise<void>((resolve, reject) => {
    try {
      if (typeof fn !== "function")
        return reject(new Error("middleware is not a function"));
      // call middleware with safe typing
      (
        fn as (
          req: unknown,
          res: unknown,
          next: (result?: unknown) => void
        ) => void
      )(req, res, (result?: unknown) => {
        if (result instanceof Error) return reject(result);
        resolve();
      });
    } catch (err) {
      reject(err);
    }
  });
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Método não permitido" });
  }

  try {
    await runMiddleware(req, res, upload.array("arquivos"));
    const r = req as NextApiRequest & {
      files?: Express.Multer.File[];
      body?: Record<string, unknown>;
    };

    // fields
    const tituloRaw = r.body?.titulo;
    const descricaoRaw = r.body?.descricao;
    const tipoRaw = r.body?.tipo;
    const notaRaw =
      r.body?.nota ?? r.body?._payload_nota ?? r.body?.payload_nota;
    const scriptRaw = r.body?.script;
    const linguagemRaw = r.body?.linguagem;
    const alternativasRaw = r.body?.alternativas;

    const titulo = typeof tituloRaw === "string" ? tituloRaw.trim() : "";
    if (!titulo) {
      return res.status(400).json({ error: "titulo é obrigatório" });
    }

    const tipo =
      typeof tipoRaw === "string" ? tipoRaw.trim().toUpperCase() : "";
    const allowedTipos = ["PLUGGED", "UNPLUGGED"];
    if (!allowedTipos.includes(tipo)) {
      return res.status(400).json({ error: "tipo inválido" });
    }

    const nota = Number(notaRaw);
    if (notaRaw === undefined || Number.isNaN(nota)) {
      return res
        .status(400)
        .json({ error: "nota é obrigatória e deve ser numérica" });
    }

    // parse alternativas if present (could be JSON string)
    let alternativas: unknown = undefined;
    if (typeof alternativasRaw === "string") {
      try {
        alternativas = JSON.parse(alternativasRaw);
      } catch {
        alternativas = undefined;
      }
    } else if (Array.isArray(alternativasRaw)) alternativas = alternativasRaw;

    // create atividade record
    const data: Prisma.AtividadeCreateInput = {
      titulo,
      descricao:
        typeof descricaoRaw === "string" && descricaoRaw.trim().length > 0
          ? descricaoRaw.trim()
          : null,
      tipo: tipo as TipoAtividade,
      nota,
      script:
        typeof scriptRaw === "string" && scriptRaw.trim().length > 0
          ? scriptRaw.trim()
          : null,
      linguagem:
        typeof linguagemRaw === "string" && linguagemRaw.trim().length > 0
          ? linguagemRaw.trim()
          : null,
      ...(Array.isArray(alternativas) && alternativas.length > 0
        ? {
            alternativas: {
              create: alternativas.map((a: unknown) => {
                if (typeof a === "string") {
                  return { texto: a, correta: false };
                }
                if (a && typeof a === "object") {
                  const rec = a as Record<string, unknown>;
                  return {
                    texto: String(rec.texto ?? ""),
                    correta: !!rec.correta,
                  };
                }
                return { texto: String(a ?? ""), correta: false };
              }),
            },
          }
        : {}),
    };

    const createdAtividade = await prisma.atividade.create({ data });

    // handle files (upload to Cloudinary)
    const files = r.files ?? [];
    const createdFiles: import("@prisma/client").AtividadeArquivo[] = [];
    const errors: { filename: string; message: string }[] = [];

    for (const f of files) {
      if (!allowedMimes.includes(f.mimetype)) {
        errors.push({
          filename: f.originalname,
          message: "Tipo de arquivo não permitido",
        });
        continue;
      }
      if (f.size > MAX_FILE_SIZE) {
        errors.push({
          filename: f.originalname,
          message: "Arquivo muito grande",
        });
        continue;
      }

      try {
        const buf = (f as Express.Multer.File & { buffer?: Buffer }).buffer as
          | Buffer
          | undefined;
        if (!buf) throw new Error("No buffer available for file");
        const uploadRes = await uploadBufferToCloudinary(buf, f.originalname);
        const secureUrl = uploadRes.secure_url ?? uploadRes.url;
        if (!secureUrl) throw new Error("No URL returned from Cloudinary");

        const rec = await prisma.atividadeArquivo.create({
          data: {
            url: secureUrl,
            tipoArquivo: f.mimetype,
            atividadeId: createdAtividade.idAtividade,
          },
        });
        createdFiles.push(rec);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error("Erro ao processar/upload arquivo:", msg);
        errors.push({
          filename: f.originalname,
          message: "Erro ao salvar no banco ou upload",
        });
      }
    }

    const result = {
      atividade: createdAtividade,
      arquivos: createdFiles,
      errors,
    };
    return res.status(201).json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("atividade-com-upload error:", msg);
    return res.status(500).json({ error: "Erro interno no servidor" });
  }
}
