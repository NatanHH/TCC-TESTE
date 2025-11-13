import type { NextApiRequest, NextApiResponse } from "next";
import type {
  RequestHandler,
  Request as ExpressRequest,
  Response as ExpressResponse,
} from "express";
import multer from "multer";
import {
  v2 as cloudinaryV2,
  UploadApiResponse,
  UploadApiErrorResponse,
} from "cloudinary";
import crypto from "crypto";
import prisma from "../../../lib/prisma";
import type { AtividadeArquivo } from "@prisma/client";

export const config = {
  api: {
    bodyParser: false,
  },
};

// use memory storage and upload directly to Cloudinary
const storage = multer.memoryStorage();

// configure cloudinary from CLOUDINARY_URL or individual env vars
function tryParseCloudinaryUrl(raw: string | undefined) {
  if (!raw || typeof raw !== "string") return null;
  const m = raw.match(/^cloudinary:\/\/([^:]+):([^@]+)@(.+)$/);
  if (!m) return null;
  return { api_key: m[1], api_secret: m[2], cloud_name: m[3] };
}

try {
  // allow users to accidentally paste the full cloudinary://... value into
  // any of the three separate vars in Vercel. We detect and parse it.
  let parsed = tryParseCloudinaryUrl(process.env.CLOUDINARY_URL ?? undefined);
  if (!parsed) {
    // check common mis-paste locations
    parsed =
      tryParseCloudinaryUrl(process.env.CLOUDINARY_API_KEY ?? undefined) ||
      tryParseCloudinaryUrl(process.env.CLOUDINARY_API_SECRET ?? undefined) ||
      tryParseCloudinaryUrl(process.env.CLOUDINARY_CLOUD_NAME ?? undefined);
  }

  if (parsed) {
    cloudinaryV2.config({
      cloud_name: parsed.cloud_name,
      api_key: parsed.api_key,
      api_secret: parsed.api_secret,
    });
  } else if (process.env.CLOUDINARY_URL) {
    cloudinaryV2.config({ cloudinary_url: process.env.CLOUDINARY_URL });
  } else {
    cloudinaryV2.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
    });
  }
} catch (e) {
  // log config-time issues; actual upload errors will still be caught later
  console.error("Cloudinary config error:", e);
}

// DEBUG: log presence of Cloudinary environment variables (no secrets are printed)
// Also show whether we parsed a full URL from a mis-pasted value.
console.log("Cloudinary env presence:", {
  CLOUDINARY_URL: !!process.env.CLOUDINARY_URL,
  CLOUDINARY_CLOUD_NAME: !!process.env.CLOUDINARY_CLOUD_NAME,
  CLOUDINARY_API_KEY: !!process.env.CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET: !!process.env.CLOUDINARY_API_SECRET,
});

const CLOUDINARY_AVAILABLE = !!(
  process.env.CLOUDINARY_URL ||
  (process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET &&
    process.env.CLOUDINARY_CLOUD_NAME)
);

function uploadBufferToCloudinary(buffer: Buffer): Promise<UploadApiResponse> {
  if (!CLOUDINARY_AVAILABLE) {
    return Promise.reject(
      new Error(
        "Cloudinary não está configurado. Defina CLOUDINARY_URL ou CLOUDINARY_API_KEY/CLOUDINARY_API_SECRET/CLOUDINARY_CLOUD_NAME"
      )
    );
  }

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

function fileFilter(
  _req: unknown,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) {
  cb(null, allowedMimes.includes(file.mimetype));
}

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter,
});

// typed request shape used when multer runs
type MulterReq = NextApiRequest & {
  files?: Express.Multer.File[];
  body?: Record<string, unknown>;
};

// helper to run middleware (accept Express RequestHandler safely)
function runMiddleware(
  req: NextApiRequest,
  res: NextApiResponse,
  fn: unknown
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    try {
      const mw = fn as RequestHandler;
      mw(
        req as unknown as ExpressRequest,
        res as unknown as ExpressResponse,
        (result?: unknown) => {
          if (result instanceof Error) return reject(result);
          resolve();
        }
      );
    } catch (e) {
      reject(e);
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
    // run multer
    await runMiddleware(req, res, upload.array("arquivos"));
    const r = req as MulterReq;

    const atividadeIdRaw = r.body?.atividadeId ?? r.body?.atividade_id;
    const atividadeId =
      atividadeIdRaw !== undefined ? Number(atividadeIdRaw) : NaN;
    if (!atividadeId || Number.isNaN(atividadeId)) {
      return res
        .status(400)
        .json({ error: "atividadeId é obrigatório e deve ser numérico" });
    }

    const files = r.files ?? [];
    if (files.length === 0)
      return res.status(400).json({ error: "Nenhum arquivo enviado" });

    const created: AtividadeArquivo[] = [];
    const errors: { filename: string; message: string }[] = [];

    const atividadeExists = await prisma.atividade.findUnique({
      where: { idAtividade: atividadeId },
    });
    if (!atividadeExists) {
      return res.status(400).json({ error: "Atividade não encontrada" });
    }

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
          message: "Arquivo excede o tamanho máximo (5MB)",
        });
        continue;
      }

      try {
        const buf = (f as Express.Multer.File & { buffer?: Buffer }).buffer as
          | Buffer
          | undefined;
        if (!buf) throw new Error("No buffer available for file");
        const uploadRes = await uploadBufferToCloudinary(buf);
        const secureUrl = uploadRes.secure_url ?? uploadRes.url;
        if (!secureUrl) throw new Error("No URL returned from Cloudinary");

        const record = await prisma.atividadeArquivo.create({
          data: { url: secureUrl, tipoArquivo: f.mimetype, atividadeId },
        });
        created.push(record);
      } catch (dbErr: unknown) {
        const msg = dbErr instanceof Error ? dbErr.message : String(dbErr);
        console.error(
          "Erro ao gravar DB/Upload para arquivo:",
          f.originalname,
          msg
        );
        errors.push({
          filename: f.originalname,
          message: "Erro ao salvar no banco ou upload",
        });
      }
    }

    if (created.length === 0)
      return res.status(400).json({ uploaded: 0, arquivos: [], errors });
    return res
      .status(201)
      .json({ uploaded: created.length, arquivos: created, errors });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("Upload handler error:", msg);
    return res.status(500).json({ error: "Erro interno no servidor" });
  }
}
