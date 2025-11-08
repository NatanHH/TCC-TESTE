import type { NextApiRequest, NextApiResponse } from "next";
import "dotenv/config";
import { createAdmin } from "../../../prisma/seed-admin";

// REMOVA ESTA ROTA APÓS USO. Ela é temporária e deve ser apagada do repositório
// para não expor um ponto de criação de administrador.

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST")
    return res.status(405).json({ ok: false, message: "Method not allowed" });

  const secret = req.headers["x-one-time-secret"] as string | undefined;
  const expected = process.env.ONETIME_ADMIN_SECRET;
  if (!expected || !secret || secret !== expected) {
    return res.status(401).json({ ok: false, message: "Unauthorized" });
  }

  try {
    await createAdmin();
    return res
      .status(201)
      .json({ ok: true, created: true, message: "Admin created/updated" });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ ok: false, created: false, message: msg });
  }
}

/*
Usage (after deploy):

curl -X POST https://<your-deploy>.vercel.app/api/__create-admin \
  -H "x-one-time-secret: <ONETIME_ADMIN_SECRET>"

Remember: delete this file after you've created the admin.
*/
