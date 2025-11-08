import prisma from "./prisma";
import bcrypt from "bcryptjs";

// Module-level singleton promise so seeding runs only once per process.
let ensureAdminPromise: Promise<void> | null = null;

async function doEnsureAdmin(): Promise<void> {
  try {
    if (process.env.DISABLE_AUTO_CREATE_ADMIN === "true") return;

    const email = (
      process.env.TEST_ADMIN_EMAIL || "admin@exemplo.com"
    ).toLowerCase();
    const senha = process.env.TEST_ADMIN_PASS || "123";

    const exists = await prisma.administrador.findUnique({ where: { email } });
    if (exists) {
      // already present, nothing to do
      console.log(`ensureAdmin: administrator already exists (${email})`);
      return;
    }

    const hash = bcrypt.hashSync(senha, 10);

    await prisma.administrador.create({
      data: {
        nome: "Admin",
        email,
        senha: hash,
      },
    });

    console.log("ensureAdmin: created test administrator", email);
  } catch (err) {
    console.error("ensureAdmin: failed to ensure administrator:", err);
    // don't throw so the app can continue even if seeding fails
  }
}

/**
 * Ensure the admin exists. Returns a promise that resolves when seeding is done.
 * The function is idempotent and will only run the seeding once per process.
 */
export function ensureAdmin(): Promise<void> {
  if (!ensureAdminPromise) {
    ensureAdminPromise = doEnsureAdmin();
  }
  return ensureAdminPromise;
}

// Auto-start the seeding when this module is imported, but only when not disabled.
// By default we run in development; in production it only runs if TEST_ADMIN_AUTO_CREATE=true
if (
  process.env.DISABLE_AUTO_CREATE_ADMIN !== "true" &&
  (process.env.NODE_ENV !== "production" ||
    process.env.TEST_ADMIN_AUTO_CREATE === "true")
) {
  // fire-and-forget; errors are logged inside doEnsureAdmin
  ensureAdmin().catch((e) => console.error("ensureAdmin auto-start error:", e));
}
