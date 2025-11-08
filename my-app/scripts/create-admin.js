// simple script to create an Administrador row for testing login
// USAGE: from project root "my-app" run: node .\scripts\create-admin.js
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");

(async function main() {
  const prisma = new PrismaClient();
  try {
    const email = process.env.TEST_ADMIN_EMAIL || "admin@exemplo.com";
    const senha = process.env.TEST_ADMIN_PASS || "123";
    const hash = bcrypt.hashSync(senha, 10);

    // try to find existing
    const exists = await prisma.administrador.findUnique({ where: { email } });
    if (exists) {
      console.log("Administrador já existe:", { email });
      console.log("Use essas credenciais para testar: ", { email, senha });
      process.exit(0);
    }

    const created = await prisma.administrador.create({
      data: {
        nome: "Admin",
        email: email.toLowerCase(),
        senha: hash,
      },
    });

    console.log(
      "Administrador criado com id:",
      created.idAdm || created.id || "unknown"
    );
    console.log("Use essas credenciais para testar: ", { email, senha });
  } catch (err) {
    console.error("erro ao criar admin:", err);
    process.exitCode = 1;
  } finally {
    try {
      await new PrismaClient().$disconnect();
    } catch {}
  }
})();
