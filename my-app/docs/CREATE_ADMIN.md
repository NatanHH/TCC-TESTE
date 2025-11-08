# Criar Administrador (seed)

Instruções para criar um usuário administrador no banco de produção.

ATENÇÃO: Siga com cuidado. Não deixe endpoints temporários em produção depois do uso.

Passos rápidos

1. Puxe variáveis do Vercel (produção):

```powershell
npx vercel env pull .env.production --environment=production
```

2. Carregue as variáveis no PowerShell (exemplo):

```powershell
Get-Content .env.production | ForEach-Object {
  if ($_ -match '^[^#].*=') {
    $parts = $_ -split '=', 2
    $name = $parts[0].Trim()
    $value = $parts[1].Trim('"')
    Set-Item -Path env:$name -Value $value
  }
}

# confirmar
Get-ChildItem env:DATABASE_URL
```

3. Gere clientes do Prisma e execute o seed:

```powershell
npx prisma generate
npm run seed:admin
```

4. Alternativa (rota temporária protegida)

Depois de fazer deploy, você pode habilitar temporariamente a rota
`/api/__create-admin` e invocar com o header `x-one-time-secret` igual
à variável `ONETIME_ADMIN_SECRET` definida no Vercel:

```bash
curl -X POST https://<seu-deploy>.vercel.app/api/__create-admin \
  -H "x-one-time-secret: <ONETIME_ADMIN_SECRET>"
```

REMOVA A ROTA `src/pages/api/__create-admin.ts` IMEDIATAMENTE APÓS O USO.

Notas de segurança e compatibilidade

- Se sua `DATABASE_URL` for `file:...` (SQLite), não use esse arquivo como
  banco de produção em Vercel; arquivos locais não são persistidos em serverless.
  Mude para um DB remoto (Postgres, MySQL, PlanetScale, Neon etc.).
- Se seu schema Prisma não possui o model `Administrador`, adapte `prisma/seed-admin.ts`
  para usar o model correto (ex.: `User`) e os nomes de campos (ex.: `password` ao
  invés de `senha`, `isAdmin` ao invés de `role`). Há comentários no arquivo indicando
  onde adaptar.
- Não deixe a senha gerada em logs públicos. Se o script gerar uma senha, ela será
  mostrada apenas uma vez; troque a senha imediatamente após o login.

Problemas comuns

- `npx ts-node` não encontrado: instale devDependencies localmente (`npm install`).
- Erros de permissão/credenciais: verifique `DATABASE_URL` e as permissões do usuário
  no banco remoto.
- Erros de migrations: verifique se as migrations foram aplicadas (se necessário
  rode `npx prisma migrate deploy`).
