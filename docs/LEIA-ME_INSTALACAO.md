# PTS Compartilhado – Pacote de implantação

Documento para a equipe de TI da APAE Campo Grande / CER IV.

## O que tem neste pacote

| Arquivo | Para que serve |
|---|---|
| `pts-compartilhado-servidor.html` | O sistema (telas). Um único arquivo HTML, sem dependências de instalação. |
| `sql/01_estrutura.sql` | Cria as tabelas, as regras de acesso e as funções do banco (PostgreSQL). |
| `sql/02_dados_demonstracao.sql` | Opcional. Pacientes e profissionais **fictícios** para treinamento. |
| `sql/03_rede_campo_grande.sql` | Cadastro inicial de UBS/USF, CRAS e CAPS de Campo Grande-MS. |
| `sql/04_seguranca.sql` | Reforços de segurança: visibilidade só da equipe, saída por inatividade, registro de acessos e verificação em duas etapas. **Obrigatório.** |
| `SEGURANCA_E_LGPD.md` | Como os dados são protegidos. Para o jurídico/encarregado de dados. |

## Como o sistema funciona (arquitetura)

```
Navegador do profissional  ──HTTPS──►  API do Supabase (PostgREST)  ──►  PostgreSQL
 (arquivo HTML)                         chama apenas funções pts_*         tabelas pts_* (RLS ligado)
```

- O navegador **nunca acessa as tabelas diretamente**. Todas as tabelas `pts_*` têm Row Level Security ligado e nenhuma política: o acesso direto é negado.
- O sistema chama apenas funções `pts_*` (SECURITY DEFINER), que validam a sessão do usuário a cada chamada e aplicam as permissões (cada profissional edita só a própria área do PTS; só a coordenação cadastra usuários e altera configurações).
- Login próprio do sistema (tabela `pts_usuarios`), com senha criptografada (bcrypt), bloqueio após 5 tentativas erradas e sessões que expiram após 12 horas sem uso.
- PDFs assinados pelo gov.br ficam na tabela `pts_arquivos`.
- Registro de ações em `pts_auditoria` (login, exclusões, cadastro de profissionais) e de leituras em `pts_acessos`.

## Opção A – Supabase em nuvem (usada no piloto)

1. Criar uma conta no Supabase **com e-mail institucional** e um projeto na região **São Paulo (sa-east-1)**.
2. No *SQL Editor*, rodar `sql/01_estrutura.sql`, depois `sql/03_rede_campo_grande.sql` e depois `sql/04_seguranca.sql`.
3. Criar o primeiro usuário da coordenação (trocar e-mail, nome e senha):
   ```sql
   insert into public.pts_usuarios(email, senha_hash, nome, area, registro, papel)
   values ('coordenacao@exemplo.org.br', extensions.crypt('SENHA-FORTE-AQUI', extensions.gen_salt('bf')),
           'Nome da Coordenação', 'fisio', '', 'coord');
   ```
   Os demais profissionais são cadastrados pela própria coordenação, dentro do sistema (Equipe e configurações).
4. Em *Project Settings → API*, copiar a **URL do projeto** e a chave **anon/publishable**.
5. No arquivo `pts-compartilhado-servidor.html`, procurar a linha que começa com `const SRV=` e trocar `url` e `key` pelos valores do passo 4.
6. Publicar o HTML (ver "Onde colocar o HTML", abaixo).

## Opção B – Servidor próprio da APAE (Supabase self-hosted)

O Supabase é de código aberto e roda com Docker no servidor da instituição.

**Requisitos (documentação oficial do Supabase):** Linux (Ubuntu/Debian ou RHEL) com Docker e Docker Compose; mínimo de 4 GB de RAM, 2 núcleos e 40 GB de SSD; recomendado 8 GB, 4 núcleos e 80 GB.

1. Instalar Git, Docker e Docker Compose.
2. Seguir o guia oficial: https://supabase.com/docs/guides/self-hosting/docker
   - gerar as chaves com `utils/generate-keys.sh`;
   - definir `SUPABASE_PUBLIC_URL`, `API_EXTERNAL_URL`, `SITE_URL` e uma `DASHBOARD_PASSWORD` forte no `.env`;
   - iniciar com `sh run.sh start` e conferir com `docker compose ps`.
3. Configurar **HTTPS** com um proxy reverso (Nginx, Caddy ou Traefik) e um domínio (ex.: `pts.apae-cg.org.br`).
4. Serviços que o PTS Compartilhado **não usa** e podem ser desligados no `docker-compose.yml` para economizar memória: Realtime, Storage, imgproxy, Edge Functions e Analytics/Logs.
5. Rodar os scripts SQL e criar o usuário da coordenação como nos passos 2 e 3 da Opção A (pelo Studio, em `http://<servidor>:8000`).
6. Trocar `url` e `key` no HTML (passo 5 da Opção A).

**Alternativa mínima:** como o sistema usa só PostgreSQL + PostgREST, a TI pode rodar apenas esses dois componentes (sem o restante do Supabase). Nesse caso, criar os papéis `anon` e `authenticated` antes de rodar `01_estrutura.sql` e apontar o PostgREST para o schema `public`. O banco precisa da extensão `pgcrypto` no schema `extensions` (senhas e códigos de duas etapas).

O site carrega duas bibliotecas do cdnjs.cloudflare.com: jsPDF (gerar a ficha em PDF) e qrcode-generator (QR code das duas etapas). Se a rede do CER bloquear sites externos, baixe os dois arquivos e sirva junto com o HTML.

## Onde colocar o HTML

Qualquer uma destas opções funciona:
- **Servidor web da APAE** (Nginx/Apache/IIS) – recomendado, com HTTPS.
- **Pasta de rede do CER** – cada profissional abre o arquivo no navegador.
- **Hospedagem estática** (GitHub Pages, Netlify, Cloudflare Pages).

O arquivo carrega duas bibliotecas públicas (gerador de PDF jsPDF, do cdnjs.cloudflare.com, e uma fonte do Google Fonts). Se a rede bloquear esses endereços, a TI pode baixá-los e servi-los localmente.

## Rotinas da TI

- **Backup diário** do banco (`pg_dump`), guardado fora do servidor, com teste de restauração periódico.
- **Atualizações de segurança** do sistema operacional e do Docker.
- **Contas:** desativar o usuário quando o profissional sair da instituição (a coordenação faz isso pelo sistema).
- **Limpeza de sessões antigas** (opcional): `delete from public.pts_sessoes where expira_em < now();`

## Dados de demonstração

O arquivo `02_dados_demonstracao.sql` cria 6 profissionais e 4 pacientes **fictícios** para treinamento. Antes de rodar, troque `<SENHA_COORDENACAO>` por uma senha. **Não use esse arquivo em produção.** Para apagar os dados de demonstração:

```sql
delete from public.pts_pts where id in ('ex1','ex2','ex3','ex4');
delete from public.pts_pedidos where id = 'ped1';
delete from public.pts_usuarios where email like '%@pts.teste';
```
