-- PTS Compartilhado · estrutura do banco (PostgreSQL / Supabase)
-- Todas as tabelas têm o prefixo pts_ e RLS ligado SEM políticas: ninguém acessa direto.
-- O acesso acontece apenas pelas funções pts_* (security definer), que validam a sessão do usuário.

create table if not exists public.pts_usuarios(
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  senha_hash text not null,
  nome text not null,
  area text not null check (area in ('fisio','fono','nutri','psico','to','ss')),
  registro text default '',
  papel text not null default 'prof' check (papel in ('prof','coord')),
  ativo boolean not null default true,
  pin_hash text,
  assinatura_img text,
  tentativas int not null default 0,
  bloqueado_ate timestamptz,
  criado_em timestamptz not null default now()
);
create table if not exists public.pts_sessoes(
  token uuid primary key default gen_random_uuid(),
  usuario_id uuid not null references public.pts_usuarios(id) on delete cascade,
  criado_em timestamptz not null default now(),
  expira_em timestamptz not null default now() + interval '12 hours'
);
create table if not exists public.pts_config(chave text primary key, valor jsonb);
create table if not exists public.pts_rede(id text primary key, dados jsonb not null, atualizado_em timestamptz default now());
create table if not exists public.pts_pts(id text primary key, dados jsonb not null, atualizado_em timestamptz default now(), atualizado_por uuid);
create table if not exists public.pts_extra(pts_id text primary key references public.pts_pts(id) on delete cascade, dados jsonb not null, atualizado_em timestamptz default now(), atualizado_por uuid);
create table if not exists public.pts_areas(pts_id text references public.pts_pts(id) on delete cascade, area text, dados jsonb not null, atualizado_em timestamptz default now(), atualizado_por uuid, primary key(pts_id,area));
create table if not exists public.pts_mensagens(id text primary key, pts_id text not null references public.pts_pts(id) on delete cascade, autor_id uuid, dados jsonb not null, em timestamptz default now());
create table if not exists public.pts_historico(id text primary key, pts_id text not null references public.pts_pts(id) on delete cascade, dados jsonb not null, autor_id uuid, em timestamptz default now());
create table if not exists public.pts_gov(pts_id text references public.pts_pts(id) on delete cascade, prof_id text, dados jsonb not null, primary key(pts_id,prof_id));
create table if not exists public.pts_pedidos(id text primary key, dados jsonb not null, atualizado_em timestamptz default now(), atualizado_por uuid);
create table if not exists public.pts_lidos(usuario_id uuid references public.pts_usuarios(id) on delete cascade, pts_id text, em text, primary key(usuario_id,pts_id));
create table if not exists public.pts_arquivos(id text primary key, nome text, conteudo bytea not null, enviado_por uuid, criado_em timestamptz default now());
create table if not exists public.pts_versao(id int primary key default 1, n bigint not null default 0, check (id=1));
insert into public.pts_versao(id,n) values (1,0) on conflict do nothing;
create table if not exists public.pts_auditoria(id bigserial primary key, usuario_id uuid, acao text, detalhe text, em timestamptz default now());

create index if not exists pts_mensagens_pts on public.pts_mensagens(pts_id);
create index if not exists pts_historico_pts on public.pts_historico(pts_id);
create index if not exists pts_sessoes_usuario on public.pts_sessoes(usuario_id);

do $$ declare t text; begin
  foreach t in array array['pts_usuarios','pts_sessoes','pts_config','pts_rede','pts_pts','pts_extra','pts_areas','pts_mensagens','pts_historico','pts_gov','pts_pedidos','pts_lidos','pts_arquivos','pts_versao','pts_auditoria'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
  end loop;
end $$;

-- ---------- funções internas ----------
create or replace function public.pts__usuario(p_token uuid) returns public.pts_usuarios
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios;
begin
  select us.* into u from public.pts_sessoes s join public.pts_usuarios us on us.id = s.usuario_id
   where s.token = p_token and s.expira_em > now() and us.ativo;
  if u.id is null then raise exception 'sessao_invalida' using errcode = '28000'; end if;
  update public.pts_sessoes set expira_em = now() + interval '12 hours' where token = p_token;
  return u;
end $$;
revoke all on function public.pts__usuario(uuid) from public, anon, authenticated;

create or replace function public.pts__publico(u public.pts_usuarios, eu boolean) returns jsonb
language sql immutable set search_path = '' as $$
  select jsonb_build_object('id',u.id,'email',u.email,'nome',u.nome,'area',u.area,'registro',u.registro,'papel',u.papel,'ativo',u.ativo)
    || case when eu then jsonb_build_object('pinHash',u.pin_hash,'assinaturaImg',u.assinatura_img) else '{}'::jsonb end
$$;
revoke all on function public.pts__publico(public.pts_usuarios, boolean) from public, anon, authenticated;

-- ---------- login ----------
create or replace function public.pts_login(p_email text, p_senha text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios; t uuid;
begin
  select * into u from public.pts_usuarios where email = lower(trim(p_email));
  if u.id is null then return jsonb_build_object('erro','login_invalido'); end if;
  if u.bloqueado_ate is not null and u.bloqueado_ate > now() then return jsonb_build_object('erro','login_bloqueado'); end if;
  if not u.ativo or u.senha_hash <> extensions.crypt(p_senha, u.senha_hash) then
    update public.pts_usuarios set tentativas = tentativas + 1,
      bloqueado_ate = case when tentativas + 1 >= 5 then now() + interval '15 minutes' else null end where id = u.id;
    return jsonb_build_object('erro','login_invalido');
  end if;
  update public.pts_usuarios set tentativas = 0, bloqueado_ate = null where id = u.id;
  delete from public.pts_sessoes where usuario_id = u.id and expira_em < now();
  insert into public.pts_sessoes(usuario_id) values (u.id) returning token into t;
  insert into public.pts_auditoria(usuario_id, acao) values (u.id, 'login');
  return jsonb_build_object('token', t, 'usuario', public.pts__publico(u, true));
end $$;

create or replace function public.pts_sair(p_token uuid) returns void
language sql security definer set search_path = '' as $$ delete from public.pts_sessoes where token = p_token $$;

create or replace function public.pts_trocar_senha(p_token uuid, p_atual text, p_nova text) returns void
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
begin
  if length(coalesce(p_nova,'')) < 8 then raise exception 'senha_curta'; end if;
  if u.senha_hash <> extensions.crypt(p_atual, u.senha_hash) then raise exception 'senha_atual_incorreta'; end if;
  update public.pts_usuarios set senha_hash = extensions.crypt(p_nova, extensions.gen_salt('bf')) where id = u.id;
  insert into public.pts_auditoria(usuario_id, acao) values (u.id, 'trocou a senha');
end $$;

-- ---------- leitura ----------
create or replace function public.pts_versao(p_token uuid) returns bigint
language plpgsql security definer set search_path = '' as $$
begin perform public.pts__usuario(p_token); return (select n from public.pts_versao where id = 1); end $$;

create or replace function public.pts_carregar(p_token uuid) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
begin
  return jsonb_build_object(
    'eu', public.pts__publico(u, true),
    'versao', (select n from public.pts_versao where id = 1),
    'usuarios', coalesce((select jsonb_agg(public.pts__publico(x, false) order by x.nome) from public.pts_usuarios x), '[]'::jsonb),
    'config', coalesce((select jsonb_object_agg(chave, valor) from public.pts_config), '{}'::jsonb),
    'rede', coalesce((select jsonb_agg(dados) from public.pts_rede), '[]'::jsonb),
    'pedidos', coalesce((select jsonb_agg(dados) from public.pts_pedidos), '[]'::jsonb),
    'lidos', coalesce((select jsonb_object_agg(pts_id, em) from public.pts_lidos where usuario_id = u.id), '{}'::jsonb),
    'pts', coalesce((select jsonb_agg(jsonb_build_object(
        'dados', p.dados,
        'extra', (select e.dados from public.pts_extra e where e.pts_id = p.id),
        'areas', coalesce((select jsonb_object_agg(a.area, a.dados) from public.pts_areas a where a.pts_id = p.id), '{}'::jsonb),
        'mensagens', coalesce((select jsonb_agg(m.dados order by m.em) from public.pts_mensagens m where m.pts_id = p.id), '[]'::jsonb),
        'historico', coalesce((select jsonb_agg(h.dados order by h.em) from public.pts_historico h where h.pts_id = p.id), '[]'::jsonb),
        'gov', coalesce((select jsonb_object_agg(g.prof_id, g.dados) from public.pts_gov g where g.pts_id = p.id), '{}'::jsonb)
      )) from public.pts_pts p), '[]'::jsonb)
  );
end $$;

-- ---------- gravação ----------
-- p_ops: lista de operações {t, op:'up'|'del', k:{...}, d:{...}}
create or replace function public.pts_salvar(p_token uuid, p_ops jsonb) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
  o jsonb; t text; op text; k jsonb; d jsonb; pd jsonb; coord boolean; rej jsonb := '[]'::jsonb; nv bigint;
begin
  coord := u.papel = 'coord';
  for o in select * from jsonb_array_elements(coalesce(p_ops,'[]'::jsonb)) loop
    t := o->>'t'; op := o->>'op'; k := o->'k'; d := o->'d';
    if t = 'pts' then
      if op = 'up' then
        insert into public.pts_pts(id, dados, atualizado_por) values (k->>'id', d, u.id)
        on conflict (id) do update set dados = excluded.dados, atualizado_em = now(), atualizado_por = u.id;
      else
        select dados into pd from public.pts_pts where id = k->>'id';
        if coord or pd->>'respId' = u.id::text then delete from public.pts_pts where id = k->>'id';
          insert into public.pts_auditoria(usuario_id, acao, detalhe) values (u.id, 'excluiu PTS', k->>'id');
        else rej := rej || jsonb_build_array(o); end if;
      end if;
    elsif t = 'extra' then
      insert into public.pts_extra(pts_id, dados, atualizado_por) values (k->>'id', d, u.id)
      on conflict (pts_id) do update set dados = excluded.dados, atualizado_em = now(), atualizado_por = u.id;
    elsif t = 'area' then
      select dados into pd from public.pts_pts where id = k->>'pts';
      if coord or pd->>'respId' = u.id::text or pd->'equipe'->>(k->>'area') = u.id::text
         or not exists (select 1 from public.pts_areas where pts_id = k->>'pts' and area = k->>'area') then
        insert into public.pts_areas(pts_id, area, dados, atualizado_por) values (k->>'pts', k->>'area', d, u.id)
        on conflict (pts_id, area) do update set dados = excluded.dados, atualizado_em = now(), atualizado_por = u.id;
      else rej := rej || jsonb_build_array(o); end if;
    elsif t = 'msg' then
      if d->>'autorId' = u.id::text then
        insert into public.pts_mensagens(id, pts_id, autor_id, dados) values (k->>'id', k->>'pts', u.id, d) on conflict (id) do nothing;
      else rej := rej || jsonb_build_array(o); end if;
    elsif t = 'hist' then
      insert into public.pts_historico(id, pts_id, dados, autor_id) values (k->>'id', k->>'pts', d, u.id) on conflict (id) do nothing;
    elsif t = 'gov' then
      if op = 'up' then
        insert into public.pts_gov(pts_id, prof_id, dados) values (k->>'pts', k->>'prof', d)
        on conflict (pts_id, prof_id) do update set dados = excluded.dados;
      else delete from public.pts_gov where pts_id = k->>'pts' and prof_id = k->>'prof'; end if;
    elsif t = 'ped' then
      if op = 'up' then
        insert into public.pts_pedidos(id, dados, atualizado_por) values (k->>'id', d, u.id)
        on conflict (id) do update set dados = excluded.dados, atualizado_em = now(), atualizado_por = u.id;
      else delete from public.pts_pedidos where id = k->>'id'; end if;
    elsif t = 'rede' then
      if op = 'up' then
        insert into public.pts_rede(id, dados) values (k->>'id', d) on conflict (id) do update set dados = excluded.dados, atualizado_em = now();
      else delete from public.pts_rede where id = k->>'id'; end if;
    elsif t = 'cfg' then
      if coord then insert into public.pts_config(chave, valor) values (k->>'id', d) on conflict (chave) do update set valor = excluded.valor;
      else rej := rej || jsonb_build_array(o); end if;
    elsif t = 'lido' then
      insert into public.pts_lidos(usuario_id, pts_id, em) values (u.id, k->>'pts', d#>>'{}') on conflict (usuario_id, pts_id) do update set em = excluded.em;
    elsif t = 'eu' then
      update public.pts_usuarios set pin_hash = d->>'pinHash', assinatura_img = d->>'assinaturaImg' where id = u.id;
    else rej := rej || jsonb_build_array(o); end if;
  end loop;
  update public.pts_versao set n = n + 1 where id = 1 returning n into nv;
  return jsonb_build_object('versao', nv, 'rejeitadas', rej);
end $$;

-- ---------- arquivos (PDFs assinados) ----------
create or replace function public.pts_arquivo_enviar(p_token uuid, p_id text, p_nome text, p_base64 text) returns void
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
begin
  if length(p_base64) > 14000000 then raise exception 'arquivo_grande'; end if;
  insert into public.pts_arquivos(id, nome, conteudo, enviado_por) values (p_id, p_nome, decode(p_base64, 'base64'), u.id)
  on conflict (id) do update set conteudo = excluded.conteudo, nome = excluded.nome;
end $$;
create or replace function public.pts_arquivo_baixar(p_token uuid, p_id text) returns text
language plpgsql security definer set search_path = '' as $$
begin perform public.pts__usuario(p_token);
  return (select encode(conteudo, 'base64') from public.pts_arquivos where id = p_id); end $$;

-- ---------- equipe (coordenação) ----------
create or replace function public.pts_usuario_criar(p_token uuid, p_email text, p_senha text, p_nome text, p_area text, p_registro text, p_papel text default 'prof') returns uuid
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token); nid uuid;
begin
  if u.papel <> 'coord' then raise exception 'sem_permissao'; end if;
  if length(coalesce(p_senha,'')) < 8 then raise exception 'senha_curta'; end if;
  insert into public.pts_usuarios(email, senha_hash, nome, area, registro, papel)
  values (lower(trim(p_email)), extensions.crypt(p_senha, extensions.gen_salt('bf')), p_nome, p_area, coalesce(p_registro,''), coalesce(nullif(p_papel,''),'prof'))
  returning id into nid;
  insert into public.pts_auditoria(usuario_id, acao, detalhe) values (u.id, 'cadastrou profissional', p_email);
  update public.pts_versao set n = n + 1 where id = 1;
  return nid;
end $$;
create or replace function public.pts_usuario_atualizar(p_token uuid, p_id uuid, p_dados jsonb) returns void
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
begin
  if u.papel <> 'coord' then raise exception 'sem_permissao'; end if;
  if p_id = u.id and (coalesce(p_dados->>'papel','coord') <> 'coord' or (p_dados->>'ativo') = 'false') then raise exception 'proprio_coord'; end if;
  if coalesce(p_dados->>'senha','') <> '' and length(p_dados->>'senha') < 8 then raise exception 'senha_curta'; end if;
  if p_dados ? 'nome' and trim(coalesce(p_dados->>'nome','')) = '' then raise exception 'nome_vazio'; end if;
  if p_dados ? 'email' and position('@' in coalesce(p_dados->>'email','')) = 0 then raise exception 'email_invalido'; end if;
  update public.pts_usuarios set
    nome = coalesce(nullif(trim(p_dados->>'nome'),''), nome),
    email = coalesce(nullif(lower(trim(p_dados->>'email')),''), email),
    area = coalesce(p_dados->>'area', area), registro = coalesce(trim(p_dados->>'registro'), registro),
    papel = coalesce(p_dados->>'papel', papel), ativo = coalesce((p_dados->>'ativo')::boolean, ativo),
    senha_hash = case when coalesce(p_dados->>'senha','') <> '' then extensions.crypt(p_dados->>'senha', extensions.gen_salt('bf')) else senha_hash end
  where id = p_id;
  if (p_dados->>'ativo') = 'false' then delete from public.pts_sessoes where usuario_id = p_id; end if;
  insert into public.pts_auditoria(usuario_id, acao, detalhe) values (u.id, 'alterou profissional', p_id::text);
  update public.pts_versao set n = n + 1 where id = 1;
end $$;

do $$ declare f text; begin
  foreach f in array array['pts_login(text,text)','pts_sair(uuid)','pts_trocar_senha(uuid,text,text)','pts_versao(uuid)','pts_carregar(uuid)','pts_salvar(uuid,jsonb)','pts_arquivo_enviar(uuid,text,text,text)','pts_arquivo_baixar(uuid,text)','pts_usuario_criar(uuid,text,text,text,text,text,text)','pts_usuario_atualizar(uuid,uuid,jsonb)'] loop
    execute format('revoke all on function public.%s from public', f);
    execute format('grant execute on function public.%s to anon, authenticated', f);
  end loop;
end $$;

-- O sistema usa apenas o papel anon (a sessão é validada pelas próprias funções).
do $$ declare f text; begin
  foreach f in array array['pts_login(text,text)','pts_sair(uuid)','pts_trocar_senha(uuid,text,text)','pts_versao(uuid)','pts_carregar(uuid)','pts_salvar(uuid,jsonb)','pts_arquivo_enviar(uuid,text,text,text)','pts_arquivo_baixar(uuid,text)','pts_usuario_criar(uuid,text,text,text,text,text,text)','pts_usuario_atualizar(uuid,uuid,jsonb)'] loop
    execute format('revoke execute on function public.%s from authenticated', f);
  end loop;
end $$;
