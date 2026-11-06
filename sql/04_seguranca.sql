-- PTS Compartilhado · reforços de segurança (rodar depois de 01, 02 e 03)
-- 1) cada profissional só vê os PTS em que é responsável ou está na equipe (coordenação vê todos)
-- 2) sessão encerrada após 30 min sem uso (o site encerra antes, com 15 min)
-- 3) registro de quem abriu cada PTS
-- 4) verificação em duas etapas (código de 6 dígitos de aplicativo autenticador, padrão TOTP)

alter table public.pts_sessoes add column if not exists ultimo_uso timestamptz not null default now();
alter table public.pts_sessoes add column if not exists mfa_pendente boolean not null default false;
alter table public.pts_usuarios add column if not exists totp_segredo text;
alter table public.pts_usuarios add column if not exists totp_pendente text;
alter table public.pts_usuarios add column if not exists totp_ativo boolean not null default false;
alter table public.pts_usuarios add column if not exists totp_ultimo bigint;

create table if not exists public.pts_acessos(id bigserial primary key, usuario_id uuid references public.pts_usuarios(id) on delete set null, pts_id text not null, em timestamptz not null default now());
create index if not exists pts_acessos_pts on public.pts_acessos(pts_id, em desc);
alter table public.pts_acessos enable row level security;
revoke all on public.pts_acessos from anon, authenticated;

-- ---------- sessão ----------
create or replace function public.pts__usuario(p_token uuid) returns public.pts_usuarios
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios;
begin
  select us.* into u from public.pts_sessoes s join public.pts_usuarios us on us.id = s.usuario_id
   where s.token = p_token and s.expira_em > now() and s.ultimo_uso > now() - interval '30 minutes'
     and not s.mfa_pendente and us.ativo;
  if u.id is null then raise exception 'sessao_invalida' using errcode = '28000'; end if;
  update public.pts_sessoes set ultimo_uso = now() where token = p_token;
  return u;
end $$;
revoke all on function public.pts__usuario(uuid) from public, anon, authenticated;

-- consulta que NÃO conta como uso (verificação automática a cada 8 s e recarga automática)
create or replace function public.pts__usuario_passivo(p_token uuid) returns public.pts_usuarios
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios;
begin
  select us.* into u from public.pts_sessoes s join public.pts_usuarios us on us.id = s.usuario_id
   where s.token = p_token and s.expira_em > now() and s.ultimo_uso > now() - interval '30 minutes'
     and not s.mfa_pendente and us.ativo;
  if u.id is null then raise exception 'sessao_invalida' using errcode = '28000'; end if;
  return u;
end $$;
revoke all on function public.pts__usuario_passivo(uuid) from public, anon, authenticated;

create or replace function public.pts__publico(u public.pts_usuarios, eu boolean) returns jsonb
language sql immutable set search_path = '' as $$
  select jsonb_build_object('id',u.id,'email',u.email,'nome',u.nome,'area',u.area,'registro',u.registro,'papel',u.papel,'ativo',u.ativo,'doisFatores',u.totp_ativo)
    || case when eu then jsonb_build_object('pinHash',u.pin_hash,'assinaturaImg',u.assinatura_img) else '{}'::jsonb end
$$;
revoke all on function public.pts__publico(public.pts_usuarios, boolean) from public, anon, authenticated;

-- ---------- quem pode ver um PTS ----------
create or replace function public.pts__pode_ver(u public.pts_usuarios, pd jsonb) returns boolean
language sql immutable set search_path = '' as $$
  select coalesce(u.papel = 'coord', false) or pd is null
      or coalesce(pd->>'respId' = u.id::text, false) or coalesce(pd->>'respDoc' = u.id::text, false)
      or exists (select 1 from jsonb_each_text(coalesce(pd->'equipe','{}'::jsonb)) e where e.value = u.id::text)
$$;
revoke all on function public.pts__pode_ver(public.pts_usuarios, jsonb) from public, anon, authenticated;

create or replace function public.pts__pode_ver_id(u public.pts_usuarios, p_pts text) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((select public.pts__pode_ver(u, dados) from public.pts_pts where id = p_pts), true)
$$;
revoke all on function public.pts__pode_ver_id(public.pts_usuarios, text) from public, anon, authenticated;

-- ---------- TOTP (RFC 6238) ----------
create or replace function public.pts__base32(p text) returns bytea
language plpgsql immutable set search_path = '' as $$
declare alf text := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; bits text := ''; i int; v int; res bytea := ''::bytea; c text;
begin
  for i in 1..length(p) loop
    c := upper(substr(p, i, 1)); if c = '=' or c = ' ' then continue; end if;
    v := position(c in alf) - 1; if v < 0 then raise exception 'base32_invalido'; end if;
    bits := bits || lpad(v::bit(5)::text, 5, '0');
  end loop;
  i := 1;
  while i + 7 <= length(bits) loop
    res := res || set_byte('\x00'::bytea, 0, substr(bits, i, 8)::bit(8)::int);
    i := i + 8;
  end loop;
  return res;
end $$;
revoke all on function public.pts__base32(text) from public, anon, authenticated;

create or replace function public.pts__totp(p_segredo text, p_passo bigint) returns text
language plpgsql immutable set search_path = '' as $$
declare h bytea; o int; n bigint;
begin
  h := extensions.hmac(int8send(p_passo), public.pts__base32(p_segredo), 'sha1');
  o := get_byte(h, 19) & 15;
  n := ((get_byte(h, o) & 127)::bigint << 24) | (get_byte(h, o+1)::bigint << 16) | (get_byte(h, o+2)::bigint << 8) | get_byte(h, o+3)::bigint;
  return lpad((n % 1000000)::text, 6, '0');
end $$;
revoke all on function public.pts__totp(text, bigint) from public, anon, authenticated;

-- devolve o passo aceito (para impedir reutilização do mesmo código) ou null
create or replace function public.pts__totp_passo(p_segredo text, p_codigo text) returns bigint
language plpgsql stable set search_path = '' as $$
declare agora bigint := floor(extract(epoch from now()) / 30); d int;
begin
  if p_segredo is null or coalesce(p_codigo,'') !~ '^\s*\d{6}\s*$' then return null; end if;
  for d in -1..1 loop
    if public.pts__totp(p_segredo, agora + d) = trim(p_codigo) then return agora + d; end if;
  end loop;
  return null;
end $$;
revoke all on function public.pts__totp_passo(text, text) from public, anon, authenticated;

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
  delete from public.pts_sessoes where usuario_id = u.id and (expira_em < now() or ultimo_uso < now() - interval '30 minutes');
  if u.totp_ativo then
    insert into public.pts_sessoes(usuario_id, mfa_pendente, expira_em) values (u.id, true, now() + interval '5 minutes') returning token into t;
    return jsonb_build_object('precisa_codigo', true, 'desafio', t);
  end if;
  update public.pts_usuarios set tentativas = 0, bloqueado_ate = null where id = u.id;
  insert into public.pts_sessoes(usuario_id) values (u.id) returning token into t;
  insert into public.pts_auditoria(usuario_id, acao) values (u.id, 'login');
  return jsonb_build_object('token', t, 'usuario', public.pts__publico(u, true));
end $$;

create or replace function public.pts_login_codigo(p_desafio uuid, p_codigo text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios; passo bigint;
begin
  select us.* into u from public.pts_sessoes s join public.pts_usuarios us on us.id = s.usuario_id
   where s.token = p_desafio and s.mfa_pendente and s.expira_em > now() and us.ativo;
  if u.id is null then return jsonb_build_object('erro','desafio_expirado'); end if;
  if u.bloqueado_ate is not null and u.bloqueado_ate > now() then return jsonb_build_object('erro','login_bloqueado'); end if;
  passo := public.pts__totp_passo(u.totp_segredo, p_codigo);
  if passo is null or passo <= coalesce(u.totp_ultimo, 0) then
    update public.pts_usuarios set tentativas = tentativas + 1,
      bloqueado_ate = case when tentativas + 1 >= 5 then now() + interval '15 minutes' else null end where id = u.id;
    if u.tentativas + 1 >= 5 then delete from public.pts_sessoes where token = p_desafio; return jsonb_build_object('erro','login_bloqueado'); end if;
    return jsonb_build_object('erro','codigo_invalido');
  end if;
  update public.pts_usuarios set tentativas = 0, bloqueado_ate = null, totp_ultimo = passo where id = u.id;
  update public.pts_sessoes set mfa_pendente = false, expira_em = now() + interval '12 hours', ultimo_uso = now() where token = p_desafio;
  insert into public.pts_auditoria(usuario_id, acao) values (u.id, 'login (duas etapas)');
  return jsonb_build_object('token', p_desafio, 'usuario', public.pts__publico(u, true));
end $$;

-- ---------- duas etapas: ativar / desativar ----------
create or replace function public.pts_2fa_iniciar(p_token uuid) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token); alf text := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; s text := ''; b bytea := extensions.gen_random_bytes(32); i int;
begin
  for i in 0..31 loop s := s || substr(alf, (get_byte(b, i) % 32) + 1, 1); end loop;
  update public.pts_usuarios set totp_pendente = s where id = u.id;
  return jsonb_build_object('segredo', s, 'uri',
    'otpauth://totp/PTS%20Compartilhado:' || replace(u.email,'@','%40') || '?secret=' || s || '&issuer=PTS%20Compartilhado&digits=6&period=30');
end $$;

create or replace function public.pts_2fa_confirmar(p_token uuid, p_codigo text) returns void
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token); passo bigint;
begin
  if u.totp_pendente is null then raise exception 'sem_configuracao'; end if;
  passo := public.pts__totp_passo(u.totp_pendente, p_codigo);
  if passo is null then raise exception 'codigo_invalido'; end if;
  update public.pts_usuarios set totp_segredo = totp_pendente, totp_pendente = null, totp_ativo = true, totp_ultimo = passo where id = u.id;
  insert into public.pts_auditoria(usuario_id, acao) values (u.id, 'ativou verificação em duas etapas');
  update public.pts_versao set n = n + 1 where id = 1;
end $$;

create or replace function public.pts_2fa_desativar(p_token uuid, p_codigo text) returns void
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
begin
  if not u.totp_ativo then return; end if;
  if public.pts__totp_passo(u.totp_segredo, p_codigo) is null then raise exception 'codigo_invalido'; end if;
  update public.pts_usuarios set totp_segredo = null, totp_ativo = false, totp_ultimo = null where id = u.id;
  insert into public.pts_auditoria(usuario_id, acao) values (u.id, 'desativou verificação em duas etapas');
  update public.pts_versao set n = n + 1 where id = 1;
end $$;

-- ---------- leitura ----------
create or replace function public.pts_versao(p_token uuid) returns bigint
language plpgsql security definer set search_path = '' as $$
begin perform public.pts__usuario_passivo(p_token); return (select n from public.pts_versao where id = 1); end $$;

drop function if exists public.pts_carregar(uuid);
create or replace function public.pts_carregar(p_token uuid, p_automatico boolean default false) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios;
begin
  if p_automatico then u := public.pts__usuario_passivo(p_token); else u := public.pts__usuario(p_token); end if;
  return jsonb_build_object(
    'eu', public.pts__publico(u, true),
    'versao', (select n from public.pts_versao where id = 1),
    'usuarios', coalesce((select jsonb_agg(public.pts__publico(x, false) order by x.nome) from public.pts_usuarios x), '[]'::jsonb),
    'config', coalesce((select jsonb_object_agg(chave, valor) from public.pts_config), '{}'::jsonb),
    'rede', coalesce((select jsonb_agg(dados) from public.pts_rede), '[]'::jsonb),
    'pedidos', coalesce((select jsonb_agg(dados) from public.pts_pedidos
        where u.papel = 'coord' or dados->>'solicitanteId' = u.id::text or dados->>'destinoId' = u.id::text), '[]'::jsonb),
    'lidos', coalesce((select jsonb_object_agg(pts_id, em) from public.pts_lidos where usuario_id = u.id), '{}'::jsonb),
    -- índice mínimo dos PTS de outras equipes: só prontuário e responsável, para evitar PTS duplicado
    'indice', coalesce((select jsonb_agg(jsonb_build_object('id', p.id, 'prontuario', p.dados->>'prontuario', 'respId', p.dados->>'respId',
        'ativo', (p.dados->>'assinadoEm') is null and (p.dados->>'encerradoEm') is null))
        from public.pts_pts p where not public.pts__pode_ver(u, p.dados)), '[]'::jsonb),
    'pts', coalesce((select jsonb_agg(jsonb_build_object(
        'dados', p.dados,
        'extra', (select e.dados from public.pts_extra e where e.pts_id = p.id),
        'areas', coalesce((select jsonb_object_agg(a.area, a.dados) from public.pts_areas a where a.pts_id = p.id), '{}'::jsonb),
        'mensagens', coalesce((select jsonb_agg(m.dados order by m.em) from public.pts_mensagens m where m.pts_id = p.id), '[]'::jsonb),
        'historico', coalesce((select jsonb_agg(h.dados order by h.em) from public.pts_historico h where h.pts_id = p.id), '[]'::jsonb),
        'gov', coalesce((select jsonb_object_agg(g.prof_id, g.dados) from public.pts_gov g where g.pts_id = p.id), '{}'::jsonb)
      )) from public.pts_pts p where public.pts__pode_ver(u, p.dados)), '[]'::jsonb)
  );
end $$;

-- ---------- gravação (mesma regra de antes + só mexe em PTS que o usuário pode ver) ----------
create or replace function public.pts_salvar(p_token uuid, p_ops jsonb) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
  o jsonb; t text; op text; k jsonb; d jsonb; pd jsonb; coord boolean; rej jsonb := '[]'::jsonb; nv bigint; pid text;
begin
  coord := u.papel = 'coord';
  for o in select * from jsonb_array_elements(coalesce(p_ops,'[]'::jsonb)) loop
    t := o->>'t'; op := o->>'op'; k := o->'k'; d := o->'d';
    pid := case when t = 'pts' or t = 'extra' then k->>'id' when t in ('area','msg','hist','gov','lido') then k->>'pts' else null end;
    if pid is not null and not public.pts__pode_ver_id(u, pid) then rej := rej || jsonb_build_array(o); continue; end if;
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
      select dados into pd from public.pts_pedidos where id = k->>'id';
      if coord or pd is null or pd->>'solicitanteId' = u.id::text or pd->>'destinoId' = u.id::text then
        if op = 'up' then
          insert into public.pts_pedidos(id, dados, atualizado_por) values (k->>'id', d, u.id)
          on conflict (id) do update set dados = excluded.dados, atualizado_em = now(), atualizado_por = u.id;
        else delete from public.pts_pedidos where id = k->>'id'; end if;
      else rej := rej || jsonb_build_array(o); end if;
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

-- ---------- arquivos: só baixa quem pode ver o PTS do arquivo ----------
create or replace function public.pts_arquivo_baixar(p_token uuid, p_id text) returns text
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
begin
  if not (u.papel = 'coord'
      or exists (select 1 from public.pts_arquivos where id = p_id and enviado_por = u.id)
      or exists (select 1 from public.pts_gov g join public.pts_pts p on p.id = g.pts_id where g.dados->>'arquivoId' = p_id and public.pts__pode_ver(u, p.dados))
      or exists (select 1 from public.pts_extra e join public.pts_pts p on p.id = e.pts_id where e.dados->'govBase'->>'arquivoId' = p_id and public.pts__pode_ver(u, p.dados)))
  then raise exception 'sem_permissao'; end if;
  return (select encode(conteudo, 'base64') from public.pts_arquivos where id = p_id);
end $$;

-- ---------- registro de acessos ----------
create or replace function public.pts_registrar_acesso(p_token uuid, p_pts text) returns void
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token);
begin
  if not public.pts__pode_ver_id(u, p_pts) then raise exception 'sem_permissao'; end if;
  if not exists (select 1 from public.pts_acessos where usuario_id = u.id and pts_id = p_pts and em > now() - interval '10 minutes') then
    insert into public.pts_acessos(usuario_id, pts_id) values (u.id, p_pts);
  end if;
end $$;

create or replace function public.pts_acessos_listar(p_token uuid, p_pts text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.pts_usuarios := public.pts__usuario(p_token); pd jsonb;
begin
  select dados into pd from public.pts_pts where id = p_pts;
  if not (u.papel = 'coord' or pd->>'respId' = u.id::text) then raise exception 'sem_permissao'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('nome', coalesce(us.nome,'(usuário removido)'), 'area', us.area, 'em', a.em) order by a.em desc)
    from (select * from public.pts_acessos where pts_id = p_pts order by em desc limit 300) a
    left join public.pts_usuarios us on us.id = a.usuario_id), '[]'::jsonb);
end $$;

-- ---------- coordenação: também pode desligar as duas etapas de alguém (ex.: celular perdido) ----------
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
    senha_hash = case when coalesce(p_dados->>'senha','') <> '' then extensions.crypt(p_dados->>'senha', extensions.gen_salt('bf')) else senha_hash end,
    totp_ativo = case when (p_dados->>'doisFatores') = 'false' then false else totp_ativo end,
    totp_segredo = case when (p_dados->>'doisFatores') = 'false' then null else totp_segredo end
  where id = p_id;
  if (p_dados->>'ativo') = 'false' or coalesce(p_dados->>'senha','') <> '' then delete from public.pts_sessoes where usuario_id = p_id and usuario_id <> u.id; end if;
  insert into public.pts_auditoria(usuario_id, acao, detalhe) values (u.id,
    case when (p_dados->>'doisFatores') = 'false' then 'desativou duas etapas de profissional' else 'alterou profissional' end, p_id::text);
  update public.pts_versao set n = n + 1 where id = 1;
end $$;

-- ---------- permissões das funções ----------
do $$ declare f text; begin
  foreach f in array array['pts_login(text,text)','pts_login_codigo(uuid,text)','pts_2fa_iniciar(uuid)','pts_2fa_confirmar(uuid,text)','pts_2fa_desativar(uuid,text)',
    'pts_versao(uuid)','pts_carregar(uuid,boolean)','pts_salvar(uuid,jsonb)','pts_arquivo_baixar(uuid,text)','pts_registrar_acesso(uuid,text)',
    'pts_acessos_listar(uuid,text)','pts_usuario_atualizar(uuid,uuid,jsonb)'] loop
    execute format('revoke all on function public.%s from public, authenticated', f);
    execute format('grant execute on function public.%s to anon', f);
  end loop;
end $$;
