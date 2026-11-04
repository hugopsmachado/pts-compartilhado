# PTS Compartilhado – Segurança da informação e LGPD

Documento de apoio para a coordenação, o jurídico e o encarregado de dados (DPO) da APAE Campo Grande.

## Quais dados o sistema trata

- **Dos profissionais:** nome, e-mail, área, registro no conselho e senha (guardada só como hash bcrypt, nunca em texto).
- **Dos usuários do CER (pacientes):** nome, prontuário, data de nascimento, hipótese diagnóstica, objetivos terapêuticos, diagnóstico ampliado (contexto familiar e social, endereço, genograma, ecomapa), plano de ações, mensagens da equipe e PDFs assinados.

Dados de saúde são **dados pessoais sensíveis** (Lei 13.709/2018, art. 5º, II). O tratamento se apoia na tutela da saúde, em procedimento realizado por profissionais e serviços de saúde (art. 11, II, "f").

## Medidas de segurança já implementadas (art. 46 da LGPD)

| Medida | Como funciona |
|---|---|
| Acesso só com login individual | Cada profissional tem e-mail e senha próprios. Não há conta compartilhada. |
| Senhas protegidas | Hash bcrypt. Mínimo de 8 caracteres. Bloqueio por 15 minutos após 5 tentativas erradas. |
| Sessão com prazo | A sessão expira após 12 horas sem uso. Desativar um profissional encerra as sessões dele na hora. |
| Banco fechado | As tabelas não podem ser lidas ou gravadas diretamente pela internet. Todo acesso passa por funções que conferem a sessão e as permissões. |
| Permissões por função | Cada profissional edita só a área dele no PTS. Só o responsável ou a coordenação exclui um PTS. Só a coordenação cadastra profissionais e muda configurações. |
| Conexão criptografada | HTTPS entre o navegador e o servidor. |
| Registro de ações | Login, exclusões e cadastros ficam registrados (`pts_auditoria`). Cada PTS tem um histórico de quem fez o quê e quando. |
| Dados no Brasil | No piloto, o servidor fica em São Paulo (Supabase, região sa-east-1). |

## O que a APAE precisa definir antes de usar com dados reais

1. **Onde os dados ficam:** nuvem (com contrato e cláusulas de proteção de dados) ou servidor próprio.
2. **Controlador e encarregado:** a APAE como controladora, com um encarregado (DPO) nomeado.
3. **Quem tem acesso:** lista de profissionais autorizados e quem pode cadastrá-los.
4. **Prazo de guarda:** os PTS fazem parte do prontuário e seguem as regras de guarda de prontuário do serviço (ver também a Lei 13.787/2018).
5. **Backup e incidentes:** rotina de backup e um plano de resposta a incidentes (art. 48 da LGPD).
6. **Termo de uso** para os profissionais, com orientações de sigilo.

## Limitações conhecidas da versão piloto

- Dois profissionais editando **o mesmo campo** do diagnóstico ampliado ou do plano de ações ao mesmo tempo: vale a última gravação. Os objetivos de cada área não têm esse problema, porque cada área é editada só pelo seu profissional.
- Atualização entre computadores a cada 8 segundos, aproximadamente (não é instantânea).
- O sistema não guarda cópia do prontuário completo, só o PTS. A ficha assinada continua indo para o prontuário físico.
