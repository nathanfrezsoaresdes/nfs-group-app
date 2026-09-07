// Netlify Function: armazenamento seguro das credenciais de acesso Copel.
//
// REGRA DE OURO DESTE ARQUIVO: a senha da Copel em texto puro NUNCA existe fora daqui.
// O frontend (index.html) nunca vê, guarda nem processa a senha — ele só manda a senha
// UMA VEZ (ao cadastrar/alterar) e, depois, só pede pra "revelar" quando alguém com
// permissão explicitamente pede. Fora isso, toda leitura (listar) devolve os dados
// SEM o campo de senha.
//
// Isso usa duas coisas que precisam estar configuradas no Netlify (nunca no código):
//   1) COPEL_CRED_SECRET_KEY — uma chave de 32 bytes (256 bits) em base64, usada pra
//      criptografar/descriptografar a senha com AES-256-GCM.
//   2) FIREBASE_SERVICE_ACCOUNT — o JSON da conta de serviço do Firebase (Admin SDK),
//      como uma única linha de texto, pra essa função conseguir ler/escrever no
//      Firestore com privilégio de servidor (não depende das regras do Firestore do
//      cliente, então mesmo com o projeto em "modo de teste" essa coleção fica segura,
//      já que só esta função consegue falar com ela).
//
// IMPORTANTE (limitação que precisa ser resolvida antes da integração real da Copel,
// ver item 30 do pedido): hoje o sistema não tem um jeito do SERVIDOR confirmar de
// verdade quem está pedindo pra revelar uma senha — a permissão "revelar credencial"
// é checada no navegador (front-end), e o nome de quem pediu é só registrado aqui pra
// auditoria, não é uma autenticação real. Antes de ligar isso à Copel de verdade,
// o certo é adicionar um sistema de login com token verificável no servidor (por
// exemplo, Firebase Authentication), e esta função passar a exigir e validar esse
// token antes de descriptografar qualquer coisa.

const crypto = require('crypto');
const admin = require('firebase-admin');

const COLECAO = 'copel_credenciais';

function getFirestore(){
  if(!admin.apps.length){
    const credenciais = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(credenciais) });
  }
  return admin.firestore();
}

function getChaveCriptografia(){
  const chaveBase64 = process.env.COPEL_CRED_SECRET_KEY;
  if(!chaveBase64) throw new Error('COPEL_CRED_SECRET_KEY não configurada no ambiente do Netlify.');
  const chave = Buffer.from(chaveBase64, 'base64');
  if(chave.length !== 32) throw new Error('COPEL_CRED_SECRET_KEY precisa ter 32 bytes (256 bits) em base64.');
  return chave;
}

function criptografar(textoPlano){
  const chave = getChaveCriptografia();
  const iv = crypto.randomBytes(12); // recomendado para GCM
  const cifra = crypto.createCipheriv('aes-256-gcm', chave, iv);
  const criptografado = Buffer.concat([cifra.update(textoPlano, 'utf8'), cifra.final()]);
  const authTag = cifra.getAuthTag();
  return {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: criptografado.toString('base64')
  };
}

function descriptografar(pacote){
  const chave = getChaveCriptografia();
  const decifra = crypto.createDecipheriv('aes-256-gcm', chave, Buffer.from(pacote.iv, 'base64'));
  decifra.setAuthTag(Buffer.from(pacote.authTag, 'base64'));
  const textoPlano = Buffer.concat([
    decifra.update(Buffer.from(pacote.ciphertext, 'base64')),
    decifra.final()
  ]);
  return textoPlano.toString('utf8');
}

// Nunca inclui o campo de senha na resposta — usado em toda leitura que não seja "revelar".
function removerSenha(doc){
  const { senhaCopelCriptografada, ...resto } = doc;
  return resto;
}

function normalizarDocumento(valor){
  return String(valor || '').replace(/\D/g, '');
}
function validarCpfCnpj(doc){
  const limpo = normalizarDocumento(doc);
  if(limpo.length === 11) return { valido: true, tipo: 'cpf', normalizado: limpo };
  if(limpo.length === 14) return { valido: true, tipo: 'cnpj', normalizado: limpo };
  return { valido: false, tipo: null, normalizado: limpo };
}

exports.handler = async function(event){
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, body: JSON.stringify({ erro: 'Método não permitido.' }) };
  }

  let payload;
  try{
    payload = JSON.parse(event.body || '{}');
  }catch(e){
    return { statusCode: 400, body: JSON.stringify({ erro: 'Requisição inválida.' }) };
  }

  const { acao } = payload;

  try{
    const db = getFirestore();
    const ref = db.collection(COLECAO);

    if(acao === 'listar'){
      const snap = await ref.get();
      const lista = snap.docs.map(d => removerSenha({ id: d.id, ...d.data() }));
      return resposta200({ credenciais: lista });
    }

    if(acao === 'salvar'){
      const { id, dados, usuario } = payload;
      const docValidacao = validarCpfCnpj(dados.cpfCnpj);
      if(!docValidacao.valido){
        return resposta400('CPF (11 dígitos) ou CNPJ (14 dígitos) inválido.');
      }

      const agora = new Date().toISOString();
      const registro = {
        clienteRazaoSocial: dados.clienteRazaoSocial || '',
        cpfCnpj: docValidacao.normalizado,
        tipoDocumento: docValidacao.tipo,
        loginCopel: dados.loginCopel || docValidacao.normalizado,
        ucs: Array.isArray(dados.ucs) ? dados.ucs.filter(Boolean) : [],
        empresaResponsavelId: dados.empresaResponsavelId || '',
        observacoes: dados.observacoes || '',
        status: dados.status || 'nao_testado',
        atualizadoEm: agora,
        atualizadoPor: usuario || 'desconhecido'
      };

      // Só re-criptografa a senha se uma nova senha foi realmente enviada nesta chamada.
      // Editar outros campos sem mexer na senha não deve exigir redigitar a senha.
      if(dados.senhaCopel){
        registro.senhaCopelCriptografada = criptografar(dados.senhaCopel);
      }

      let idFinal = id;
      if(id){
        await ref.doc(id).set(registro, { merge: true });
      }else{
        registro.criadoEm = agora;
        registro.criadoPor = usuario || 'desconhecido';
        registro.status = registro.status || 'nao_testado';
        const novoDoc = await ref.add(registro);
        idFinal = novoDoc.id;
      }

      const salvo = await ref.doc(idFinal).get();
      return resposta200({ credencial: removerSenha({ id: idFinal, ...salvo.data() }) });
    }

    if(acao === 'revelar'){
      const { id, usuario, motivo } = payload;
      if(!id) return resposta400('Informe o id da credencial.');
      const doc = await ref.doc(id).get();
      if(!doc.exists) return resposta400('Credencial não encontrada.');
      const dados = doc.data();
      if(!dados.senhaCopelCriptografada) return resposta400('Essa credencial ainda não tem senha cadastrada.');

      const senha = descriptografar(dados.senhaCopelCriptografada);

      // Auditoria: registra QUEM e QUANDO revelou — nunca a senha em si.
      await db.collection('copel_credenciais_auditoria').add({
        credencialId: id, acao: 'Credencial revelada', usuario: usuario || 'desconhecido',
        motivo: motivo || '', data: new Date().toISOString()
      });

      return resposta200({ senha });
    }

    if(acao === 'excluir'){
      const { id, usuario } = payload;
      if(!id) return resposta400('Informe o id da credencial.');
      await ref.doc(id).delete();
      await db.collection('copel_credenciais_auditoria').add({
        credencialId: id, acao: 'Credencial excluída', usuario: usuario || 'desconhecido', data: new Date().toISOString()
      });
      return resposta200({ ok: true });
    }

    if(acao === 'atualizarStatus'){
      const { id, status, usuario } = payload;
      if(!id || !status) return resposta400('Informe id e status.');
      await ref.doc(id).set({ status, ultimaVerificacao: new Date().toISOString() }, { merge: true });
      await db.collection('copel_credenciais_auditoria').add({
        credencialId: id, acao: 'Mudança de status para "' + status + '"', usuario: usuario || 'desconhecido', data: new Date().toISOString()
      });
      return resposta200({ ok: true });
    }

    if(acao === 'testarAcesso'){
      // Preparado para a integração futura (item 21/22 do pedido). Ainda não existe
      // integração real com o login da Copel — não simular sucesso/falha nenhum.
      return resposta200({ pendente: true, mensagem: 'Pendente de integração.' });
    }

    return resposta400('Ação não reconhecida.');

  }catch(err){
    // Nunca deixa a mensagem de erro vazar dados sensíveis (a própria lib de crypto não
    // inclui a senha na mensagem de erro, mas ainda assim evitamos ecoar o payload).
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ erro: 'Erro ao processar credenciais Copel: ' + err.message })
    };
  }
};

function resposta200(corpo){
  return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(corpo) };
}
function resposta400(mensagem){
  return { statusCode: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ erro: mensagem }) };
}
