// Netlify Function: recebe os dados lidos pela extensão NFS Copel (depois do
// login manual do usuário na Copel) e grava exatamente nos mesmos documentos
// que o NFS Group já lê (coleção "estoque_kv", chaves "estoque:copel_ucs" e
// "estoque:copel_faturas") — assim, depois de sincronizar, os dados aparecem
// na tela de Faturas Copel sem precisar de nenhuma mudança no frontend.
//
// SEGURANÇA / LIMITAÇÃO HONESTA: o pedido original pede para "validar usuário
// NFS". Hoje o NFS Group não tem um sistema de login com token verificável no
// servidor (Firebase Authentication, por exemplo) — os logins de colaborador
// são conferidos só no navegador. Por isso, a "validação" possível aqui é uma
// chave de API compartilhada (COPEL_SYNC_API_KEY), guardada nas variáveis de
// ambiente do Netlify e configurada uma vez na extensão — isso impede que
// QUALQUER UM na internet chame este endpoint, mas não é uma autenticação por
// usuário individual. Antes de expandir o uso, o ideal é adicionar um sistema
// de login real (ver observação equivalente em copel-credenciais.js).
//
// Variáveis de ambiente necessárias no Netlify (nunca no código):
//   FIREBASE_SERVICE_ACCOUNT — mesmo JSON de conta de serviço já usado por
//                               copel-credenciais.js.
//   COPEL_SYNC_API_KEY       — uma chave qualquer (ex: gerada com
//                               `openssl rand -hex 24`), que a extensão envia
//                               no cabeçalho "x-copel-sync-key".

const admin = require('firebase-admin');

const COLLECTION = 'estoque_kv';
const CHAVE_UCS = 'estoque:copel_ucs';
const CHAVE_FATURAS = 'estoque:copel_faturas';
const CHAVE_ULTIMA_SINC = 'estoque:copel_ultima_sinc';

function getFirestore(){
  if(!admin.apps.length){
    const credenciais = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(credenciais) });
  }
  return admin.firestore();
}

async function lerChave(db, chave){
  const snap = await db.collection(COLLECTION).doc(chave).get();
  if(!snap.exists) return null;
  const dados = snap.data();
  try{ return dados.value ? JSON.parse(dados.value) : null; }catch(e){ return null; }
}
async function gravarChave(db, chave, valor){
  await db.collection(COLLECTION).doc(chave).set({ value: JSON.stringify(valor), updatedAt: Date.now() });
}

function referenciaParaOrdenavel(ref){
  const MESES = { JAN:'01',FEV:'02',MAR:'03',ABR:'04',MAI:'05',JUN:'06',JUL:'07',AGO:'08',SET:'09',OUT:'10',NOV:'11',DEZ:'12' };
  if(!ref) return '';
  const m = String(ref).match(/([A-Z]{3})\/(\d{2})/i);
  if(!m) return String(ref);
  return '20' + m[2] + '-' + (MESES[m[1].toUpperCase()] || '01');
}

exports.handler = async function(event){
  // CORS/preflight (item raiz do bug reportado): o navegador manda um OPTIONS
  // antes do POST sempre que a requisição tem um cabeçalho customizado
  // (aqui, x-copel-sync-key). Sem responder isso corretamente, o navegador
  // bloqueia o POST de verdade ANTES de ele sair — e o fetch() da extensão
  // recebe um erro genérico de rede, sem status HTTP nenhum. Foi exatamente
  // isso que causou "falha de conexão" em 100% dos lotes.
  if(event.httpMethod === 'OPTIONS'){
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, x-copel-sync-key',
        'Access-Control-Max-Age': '86400'
      },
      body: ''
    };
  }

  if(event.httpMethod !== 'POST'){
    return resposta(405, { erro: 'Método não permitido.' });
  }

  const chaveEnviada = event.headers['x-copel-sync-key'] || event.headers['X-Copel-Sync-Key'];
  if(!process.env.COPEL_SYNC_API_KEY || chaveEnviada !== process.env.COPEL_SYNC_API_KEY){
    return resposta(401, { erro: 'Chave de sincronização inválida ou ausente.' });
  }

  let payload;
  try{
    payload = JSON.parse(event.body || '{}');
  }catch(e){
    return resposta(400, { erro: 'Requisição inválida.' });
  }

  // Ação leve pro botão "Testar conexão" da extensão — só confirma que a
  // chave é válida e que a função está no ar. Não toca no Firebase.
  if(payload.acao === 'testarConexao'){
    return resposta(200, { ok: true, mensagem: 'Conexão OK – Backend NFS Group acessível.' });
  }

  const debitos = Array.isArray(payload.debitos) ? payload.debitos : null;
  if(!debitos){
    return resposta(400, { erro: 'Envie um array "debitos".' });
  }

  // Validação de formato — item explícito do pedido ("validar formato dos dados")
  const invalidos = debitos.filter(d => !d || !d.uc);
  if(invalidos.length > 0){
    return resposta(400, { erro: `${invalidos.length} débito(s) sem UC — não é possível organizar com segurança.` });
  }

  try{
    const db = getFirestore();
    let copelUcs = (await lerChave(db, CHAVE_UCS)) || [];
    let copelFaturas = (await lerChave(db, CHAVE_FATURAS)) || [];

    let ucsNovas = 0, ucsAtualizadas = 0, faturasNovas = 0, faturasAtualizadas = 0;
    const agora = new Date().toISOString();

    debitos.forEach(d=>{
      let registroUc = copelUcs.find(u => u.uc === d.uc);
      if(!registroUc){
        registroUc = { uc: d.uc, titular: d.titular || null, endereco: d.endereco || null, cidade: null, estado: null, cpfCnpj: null, ultimaAtualizacao: agora };
        copelUcs.push(registroUc);
        ucsNovas++;
      }else{
        if(d.endereco) registroUc.endereco = d.endereco;
        registroUc.ultimaAtualizacao = agora;
        ucsAtualizadas++;
      }

      // Chave de deduplicação (item explícito do pedido): credencial + UC + referência + nº fatura.
      const idFatura = (payload.credencialId ? payload.credencialId + '_' : '') + d.uc + '_' + (d.numeroFatura || d.referencia || ('sem-ref-' + Date.now()));
      let registroFatura = copelFaturas.find(f => f.id === idFatura
        || (d.numeroFatura && f.numeroFatura === d.numeroFatura && f.uc === d.uc));

      if(!registroFatura){
        copelFaturas.push({
          id: idFatura, uc: d.uc, referencia: d.referencia || null,
          referenciaOrdenavel: referenciaParaOrdenavel(d.referencia),
          numeroFatura: d.numeroFatura || null,
          vencimento: d.vencimento || null, valor: d.valor != null ? d.valor : null,
          situacao: d.situacao || null, origem: d.origem || null,
          via: d.via || null, downloadAnterior: d.via === '2',
          linkDocumento: d.linkDocumento || null,
          statusManual: null, temPdf: false, pdfKey: null,
          processadoEm: agora, processadoPor: 'Extensão NFS Copel'
        });
        faturasNovas++;
      }else{
        registroFatura.referencia = d.referencia || registroFatura.referencia;
        registroFatura.numeroFatura = d.numeroFatura || registroFatura.numeroFatura;
        registroFatura.vencimento = d.vencimento || registroFatura.vencimento;
        registroFatura.valor = d.valor != null ? d.valor : registroFatura.valor;
        registroFatura.situacao = d.situacao || registroFatura.situacao;
        registroFatura.origem = d.origem || registroFatura.origem;
        if(d.via){ registroFatura.via = d.via; registroFatura.downloadAnterior = d.via === '2'; }
        if(d.linkDocumento) registroFatura.linkDocumento = d.linkDocumento;
        registroFatura.processadoEm = agora;
        registroFatura.processadoPor = 'Extensão NFS Copel';
        faturasAtualizadas++;
      }
    });

    await gravarChave(db, CHAVE_UCS, copelUcs);
    await gravarChave(db, CHAVE_FATURAS, copelFaturas);
    await gravarChave(db, CHAVE_ULTIMA_SINC, agora);

    const vencidas = copelFaturas.filter(f=>{
      if(!f.vencimento) return false;
      const hoje = new Date().toISOString().slice(0,10);
      return f.vencimento < hoje && f.statusManual !== 'paga';
    });
    const valorVencido = vencidas.reduce((s,f)=> s + (f.valor||0), 0);

    return resposta(200, {
      ok: true,
      ucsSincronizadas: ucsNovas + ucsAtualizadas,
      ucsNovas, ucsAtualizadas,
      faturasEncontradas: debitos.length,
      faturasNovas, faturasAtualizadas,
      faturasVencidas: vencidas.length,
      valorTotalVencido: valorVencido
    });

  }catch(err){
    return resposta(500, { erro: 'Erro ao sincronizar: ' + err.message });
  }
};

function resposta(statusCode, corpo){
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-copel-sync-key'
    },
    body: JSON.stringify(corpo)
  };
}
