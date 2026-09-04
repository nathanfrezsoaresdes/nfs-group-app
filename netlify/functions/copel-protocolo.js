// Netlify Function: consulta o status de um protocolo no site público da Copel.
// Reproduz, do lado do servidor, o mesmo fluxo que o navegador faz:
// 1) GET na página para pegar cookies de sessão + o token "ViewState" (a página é feita em JSF/Java)
// 2) POST simulando a pesquisa, com o número do protocolo e esse token
// 3) Extrai do HTML de resposta o texto da "Situação do serviço"
//
// IMPORTANTE: essa é uma automação de uma ferramenta pública (sem login), mas o site
// tem proteção anti-robô (WAF). Pode ser que, mesmo copiando os cabeçalhos certinhos,
// o site bloqueie por identificar que não é um navegador de verdade. Se isso acontecer,
// vamos precisar ajustar.

const BASE_URL = 'https://www.copel.com/slwweb/publico/acompanhamento/inicio.jsf';

const HEADERS_NAVEGADOR = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
};

function extrairCookies(resposta){
  // Node 18+/20 (ambiente do Netlify) suporta getSetCookie(); mantemos um fallback simples.
  let bruto = [];
  if(typeof resposta.headers.getSetCookie === 'function'){
    bruto = resposta.headers.getSetCookie();
  }else{
    const unico = resposta.headers.get('set-cookie');
    if(unico) bruto = [unico];
  }
  return bruto.map(c => c.split(';')[0]).join('; ');
}

exports.handler = async function(event){
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, body: JSON.stringify({ erro: 'Método não permitido.' }) };
  }

  let protocolo = '';
  try{
    const body = JSON.parse(event.body || '{}');
    protocolo = String(body.protocolo || '').trim();
  }catch(e){
    return { statusCode: 400, body: JSON.stringify({ erro: 'Requisição inválida.' }) };
  }

  if(!protocolo){
    return { statusCode: 400, body: JSON.stringify({ erro: 'Informe o número do protocolo.' }) };
  }

  try{
    // 1) Carrega a página pra pegar sessão + ViewState atuais
    const respostaInicial = await fetch(BASE_URL, { headers: HEADERS_NAVEGADOR });
    if(!respostaInicial.ok){
      return { statusCode: 502, body: JSON.stringify({ erro: `A Copel respondeu com erro (${respostaInicial.status}) ao abrir a página.` }) };
    }

    const cookies = extrairCookies(respostaInicial);
    const htmlInicial = await respostaInicial.text();

    const viewStateMatch = htmlInicial.match(/name="javax\.faces\.ViewState"[^>]*value="([^"]+)"/);
    const viewState = viewStateMatch ? viewStateMatch[1] : null;

    if(!viewState){
      return { statusCode: 502, body: JSON.stringify({ erro: 'Não encontrei o token de sessão da página da Copel. O site pode ter mudado ou bloqueado o acesso automático.' }) };
    }

    // 2) Envia a pesquisa (mesmos campos capturados do navegador real)
    const corpo = new URLSearchParams({
      'formPrincipal': 'formPrincipal',
      'formPrincipal:j_idt23': protocolo,
      'formPrincipal:btnPesquisar': '',
      'javax.faces.ViewState': viewState
    }).toString();

    const respostaBusca = await fetch(BASE_URL, {
      method: 'POST',
      headers: {
        ...HEADERS_NAVEGADOR,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': cookies,
        'Referer': BASE_URL
      },
      body: corpo
    });

    const htmlResultado = await respostaBusca.text();

    // 3) Tenta extrair a mensagem de status (ex: "Seu pedido está com a equipe executora e será atendido até o dia...")
    let statusTexto = null;
    const padraoPedido = htmlResultado.match(/Seu pedido est[^<]+/i);
    if(padraoPedido){
      statusTexto = padraoPedido[0].trim();
    }else{
      const padraoGenerico = htmlResultado.match(/Situa[cç][aã]o do servi[cç]o[\s\S]{0,400}?<[^>]*>\s*([^<]{5,300})\s*</i);
      if(padraoGenerico) statusTexto = padraoGenerico[1].trim();
    }

    if(!statusTexto){
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ erro: 'Não encontrei o status na resposta da Copel. O protocolo pode estar incorreto, ainda não ter sido processado, ou o site pode ter mudado o formato da página.' })
      };
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: statusTexto, consultadoEm: new Date().toISOString() })
    };

  }catch(err){
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ erro: 'Erro ao consultar a Copel: ' + err.message })
    };
  }
};
