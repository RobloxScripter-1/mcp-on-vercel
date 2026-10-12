import { createHash, randomBytes } from 'node:crypto';
import { issueOAuthClaims, verifyOAuthClaims } from './oauth-crypto';

const BASE_URL = (process.env.MCP_PUBLIC_BASE_URL || 'https://mcp-on-vercel-msaiful0404-5024s-projects.vercel.app').replace(/\/+$/, '');
const RESOURCE = process.env.MCP_RESOURCE_URL || `${BASE_URL}/mcp`;
const GITHUB_CALLBACK = `${BASE_URL}/oauth/github/callback`;
const TTL = { client: 31536000, state: 600, code: 120, access: 3600, refresh: 2592000 };
type OAuthState = { client_id:string; redirect_uri:string; state:string; challenge:string; resource:string; scope:string; trace_id?:string };
const json=(x:unknown,status=200)=>new Response(JSON.stringify(x),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
const traceId=()=>randomBytes(8).toString('hex');
const traceByRequest=new WeakMap<Request,string>();
const traceFor=(req?:Request)=>req?(traceByRequest.get(req)||traceId()):traceId();
function safeDiagnosticText(value:unknown){
  let out=String(value??'unknown');
  for(const secret of [process.env.GITHUB_OAUTH_CLIENT_SECRET,process.env.GITHUB_PAT,process.env.PROXY_SECRET,process.env.UPSTASH_REDIS_REST_TOKEN,process.env.UPSTASH_REDIS_REST_URL].filter((v):v is string=>Boolean(v)))out=out.split(secret).join('[redacted]');
  return out
    .replace(/Bearer\s+\S+/gi,'Bearer [redacted]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]+\b/g,'[GitHub token redacted]')
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,'[GitHub token redacted]')
    .replace(/(client_secret|access_token|refresh_token|code_verifier|code_challenge|state|code)=([^&\s]+)/gi,'$1=[redacted]')
    .replace(/https?:\/\/\S+/gi,'[URL redacted]')
    .slice(0,320);
}
function requestInfo(req:Request){
  const u=new URL(req.url),names:string[]=[];
  u.searchParams.forEach((_v,k)=>{if(!names.includes(k))names.push(k)});
  const hostHeader=req.headers.get('host')||null,forwardedHost=req.headers.get('x-forwarded-host')||null;
  const referer=req.headers.get('referer'),origin=req.headers.get('origin');
  const safeHost=(value:string|null)=>{if(!value)return null;try{return new URL(value.includes('://')?value:'https://'+value).host}catch{return value.split(',')[0].trim().slice(0,160)||null}};
  return {method:req.method,path:u.pathname,query_parameter_names:names,content_type:req.headers.get('content-type')||null,accept:req.headers.get('accept')||null,vercel_request_id:req.headers.get('x-vercel-id')||null,request_headers:{host:hostHeader,forwarded_host:forwardedHost,forwarded_proto:req.headers.get('x-forwarded-proto')||null,referer_host:safeHost(referer),origin_host:safeHost(origin),sec_fetch_site:req.headers.get('sec-fetch-site')||null,user_agent:safeDiagnosticText(req.headers.get('user-agent')||'unknown')}};
}
function diagnosticSanitize(value:any,key=''):any{
  if(/(^|_)(secret|pat|access_token|refresh_token|authorization_code|github_code|code_verifier|code_challenge|state|password|cookie|authorization|token)$/i.test(key))return '[redacted]';
  if(Array.isArray(value))return value.map(v=>diagnosticSanitize(v));
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,diagnosticSanitize(v,k)]));
  return typeof value==='string'?safeDiagnosticText(value):value;
}
function logEvent(name:string,data:Record<string,unknown>={}){
  console.info(JSON.stringify(diagnosticSanitize({event:name,timestamp:new Date().toISOString(),...data})));
}
function exceptionInfo(e:unknown){
  if(e instanceof Error)return {name:e.name||'Error',message:safeDiagnosticText(e.message),...(e.stack?{stack:safeDiagnosticText(e.stack)}:{})};
  return {name:'UnknownError',message:safeDiagnosticText(e)};
}
const debug=(stage:string,extra:Record<string,unknown>={},status=500,req?:Request)=>{
  const id=traceFor(req);
  const checks=Array.isArray(extra.checks)?extra.checks:[];
  const description=typeof extra.error_description==='string'?extra.error_description:stage.replace(/_/g,' ');
  const payload=diagnosticSanitize({error:'oauth_debug',stage,error_description:description,trace_id:id,...(req?{request:requestInfo(req)}:{}),...extra,diagnostics:{trace_id:id,stage,checks}});
  console.error(JSON.stringify({event:'oauth_request_failed',timestamp:new Date().toISOString(),...payload}));
  return json(payload,status);
};
const err=(e:string,d:string,status=400,req?:Request,extra:Record<string,unknown>={})=>{
  const id=traceFor(req),checks=Array.isArray(extra.checks)?extra.checks:[{name:'oauth_protocol_validation',ok:false,result:e}];
  const payload=diagnosticSanitize({error:e,error_description:d,stage:e,trace_id:id,...(req?{request:requestInfo(req)}:{}),...extra,checks,diagnostics:{trace_id:id,stage:e,checks}});
  console.error(JSON.stringify({event:'oauth_protocol_error',timestamp:new Date().toISOString(),...payload}));
  return json(payload,status);
};
const protocolFailure=(req:Request,oauthError:string,stage:string,description:string,status:number,checks:any[],extra:Record<string,unknown>={})=>err(oauthError,description,status,req,{stage,checks,...extra});
const withTraceHeader=(response:Response,id:string)=>{
  const headers=new Headers(response.headers);
  headers.set('x-oauth-trace-id',id);
  headers.set('cache-control','no-store');
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
};
const html=(t:string,m:string,status=400)=>new Response('<!doctype html><meta name="viewport" content="width=device-width"><title>'+t+'</title><main style="font:16px system-ui;max-width:650px;margin:10vh auto;padding:24px"><h1>'+t+'</h1><p>'+m+'</p></main>',{status,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
class RedisDiagnosticError extends Error {
  constructor(readonly kind:string,readonly command:string,readonly status=0,readonly detail?:string,readonly contentType?:string,readonly responseBytes?:number){super(kind)}
}
function safeRedisDetail(value:unknown){
  let text=String(value??'unknown');
  for(const secret of [process.env.UPSTASH_REDIS_REST_TOKEN,process.env.UPSTASH_REDIS_REST_URL])if(secret)text=text.split(secret).join('[redacted]');
  text=text.replace(/Bearer\s+\S+/gi,'Bearer [redacted]').replace(/https?:\/\/\S+/gi,'[URL redacted]');
  return text.slice(0,180);
}
function redisDiagnostics(error:unknown){
  const e=error instanceof RedisDiagnosticError?error:null;
  return {kind:e?.kind||'unknown_error',command:e?.command||'UNKNOWN',http_status:e?.status||0,url_configured:Boolean(process.env.UPSTASH_REDIS_REST_URL),token_configured:Boolean(process.env.UPSTASH_REDIS_REST_TOKEN),...(e?.detail?{detail:e.detail}:{}),...(e?.contentType?{content_type:e.contentType}:{}),...(typeof e?.responseBytes==='number'?{response_bytes:e.responseBytes}:{})};
}
function missing(){return ['GITHUB_OAUTH_CLIENT_ID','GITHUB_OAUTH_CLIENT_SECRET','GITHUB_ALLOWED_LOGIN','GITHUB_PAT','PROXY_SECRET'].filter(k=>!process.env[k])}
function ready(){return missing().length===0}
async function redis(cmd:any[],req?:Request){
  const started=Date.now();
  const command=Array.isArray(cmd)&&typeof cmd[0]==='string'?cmd[0].toUpperCase():'UNKNOWN';
  try{
    const u=process.env.UPSTASH_REDIS_REST_URL,t=process.env.UPSTASH_REDIS_REST_TOKEN;
    if(!u&&!t)throw new RedisDiagnosticError('missing_url_and_token',command);
    if(!u)throw new RedisDiagnosticError('missing_url',command);
    if(!t)throw new RedisDiagnosticError('missing_token',command);
    let r:Response;
    try{r=await fetch(u,{method:'POST',headers:{Authorization:'Bearer '+t,'Content-Type':'application/json'},body:JSON.stringify(cmd),cache:'no-store'});}
    catch(e:any){throw new RedisDiagnosticError('network_error',command,0,safeRedisDetail(e?.name||'fetch_failed'));}
    const contentType=r.headers.get('content-type')||'unknown';
    let raw:string;
    try{raw=await r.text();}catch(e:any){throw new RedisDiagnosticError('response_read_error',command,r.status,safeRedisDetail(e?.name||'body_read_failed'),contentType);}
    let j:any;
    try{j=JSON.parse(raw);}catch{throw new RedisDiagnosticError('non_json_response',command,r.status,undefined,contentType,raw.length);}
    if(!j||typeof j!=='object'||Array.isArray(j))throw new RedisDiagnosticError('invalid_response_shape',command,r.status,'Expected a JSON object from Upstash Redis.',contentType,raw.length);
    if(j.error)throw new RedisDiagnosticError('redis_error',command,r.status,safeRedisDetail(j.error),contentType,raw.length);
    if(!r.ok)throw new RedisDiagnosticError('http_error',command,r.status,'Upstash returned a non-success HTTP status without a Redis error field.',contentType,raw.length);
    if(!Object.prototype.hasOwnProperty.call(j,'result'))throw new RedisDiagnosticError('missing_result',command,r.status,'JSON response did not contain a result field.',contentType,raw.length);
    logEvent('oauth_redis_command_succeeded',{trace_id:traceFor(req),command,http_status:r.status,duration_ms:Date.now()-started,result_type:j.result===null?'null':Array.isArray(j.result)?'array':typeof j.result});
    return j.result;
  }catch(e){
    logEvent('oauth_redis_command_failed',{trace_id:traceFor(req),command,duration_ms:Date.now()-started,redis:redisDiagnostics(e),exception:exceptionInfo(e)});
    throw e;
  }
}
async function body(req:Request){
  const contentType=(req.headers.get('content-type')||'').split(';')[0].trim().toLowerCase();
  if(contentType==='application/json')return await req.json() as any;
  if(!contentType||contentType==='application/x-www-form-urlencoded'){
    const p=new URLSearchParams(await req.text()),o:any={};
    p.forEach((v,k)=>o[k]=v);
    return o;
  }
  throw new Error('unsupported_content_type:'+contentType);
}
function redirectOk(v:any):v is string{if(typeof v!=='string'||v.length>2048)return false;try{const u=new URL(v);return u.protocol==='https:'&&!u.username&&!u.password&&!u.hash}catch{return false}}
async function authorize(req:Request){
if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment_variables_present',ok:false,details:{missing:missing()}}]},503,req);
const u=new URL(req.url),clientId=u.searchParams.get('client_id')||'',redirect=u.searchParams.get('redirect_uri')||'',state=u.searchParams.get('state')||'',challenge=u.searchParams.get('code_challenge')||'',method=u.searchParams.get('code_challenge_method')||'',resource=u.searchParams.get('resource')||'';
const client=verifyOAuthClaims(clientId,'oauth_client');
if(!client||!Array.isArray(client.redirect_uris))return debug('oauth_client_not_found',{client_id_present:Boolean(clientId),client_id_length:clientId.length,checks:[{name:'client_id_signature_and_expiry_valid',ok:false}],possible_causes:['The client registration token is invalid or expired','The request reached a deployment using a different signing secret']},400,req);
const redirectValid=redirectOk(redirect),redirectRegistered=client.redirect_uris.includes(redirect);
if(!redirectValid||!redirectRegistered)return debug('oauth_redirect_uri_rejected',{checks:[{name:'redirect_uri_https_and_valid',ok:redirectValid},{name:'redirect_uri_matches_registration',ok:redirectRegistered}],redirect_uri_length:redirect.length,registered_redirect_uri_count:client.redirect_uris.length},400,req);
if(u.searchParams.get('response_type')!=='code'||!state)return debug('oauth_authorization_request_invalid',{checks:[{name:'response_type_is_code',ok:u.searchParams.get('response_type')==='code'},{name:'state_parameter_present',ok:Boolean(state)}]},400,req);
const pkceMethodOk=method==='S256',pkceChallengeOk=/^[A-Za-z0-9_-]{43,128}$/.test(challenge);
if(!pkceMethodOk||!pkceChallengeOk)return debug('oauth_pkce_validation_failed',{checks:[{name:'pkce_method_is_s256',ok:pkceMethodOk,result:method||'missing'},{name:'pkce_challenge_format',ok:pkceChallengeOk,details:{present:Boolean(challenge),length:challenge.length}}]},400,req);
if(resource!==RESOURCE)return debug('oauth_resource_mismatch',{checks:[{name:'resource_matches_server_configuration',ok:false}],resource_parameter_present:Boolean(resource),reconnect_required:true},400,req);
const authTraceId=traceFor(req);
let githubState:string;
try{githubState=issueOAuthClaims({typ:'github_authorization_state',client_id:clientId,redirect_uri:redirect,state,challenge,resource,scope:'github',trace_id:authTraceId},TTL.state)}
catch(e){return debug('oauth_state_signing_failed',{exception:exceptionInfo(e),checks:[{name:'oauth_state_signing_secret_available',ok:false}]},503,req)}
const stateFingerprint=createHash('sha256').update(githubState).digest('hex').slice(0,12);
logEvent('oauth_state_signed',{trace_id:traceFor(req),flow_id:authTraceId,state_fingerprint:stateFingerprint,state_ttl_seconds:TTL.state});
const gh=new URL('https://github.com/login/oauth/authorize');
gh.searchParams.set('client_id',process.env.GITHUB_OAUTH_CLIENT_ID!);gh.searchParams.set('redirect_uri',GITHUB_CALLBACK);gh.searchParams.set('scope','read:user');gh.searchParams.set('state',githubState);gh.searchParams.set('allow_signup','false');
logEvent('oauth_github_redirect_issued',{trace_id:traceFor(req),flow_id:authTraceId,state_fingerprint:stateFingerprint,callback_host:new URL(GITHUB_CALLBACK).host,callback_path:new URL(GITHUB_CALLBACK).pathname,github_authorization_host:gh.host,github_authorization_query_parameter_names:Array.from(gh.searchParams.keys()),redirect_status:302});
return Response.redirect(gh.toString(),302)}

function oauthDiagnosticResult(req:Request,record:any,stage:string,status:number,checks:any[],extra:Record<string,unknown>={}){
  const trace=traceFor(req),flowId=typeof record?.trace_id==='string'?record.trace_id:null;
  const failed=checks.filter((c:any)=>c.ok===false).map((c:any)=>c.name);
  const payload=diagnosticSanitize({
    diagnostic_mode:true,
    ok:status<400&&failed.length===0,
    stage,
    trace_id:trace,
    flow_id:flowId,
    request:requestInfo(req),
    checks,
    failed_checks:failed,
    ...extra
  });
  logEvent(status>=400?'oauth_github_diagnostic_failed':'oauth_github_diagnostic_completed',{
    trace_id:trace,flow_id:flowId,stage,http_status:status,failed_checks:failed,
    callback_query_parameter_names:Array.from(new URL(req.url).searchParams.keys())
  });
  return json(payload,status);
}
async function oauthDiagnosticStart(req:Request){
  if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment_variables_present',ok:false,details:{missing:missing()}}]},503,req);
  const flowId=traceFor(req);
  let diagnosticState:string;
  try{diagnosticState=issueOAuthClaims({typ:'github_diagnostic_state',nonce:randomBytes(24).toString('base64url'),trace_id:flowId},TTL.state)}
  catch(e){return debug('oauth_diagnostic_state_signing_failed',{exception:exceptionInfo(e),checks:[{name:'oauth_state_signing_secret_available',ok:false}]},503,req)}
  const gh=new URL('https://github.com/login/oauth/authorize');
  gh.searchParams.set('client_id',process.env.GITHUB_OAUTH_CLIENT_ID!);
  gh.searchParams.set('redirect_uri',GITHUB_CALLBACK);
  gh.searchParams.set('scope','read:user');
  gh.searchParams.set('state',diagnosticState);
  gh.searchParams.set('allow_signup','false');
  logEvent('oauth_github_diagnostic_redirect_issued',{
    trace_id:traceFor(req),flow_id:flowId,
    state_fingerprint:createHash('sha256').update(diagnosticState).digest('hex').slice(0,12),
    callback_host:new URL(GITHUB_CALLBACK).host,callback_path:new URL(GITHUB_CALLBACK).pathname,
    github_authorization_host:gh.host,
    github_authorization_query_parameter_names:Array.from(gh.searchParams.keys()),
    redirect_status:302
  });
  return Response.redirect(gh.toString(),302);
}

async function oauthDiagnosticCallback(req:Request,state:string,record:any){
  const stateFingerprint=createHash('sha256').update(state).digest('hex').slice(0,12);
  const baseChecks=[
    {name:'required_environment_variables_present',ok:ready()},
    {name:'github_state_signature_and_expiry_valid',ok:true},
    {name:'callback_host_matches_configured_host',ok:new URL(req.url).host===new URL(GITHUB_CALLBACK).host},
    {name:'callback_path_matches_configured_path',ok:new URL(req.url).pathname===new URL(GITHUB_CALLBACK).pathname}
  ];
  const ghError=reqUrlParam(req,'error');
  if(ghError){
    const description=reqUrlParam(req,'error_description')||'';
    baseChecks.push({name:'github_authorization_succeeded',ok:false} as any);
    return oauthDiagnosticResult(req,record,'oauth_diagnostic_github_authorization_denied',400,baseChecks,{
      state_fingerprint:stateFingerprint,github_error:safeDiagnosticText(ghError),
      github_error_description:safeDiagnosticText(description),
      github_error_uri_present:Boolean(reqUrlParam(req,'error_uri')),
      callback_query_parameter_names:Array.from(new URL(req.url).searchParams.keys()),
      diagnosis:'GitHub returned an OAuth error instead of an authorization code. Inspect github_error and github_error_description.'
    });
  }
  const code=reqUrlParam(req,'code');
  baseChecks.push({name:'github_authorization_code_received',ok:Boolean(code)} as any);
  if(!code)return oauthDiagnosticResult(req,record,'oauth_diagnostic_github_code_missing',400,baseChecks,{
    state_fingerprint:stateFingerprint,callback_query_parameter_names:Array.from(new URL(req.url).searchParams.keys()),
    diagnosis:'GitHub returned the state but neither a code nor an OAuth error.'
  });
  let token:any;
  let tokenStatus=0,tokenContentType='unknown',tokenBytes=0,tokenJsonOk=false;
  try{
    const r=await fetch('https://github.com/login/oauth/access_token',{
      method:'POST',
      headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded','User-Agent':'mcp-on-vercel'},
      body:new URLSearchParams({client_id:process.env.GITHUB_OAUTH_CLIENT_ID!,client_secret:process.env.GITHUB_OAUTH_CLIENT_SECRET!,code,redirect_uri:GITHUB_CALLBACK}).toString(),
      cache:'no-store'
    });
    tokenStatus=r.status;tokenContentType=r.headers.get('content-type')||'unknown';
    const raw=await r.text();tokenBytes=raw.length;
    try{token=JSON.parse(raw);tokenJsonOk=true}catch{token=null}
    const tokenHttpOk=r.ok,tokenReceived=Boolean(token?.access_token);
    const checks=[...baseChecks,
      {name:'github_token_endpoint_http_success',ok:tokenHttpOk,http_status:tokenStatus},
      {name:'github_token_response_json_valid',ok:tokenJsonOk},
      {name:'github_access_token_received',ok:tokenReceived}
    ];
    if(!tokenHttpOk||!tokenReceived)return oauthDiagnosticResult(req,record,'oauth_diagnostic_github_token_exchange_failed',502,checks,{
      state_fingerprint:stateFingerprint,github_status:tokenStatus,github_content_type:tokenContentType,github_response_bytes:tokenBytes,
      github_error:typeof token?.error==='string'?safeDiagnosticText(token.error):'unknown',
      github_error_description:typeof token?.error_description==='string'?safeDiagnosticText(token.error_description):undefined,
      diagnosis:'GitHub callback succeeded, but the authorization code could not be exchanged for an access token. Check the OAuth app client ID/secret and callback URL configuration.'
    });
    logEvent('oauth_github_diagnostic_token_exchange_succeeded',{trace_id:traceFor(req),flow_id:record.trace_id,github_status:tokenStatus,github_content_type:tokenContentType,response_bytes:tokenBytes});
  }catch(e){
    return oauthDiagnosticResult(req,record,'oauth_diagnostic_github_token_exchange_network_error',502,[...baseChecks,{name:'github_token_exchange_request_completed',ok:false}],{
      state_fingerprint:stateFingerprint,exception:exceptionInfo(e),
      diagnosis:'The server could not complete the request to GitHub token exchange endpoint.'
    });
  }
  let user:any,userStatus=0,userContentType='unknown',userBytes=0,userJsonOk=false;
  try{
    const r=await fetch('https://api.github.com/user',{
      headers:{Authorization:'Bearer '+token.access_token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'mcp-on-vercel'},
      cache:'no-store'
    });
    userStatus=r.status;userContentType=r.headers.get('content-type')||'unknown';
    const raw=await r.text();userBytes=raw.length;
    try{user=JSON.parse(raw);userJsonOk=true}catch{user=null}
    const userHttpOk=r.ok,userLoginOk=typeof user?.login==='string'&&user.login.length>0;
    const checks=[...baseChecks,
      {name:'github_token_endpoint_http_success',ok:true,http_status:tokenStatus},
      {name:'github_access_token_received',ok:true},
      {name:'github_user_endpoint_http_success',ok:userHttpOk,http_status:userStatus},
      {name:'github_user_response_json_valid',ok:userJsonOk},
      {name:'github_login_received',ok:userLoginOk}
    ];
    if(!userHttpOk||!userLoginOk)return oauthDiagnosticResult(req,record,'oauth_diagnostic_github_user_lookup_failed',502,checks,{
      state_fingerprint:stateFingerprint,github_status:userStatus,github_content_type:userContentType,github_response_bytes:userBytes,
      github_message:typeof user?.message==='string'?safeDiagnosticText(user.message):undefined,
      diagnosis:'GitHub accepted the OAuth code but the server could not retrieve the authenticated GitHub profile.'
    });
  }catch(e){
    return oauthDiagnosticResult(req,record,'oauth_diagnostic_github_user_lookup_network_error',502,[...baseChecks,{name:'github_user_lookup_request_completed',ok:false}],{
      state_fingerprint:stateFingerprint,exception:exceptionInfo(e),
      diagnosis:'The server could not complete the GitHub user profile request.'
    });
  }
  const allowlisted=(process.env.GITHUB_ALLOWED_LOGIN||'').trim().toLowerCase();
  const loginMatches=String(user.login).toLowerCase()===allowlisted;
  const finalChecks=[...baseChecks,
    {name:'github_token_exchange_succeeded',ok:true,http_status:tokenStatus},
    {name:'github_user_profile_loaded',ok:true,http_status:userStatus},
    {name:'github_login_matches_GITHUB_ALLOWED_LOGIN',ok:loginMatches},
  ];
  logEvent('oauth_github_diagnostic_identity_checked',{trace_id:traceFor(req),flow_id:record.trace_id,github_login_matches_allowlist:loginMatches});
  if(!loginMatches)return oauthDiagnosticResult(req,record,'oauth_diagnostic_github_account_not_allowed',403,finalChecks,{
    state_fingerprint:stateFingerprint,authenticated_github_login:safeDiagnosticText(user.login),
    allowlist_configured:Boolean(allowlisted),
    diagnosis:'GitHub authentication worked, but the account returned by GitHub does not match GITHUB_ALLOWED_LOGIN.'
  });
  return oauthDiagnosticResult(req,record,'oauth_diagnostic_complete',200,finalChecks,{
    state_fingerprint:stateFingerprint,authenticated_github_login:safeDiagnosticText(user.login),
    github_token_exchange:{http_status:tokenStatus,content_type:tokenContentType,response_bytes:tokenBytes,json_valid:tokenJsonOk,access_token_received:true},
    github_user_lookup:{http_status:userStatus,content_type:userContentType,response_bytes:userBytes,json_valid:userJsonOk,login_received:true},
    diagnosis:'The GitHub OAuth redirect, callback state, authorization-code exchange, GitHub profile lookup, and allowed-account check all passed. If MCP connection still fails, the remaining problem is in client registration, redirect URI, PKCE, resource binding, token issuance, or MCP bearer authentication.'
  });
}

function reqUrlParam(req:Request,key:string){return new URL(req.url).searchParams.get(key)||''}

async function githubCallback(req:Request){
if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment_variables_present',ok:false,details:{missing:missing()}}]},503,req);
const u=new URL(req.url),state=u.searchParams.get('state')||'';
if(!state)return debug('oauth_state_parameter_missing',{checks:[{name:'github_state_parameter',ok:false,result:'missing'}],redis_lookup_attempted:false,callback_expected_host:new URL(GITHUB_CALLBACK).host,callback_expected_path:new URL(GITHUB_CALLBACK).pathname,callback_received_host:u.host,callback_received_path:u.pathname,callback_query_parameter_names:Array.from(u.searchParams.keys()),diagnosis:['The callback request reached the configured route without a state query parameter.'],possible_causes:['The callback URL was opened directly','The browser/client navigated to the callback without GitHub returning code and state','An upstream redirect or client removed the callback query string']},400,req);
const record=verifyOAuthClaims(state);
if(!record)return debug('oauth_state_signature_invalid_or_expired',{state_fingerprint:createHash('sha256').update(state).digest('hex').slice(0,12),checks:[{name:'github_state_signature_valid',ok:false},{name:'github_state_expiry_valid',ok:false}],diagnosis:['The callback state could not be authenticated or has expired.']},400,req);
if(record.typ==='github_diagnostic_state')return await oauthDiagnosticCallback(req,state,record);
if(record.typ!=='github_authorization_state')return debug('oauth_state_type_invalid',{state_fingerprint:createHash('sha256').update(state).digest('hex').slice(0,12),checks:[{name:'github_state_signature_valid',ok:true},{name:'github_state_type_is_authorization',ok:false}],received_state_type:record.typ},400,req);
const stateFingerprint=createHash('sha256').update(state).digest('hex').slice(0,12);
const recordValid=typeof record.client_id==='string'&&typeof record.redirect_uri==='string'&&typeof record.state==='string'&&typeof record.challenge==='string'&&typeof record.resource==='string'&&typeof record.trace_id==='string';
if(!recordValid)return debug('oauth_state_record_invalid',{state_fingerprint:stateFingerprint,checks:[{name:'state_record_schema_valid',ok:false}]},500,req);
logEvent('oauth_state_signature_validated',{trace_id:traceFor(req),flow_id:record.trace_id,state_fingerprint:stateFingerprint});
if(u.searchParams.get('error')){const ghError=u.searchParams.get('error')||'unknown',ghDescription=u.searchParams.get('error_description')||'';logEvent('oauth_github_authorization_denied',{trace_id:traceFor(req),flow_id:record.trace_id,state_fingerprint:stateFingerprint,github_error:safeDiagnosticText(ghError),github_error_description:safeDiagnosticText(ghDescription),github_error_uri_present:Boolean(u.searchParams.get('error_uri')),callback_query_parameter_names:Array.from(u.searchParams.keys())});const d=new URL(record.redirect_uri);d.searchParams.set('error','access_denied');d.searchParams.set('state',record.state);return Response.redirect(d.toString(),302)}
const code=u.searchParams.get('code');
if(!code)return debug('github_code_missing',{flow_id:record.trace_id,state_fingerprint:stateFingerprint,github_error_parameter_present:Boolean(u.searchParams.get('error')),callback_query_parameter_names:Array.from(u.searchParams.keys()),checks:[{name:'github_state_signature_valid',ok:true},{name:'github_code_parameter',ok:false}],diagnosis:['GitHub returned a valid state, but supplied neither an authorization code nor an OAuth error.']},400,req);
let token:any;
try{
const r=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded','User-Agent':'mcp-on-vercel'},body:new URLSearchParams({client_id:process.env.GITHUB_OAUTH_CLIENT_ID!,client_secret:process.env.GITHUB_OAUTH_CLIENT_SECRET!,code,redirect_uri:GITHUB_CALLBACK}).toString(),cache:'no-store'});
const raw=await r.text();let parsed:any=null;let parseOk=false;try{parsed=JSON.parse(raw);parseOk=true}catch{}token=parsed||{};
if(!r.ok||!token.access_token)return debug('github_token_exchange_rejected',{flow_id:record.trace_id,state_fingerprint:stateFingerprint,checks:[{name:'github_token_endpoint_http_status',ok:r.ok,result:String(r.status)},{name:'github_response_json_parse',ok:parseOk},{name:'github_access_token_returned',ok:Boolean(token.access_token)}],github_status:r.status,content_type:r.headers.get('content-type')||'unknown',response_bytes:raw.length,github_error:typeof token.error==='string'?safeDiagnosticText(token.error):'unknown',github_error_description:typeof token.error_description==='string'?safeDiagnosticText(token.error_description):undefined},502,req)
logEvent('oauth_github_token_exchange_succeeded',{trace_id:traceFor(req),flow_id:record.trace_id,state_fingerprint:stateFingerprint,github_status:r.status,content_type:r.headers.get('content-type')||'unknown',response_bytes:raw.length,access_token_received:true});
}catch(e){return debug('github_token_exchange_network_error',{flow_id:record.trace_id,state_fingerprint:stateFingerprint,exception:exceptionInfo(e),checks:[{name:'github_token_exchange_request',ok:false}]},502,req)}
let user:any;
try{
const r=await fetch('https://api.github.com/user',{headers:{Authorization:'Bearer '+token.access_token,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'mcp-on-vercel'},cache:'no-store'});
const raw=await r.text();let parsed:any=null;let parseOk=false;try{parsed=JSON.parse(raw);parseOk=true}catch{}user=parsed;
if(!r.ok||!user?.login)return debug('github_user_lookup_failed',{flow_id:record.trace_id,state_fingerprint:stateFingerprint,checks:[{name:'github_user_endpoint_http_status',ok:r.ok,result:String(r.status)},{name:'github_user_response_json_parse',ok:parseOk},{name:'github_login_returned',ok:Boolean(user?.login)}],github_status:r.status,content_type:r.headers.get('content-type')||'unknown',response_bytes:raw.length,github_message:typeof user?.message==='string'?safeDiagnosticText(user.message):undefined},502,req)
logEvent('oauth_github_user_lookup_succeeded',{trace_id:traceFor(req),flow_id:record.trace_id,state_fingerprint:stateFingerprint,github_status:r.status,content_type:r.headers.get('content-type')||'unknown',response_bytes:raw.length,login_returned:true});
}catch(e){return debug('github_user_lookup_network_error',{flow_id:record.trace_id,state_fingerprint:stateFingerprint,exception:exceptionInfo(e),checks:[{name:'github_user_lookup_request',ok:false}]},502,req)}
const allowed=(process.env.GITHUB_ALLOWED_LOGIN||'').trim().toLowerCase();
if(user.login.toLowerCase()!==allowed)return debug('github_account_not_allowed',{flow_id:record.trace_id,state_fingerprint:stateFingerprint,checks:[{name:'github_login_allowlist_match',ok:false}]},403,req);
const mcpCode=issueOAuthClaims({typ:'authorization_code',client_id:record.client_id,redirect_uri:record.redirect_uri,state:record.state,challenge:record.challenge,resource:record.resource,scope:record.scope||'github',login:user.login,trace_id:record.trace_id},TTL.code);
const d=new URL(record.redirect_uri);d.searchParams.set('code',mcpCode);d.searchParams.set('state',record.state);
logEvent('oauth_authorization_code_issued',{trace_id:traceFor(req),flow_id:record.trace_id,state_fingerprint:stateFingerprint,authorization_code_ttl_seconds:TTL.code,github_login_allowlist_match:true});
return Response.redirect(d.toString(),302)}

async function register(req:Request){
  if(!ready())return json({error:'server_not_configured',missing_environment:missing()},503);
  let b:any;
  try{b=await body(req)}catch(e){return err('invalid_client_metadata','The registration body could not be parsed.')}
  const uris=b?.redirect_uris;
  if(!Array.isArray(uris)||!uris.length||!uris.every(redirectOk))return err('invalid_client_metadata','redirect_uris must contain HTTPS callback URLs.');
  if(uris.length>10||uris.reduce((sum:number,v:string)=>sum+v.length,0)>8192)return err('invalid_client_metadata','At most 10 redirect URIs with a combined length of 8192 characters are supported.');
  const clientId=issueOAuthClaims({typ:'oauth_client',sub:randomBytes(24).toString('base64url'),redirect_uris:uris,client_name:String(b.client_name||'MCP Client').slice(0,120)},TTL.client);
  logEvent('oauth_client_registered',{trace_id:traceFor(req),client_id_fingerprint:createHash('sha256').update(clientId).digest('hex').slice(0,12),redirect_uri_count:uris.length,client_ttl_seconds:TTL.client,storage:'signed_stateless'});
  return json({client_id:clientId,redirect_uris:uris,grant_types:['authorization_code','refresh_token'],response_types:['code'],token_endpoint_auth_method:'none'},201)
}

async function token(req:Request){
  if(!ready())return err('server_error','OAuth is not configured.',503,req);
  let b:any;
  try{b=await body(req)}catch(e){return debug('oauth_token_body_parse_failed',{exception:exceptionInfo(e),content_type:req.headers.get('content-type')||null,checks:[{name:'request_body_parse',ok:false}]},400,req)}
  if(!b||typeof b!=='object'||Array.isArray(b))return debug('oauth_token_body_invalid',{body_type:b===null?'null':Array.isArray(b)?'array':typeof b,checks:[{name:'request_body_is_object',ok:false}]},400,req);
  const id=typeof b.client_id==='string'?b.client_id:'';
  const grant=typeof b.grant_type==='string'?b.grant_type:'';
  const resource=typeof b.resource==='string'?b.resource:'';
  const client=verifyOAuthClaims(id,'oauth_client');
  if(!id||!client||!Array.isArray(client.redirect_uris))return protocolFailure(req,'invalid_client','oauth_client_signature_invalid_or_expired','The client_id is invalid or expired.',401,[{name:'client_id_signature_and_expiry_valid',ok:false}],{grant_type:grant||'missing'});
  if(resource!==RESOURCE)return protocolFailure(req,'invalid_request','oauth_token_resource_mismatch','The resource must match this MCP server.',400,[{name:'resource_matches_server_configuration',ok:false}],{grant_type:grant||'missing',resource_parameter_present:Boolean(resource)});
  if(grant==='authorization_code'){
    const code=typeof b.code==='string'?b.code:'';
    const redirect=typeof b.redirect_uri==='string'?b.redirect_uri:'';
    const verifier=typeof b.code_verifier==='string'?b.code_verifier:'';
    if(!code)return protocolFailure(req,'invalid_request','oauth_authorization_code_missing','The code field is required for the authorization_code grant.',400,[{name:'authorization_code_present',ok:false}],{grant_type:grant});
    if(!redirect)return protocolFailure(req,'invalid_request','oauth_token_redirect_uri_missing','redirect_uri is required for the authorization_code grant.',400,[{name:'redirect_uri_present',ok:false}],{grant_type:grant});
    const redirectRegistered=client.redirect_uris.includes(redirect);
    if(!redirectRegistered)return protocolFailure(req,'invalid_grant','oauth_token_redirect_uri_mismatch','redirect_uri does not match the URI registered for this client.',400,[{name:'redirect_uri_matches_registered_client',ok:false}],{grant_type:grant,redirect_uri_length:redirect.length,registered_redirect_uri_count:client.redirect_uris.length});
    const verifierFormatOk=/^[A-Za-z0-9._~-]{43,128}$/.test(verifier);
    if(!verifierFormatOk)return protocolFailure(req,'invalid_grant','oauth_pkce_verifier_invalid','A valid PKCE code_verifier of 43 to 128 allowed characters is required.',400,[{name:'code_verifier_format',ok:false}],{grant_type:grant,code_verifier_present:Boolean(verifier),code_verifier_length:verifier.length});
    const c=verifyOAuthClaims(code,'authorization_code');
    if(!c)return protocolFailure(req,'invalid_grant','oauth_authorization_code_signature_invalid_or_expired','The authorization code is invalid or expired.',400,[{name:'authorization_code_signature_and_expiry_valid',ok:false}],{grant_type:grant,authorization_code_ttl_seconds:TTL.code});
    const codeClientOk=c.client_id===id,codeRedirectOk=c.redirect_uri===redirect,codeResourceOk=c.resource===RESOURCE;
    if(!codeClientOk||!codeRedirectOk||!codeResourceOk)return protocolFailure(req,'invalid_grant','oauth_authorization_code_binding_mismatch','The authorization code does not match this client, redirect URI, or resource.',400,[{name:'authorization_code_client_matches',ok:codeClientOk},{name:'authorization_code_redirect_uri_matches',ok:codeRedirectOk},{name:'authorization_code_resource_matches',ok:codeResourceOk}],{grant_type:grant,flow_id:c.trace_id||null});
    const pkceMatch=typeof c.challenge==='string'&&createHash('sha256').update(verifier).digest('base64url')===c.challenge;
    if(!pkceMatch)return protocolFailure(req,'invalid_grant','oauth_pkce_verification_failed','The PKCE verifier does not match the S256 challenge sent during authorization.',400,[{name:'pkce_verifier_hash_matches_challenge',ok:false}],{grant_type:grant,flow_id:c.trace_id||null});
    const allowed=(process.env.GITHUB_ALLOWED_LOGIN||'').trim().toLowerCase();
    const loginOk=typeof c.login==='string'&&c.login.toLowerCase()===allowed;
    if(!loginOk)return protocolFailure(req,'invalid_grant','oauth_authorization_code_login_not_allowed','The authorization code login does not match the configured allowlist.',400,[{name:'github_login_matches_allowlist',ok:false}],{grant_type:grant,flow_id:c.trace_id||null});
    const common={client_id:id,login:c.login,scope:'github',resource:RESOURCE,trace_id:typeof c.trace_id==='string'?c.trace_id:null};
    const access=issueOAuthClaims({typ:'access_token',...common},TTL.access);
    const refresh=issueOAuthClaims({typ:'refresh_token',...common},TTL.refresh);
    logEvent('oauth_token_pair_issued',{trace_id:traceFor(req),flow_id:c.trace_id||null,grant_type:grant,scope:'github',access_token_ttl_seconds:TTL.access,refresh_token_ttl_seconds:TTL.refresh,login_allowlist_match:true,storage:'signed_stateless'});
    return json({access_token:access,token_type:'Bearer',expires_in:TTL.access,refresh_token:refresh,scope:'github',resource:RESOURCE})
  }
  if(grant==='refresh_token'){
    const oldToken=typeof b.refresh_token==='string'?b.refresh_token:'';
    if(!oldToken)return protocolFailure(req,'invalid_request','oauth_refresh_token_missing','The refresh_token field is required for the refresh_token grant.',400,[{name:'refresh_token_present',ok:false}],{grant_type:grant});
    const old=verifyOAuthClaims(oldToken,'refresh_token');
    if(!old)return protocolFailure(req,'invalid_grant','oauth_refresh_token_signature_invalid_or_expired','The refresh token is invalid or expired.',400,[{name:'refresh_token_signature_and_expiry_valid',ok:false}],{grant_type:grant,refresh_token_ttl_seconds:TTL.refresh});
    const clientOk=old.client_id===id,resourceMatch=old.resource===RESOURCE;
    if(!clientOk||!resourceMatch)return protocolFailure(req,'invalid_grant','oauth_refresh_token_binding_mismatch','The refresh token is not valid for this client or configured resource.',400,[{name:'refresh_token_client_matches',ok:clientOk},{name:'refresh_token_resource_matches',ok:resourceMatch}],{grant_type:grant,flow_id:old.trace_id||null});
    const allowed=(process.env.GITHUB_ALLOWED_LOGIN||'').trim().toLowerCase();
    const loginOk=typeof old.login==='string'&&old.login.toLowerCase()===allowed;
    if(!loginOk)return protocolFailure(req,'invalid_grant','oauth_refresh_token_login_not_allowed','The refresh token identity does not match the configured allowlist.',400,[{name:'github_login_matches_allowlist',ok:false}],{grant_type:grant,flow_id:old.trace_id||null});
    const common={client_id:id,login:old.login,scope:'github',resource:RESOURCE,trace_id:typeof old.trace_id==='string'?old.trace_id:null};
    const access=issueOAuthClaims({typ:'access_token',...common},TTL.access);
    const refresh=issueOAuthClaims({typ:'refresh_token',...common},TTL.refresh);
    logEvent('oauth_token_pair_refreshed',{trace_id:traceFor(req),flow_id:old.trace_id||null,grant_type:grant,scope:'github',access_token_ttl_seconds:TTL.access,refresh_token_ttl_seconds:TTL.refresh,storage:'signed_stateless'});
    return json({access_token:access,token_type:'Bearer',expires_in:TTL.access,refresh_token:refresh,scope:old.scope||'github',resource:RESOURCE})
  }
  return protocolFailure(req,'unsupported_grant_type','oauth_grant_type_unsupported','Use authorization_code or refresh_token.',400,[{name:'grant_type_supported',ok:false,result:grant||'missing'}],{grant_type:grant||'missing',supported_grant_types:['authorization_code','refresh_token']});
}

async function handler(req:Request){
  const id=traceId();
  traceByRequest.set(req,id);
  const started=Date.now();
  const request=requestInfo(req);
  logEvent('oauth_request_started',{trace_id:id,request});
  let response:Response;
  try{
    if(req.method==='OPTIONS')response=new Response(null,{status:204});
    else{
      const u=new URL(req.url),route=u.searchParams.get('route');
      const aliases:Record<string,string>={'status':'/oauth/status','protected-resource':'/.well-known/oauth-protected-resource/mcp','authorization-server':'/.well-known/oauth-authorization-server','register':'/register','authorize':'/authorize','token':'/token','github-callback':'/oauth/github/callback','diagnose':'/oauth/diagnose'};
      const p=route?(aliases[route]||'/'+route):u.pathname;
      logEvent('oauth_route_resolved',{trace_id:id,request_path:u.pathname,route_alias_present:Boolean(route),resolved_route:p,method:req.method});
      if((p==='/status'||p==='/oauth/status')&&req.method==='GET'){
        const host=new URL(req.url).host;
        let baseHost:string|null=null,resourceHost:string|null=null,baseUrlValid=false,resourceUrlValid=false;
        try{const b=new URL(BASE_URL);baseHost=b.host;baseUrlValid=b.protocol==='https:'}catch{}
        try{const r=new URL(RESOURCE);resourceHost=r.host;resourceUrlValid=r.protocol==='https:'}catch{}
        const checks:any[]=[
          {name:'required_environment_variables_present',ok:ready(),missing_environment:missing()},
          {name:'public_base_url_is_https',ok:baseUrlValid},
          {name:'resource_url_is_https',ok:resourceUrlValid},
          {name:'request_host_matches_public_base_url',ok:host===baseHost,request_host:host,configured_host:baseHost},
          {name:'github_callback_uses_configured_public_host',ok:baseHost===new URL(GITHUB_CALLBACK).host,callback_host:new URL(GITHUB_CALLBACK).host},
          {name:'resource_host_matches_public_host',ok:resourceHost===baseHost,resource_host:resourceHost,configured_host:baseHost}
        ];
        const status:any={diagnostic_schema_version:2,checked_at:new Date().toISOString(),healthy:false,oauth_configured:ready(),missing_environment:missing(),issuer:BASE_URL,resource:RESOURCE,github_callback:{host:new URL(GITHUB_CALLBACK).host,path:new URL(GITHUB_CALLBACK).pathname},request_host:host,redis:{checked:false,url_configured:Boolean(process.env.UPSTASH_REDIS_REST_URL),token_configured:Boolean(process.env.UPSTASH_REDIS_REST_TOKEN)},checks};
        if(process.env.UPSTASH_REDIS_REST_URL&&process.env.UPSTASH_REDIS_REST_TOKEN){
          status.redis.checked=true;
          try{const reply=await redis(['PING'],req);status.redis.ok=reply==='PONG';status.redis.reply_type=typeof reply;status.redis.reply=reply==='PONG'?'PONG':'unexpected_reply';checks.push({name:'upstash_redis_ping',ok:reply==='PONG',reply_type:typeof reply});}
          catch(e){status.redis.ok=false;status.redis.diagnostics=redisDiagnostics(e);checks.push({name:'upstash_redis_ping',ok:false,diagnostics:redisDiagnostics(e)});}
        }else checks.push({name:'upstash_redis_ping',ok:true,required:false,result:'not required for stateless OAuth'});
        for(const check of checks)if(check.name==='upstash_redis_ping')check.required=false;
        status.failed_checks=checks.filter((c:any)=>c.required!==false&&!c.ok).map((c:any)=>c.name);
        status.healthy=status.failed_checks.length===0;
        logEvent('oauth_health_check_completed',{trace_id:id,healthy:status.healthy,failed_checks:status.failed_checks,redis_ok:status.redis.ok===true});
        response=json(status);
      }
      else if((p==='/.well-known/oauth-protected-resource'||p==='/.well-known/oauth-protected-resource/mcp')&&req.method==='GET')response=json({resource:RESOURCE,authorization_servers:[BASE_URL],scopes_supported:['github']});
      else if(p==='/.well-known/oauth-authorization-server'&&req.method==='GET')response=json({issuer:BASE_URL,authorization_endpoint:BASE_URL+'/authorize',token_endpoint:BASE_URL+'/token',registration_endpoint:BASE_URL+'/register',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:['github']});
      else if(p==='/register'){if(req.method==='POST')response=await register(req);else response=debug('registration_method_not_allowed',{allowed_method:'POST',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
      else if(p==='/authorize'){if(req.method==='GET')response=await authorize(req);else response=debug('authorization_method_not_allowed',{allowed_method:'GET',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
      else if(p==='/token'){if(req.method==='POST')response=await token(req);else response=debug('token_method_not_allowed',{allowed_method:'POST',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
      else if(p==='/oauth/diagnose'){if(req.method==='GET')response=await oauthDiagnosticStart(req);else response=debug('oauth_diagnostic_method_not_allowed',{allowed_method:'GET',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
      else if(p==='/oauth/github/callback'){if(req.method==='GET')response=await githubCallback(req);else response=debug('github_callback_method_not_allowed',{allowed_method:'GET',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
      else response=debug('route_not_found',{checks:[{name:'route_matched',ok:false}],requested_path:u.pathname,route_alias_present:Boolean(route),resolved_route:p},404,req);
    }
  }catch(e){
    response=debug('unhandled_exception',{exception:exceptionInfo(e),...(e instanceof RedisDiagnosticError?{redis:redisDiagnostics(e)}:{}),checks:[{name:'request_handler_completed_without_exception',ok:false}]},500,req);
  }
  logEvent(response.status>=400?'oauth_request_completed_with_error':'oauth_request_completed',{trace_id:id,request_path:new URL(req.url).pathname,method:req.method,status:response.status,duration_ms:Date.now()-started,vercel_request_id:req.headers.get('x-vercel-id')||null});
  return withTraceHeader(response,id);
}
export { handler as GET, handler as POST, handler as DELETE };
