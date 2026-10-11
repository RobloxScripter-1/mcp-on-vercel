import { createHash, randomBytes } from 'node:crypto';

const BASE_URL = (process.env.MCP_PUBLIC_BASE_URL || 'https://mcp-on-vercel-msaiful0404-5024s-projects.vercel.app').replace(/\/+$/, '');
const RESOURCE = process.env.MCP_RESOURCE_URL || `${BASE_URL}/mcp`;
const GITHUB_CALLBACK = `${BASE_URL}/oauth/github/callback`;
const TTL = { client: 31536000, state: 600, code: 120, access: 3600, refresh: 2592000 };
type OAuthState = { client_id:string; redirect_uri:string; state:string; challenge:string; resource:string; scope:string };
const json=(x:unknown,status=200)=>new Response(JSON.stringify(x),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
const traceId=()=>randomBytes(8).toString('hex');
function safeDiagnosticText(value:unknown){
  let out=String(value??'unknown');
  for(const secret of [process.env.GITHUB_OAUTH_CLIENT_SECRET,process.env.GITHUB_PAT,process.env.PROXY_SECRET,process.env.UPSTASH_REDIS_REST_TOKEN,process.env.UPSTASH_REDIS_REST_URL].filter((v):v is string=>Boolean(v)))out=out.split(secret).join('[redacted]');
  return out.replace(/Bearer\\s+\\S+/gi,'Bearer [redacted]').replace(/https?:\\/\\/\\S+/gi,'[URL redacted]').slice(0,220);
}
function requestInfo(req:Request){
  const u=new URL(req.url),names:string[]=[];
  u.searchParams.forEach((_v,k)=>{if(!names.includes(k))names.push(k)});
  return {method:req.method,path:u.pathname,query_parameter_names:names,content_type:req.headers.get('content-type')||null,vercel_request_id:req.headers.get('x-vercel-id')||null};
}
function diagnosticSanitize(value:any,key=''):any{
  if(/(^|_)(secret|pat|access_token|refresh_token|authorization_code|github_code|code_verifier|code_challenge|state|password|cookie|authorization|token)$/i.test(key))return '[redacted]';
  if(Array.isArray(value))return value.map(v=>diagnosticSanitize(v));
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,diagnosticSanitize(v,k)]));
  return typeof value==='string'?safeDiagnosticText(value):value;
}
const err=(e:string,d:string,status=400)=>{const payload=diagnosticSanitize({error:e,error_description:d,diagnostics:{trace_id:traceId(),stage:e,checks:[{name:'oauth_validation',ok:false,result:e}]}});console.error(JSON.stringify({event:'oauth_protocol_error',timestamp:new Date().toISOString(),...payload}));return json(payload,status)};
const html=(t:string,m:string,status=400)=>new Response(`<!doctype html><meta name="viewport" content="width=device-width"><title>${t}</title><main style="font:16px system-ui;max-width:650px;margin:10vh auto;padding:24px"><h1>${t}</h1><p>${m}</p></main>`,{status,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
const debug=(stage:string,extra:Record<string,unknown>={},status=500,req?:Request)=>{const payload=diagnosticSanitize({error:'oauth_debug',stage,trace_id:traceId(),...(req?{request:requestInfo(req)}:{}),...extra});console.error(JSON.stringify({event:'oauth_debug',timestamp:new Date().toISOString(),...payload}));return json(payload,status)};
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
function missing(){return ['GITHUB_OAUTH_CLIENT_ID','GITHUB_OAUTH_CLIENT_SECRET','GITHUB_ALLOWED_LOGIN','GITHUB_PAT','PROXY_SECRET','UPSTASH_REDIS_REST_URL','UPSTASH_REDIS_REST_TOKEN'].filter(k=>!process.env[k])}
function ready(){return missing().length===0}
async function redis(cmd:any[]){
  const u=process.env.UPSTASH_REDIS_REST_URL,t=process.env.UPSTASH_REDIS_REST_TOKEN;
  const command=Array.isArray(cmd)&&typeof cmd[0]==='string'?cmd[0].toUpperCase():'UNKNOWN';
  if(!u&&!t)throw new RedisDiagnosticError('missing_url_and_token',command);
  if(!u)throw new RedisDiagnosticError('missing_url',command);
  if(!t)throw new RedisDiagnosticError('missing_token',command);
  let r:Response;
  try{r=await fetch(u,{method:'POST',headers:{Authorization:`Bearer ${t}`,'Content-Type':'application/json'},body:JSON.stringify(cmd),cache:'no-store'});}catch(e:any){throw new RedisDiagnosticError('network_error',command,0,safeRedisDetail(e?.name||'fetch_failed'));}
  const contentType=r.headers.get('content-type')||'unknown';
  let raw:string;
  try{raw=await r.text();}catch(e:any){throw new RedisDiagnosticError('response_read_error',command,r.status,safeRedisDetail(e?.name||'body_read_failed'),contentType);}
  let j:any;
  try{j=JSON.parse(raw);}catch{throw new RedisDiagnosticError('non_json_response',command,r.status,undefined,contentType,raw.length);}
  if(!j||typeof j!=='object'||Array.isArray(j))throw new RedisDiagnosticError('invalid_response_shape',command,r.status,'Expected a JSON object from Upstash Redis.',contentType,raw.length);
  if(j.error)throw new RedisDiagnosticError('redis_error',command,r.status,safeRedisDetail(j.error),contentType,raw.length);
  if(!r.ok)throw new RedisDiagnosticError('http_error',command,r.status,'Upstash returned a non-success HTTP status without a Redis error field.',contentType,raw.length);
  if(!Object.prototype.hasOwnProperty.call(j,'result'))throw new RedisDiagnosticError('missing_result',command,r.status,'JSON response did not contain a result field.',contentType,raw.length);
  return j.result;
}
async function put(k:string,v:any,ttl:number){await redis(['SET',k,JSON.stringify(v),'EX',ttl])}
async function get(k:string){const v=await redis(['GET',k]);if(typeof v!=='string')return null;try{return JSON.parse(v)}catch{return null}}
async function takeDetailed(k:string){
 const raw=await redis(['GET',k]);
 if(raw===null)return {value:null,observation:{key_found:false,redis_get_result_type:'null',json_parse_ok:null}};
 if(typeof raw!=='string')return {value:null,observation:{key_found:true,redis_get_result_type:typeof raw,json_parse_ok:false}};
 let value:any;try{value=JSON.parse(raw)}catch{return {value:null,observation:{key_found:true,redis_get_result_type:'string',json_parse_ok:false}}}
 const deleted=await redis(['DEL',k]);
 return {value,observation:{key_found:true,redis_get_result_type:'string',json_parse_ok:true,parsed_value_type:value===null?'null':Array.isArray(value)?'array':typeof value,redis_del_attempted:true,redis_del_result_type:deleted===null?'null':typeof deleted,...(typeof deleted==='number'?{redis_del_count:deleted}:{})}};
}
async function take(k:string){const v=await redis(['GET',k]);if(typeof v!=='string')return null;await redis(['DEL',k]);try{return JSON.parse(v)}catch{return null}}
async function body(req:Request){const ct=req.headers.get('content-type')||'';if(ct.includes('application/json'))return await req.json() as any;const p=new URLSearchParams(await req.text());const o:any={};p.forEach((v,k)=>o[k]=v);return o}
function redirectOk(v:any):v is string{if(typeof v!=='string'||v.length>2048)return false;try{const u=new URL(v);return u.protocol==='https:'&&!u.username&&!u.password&&!u.hash}catch{return false}}
async function authorize(req:Request){
if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment',ok:false,details:{missing:missing()}}]},503,req);
const u=new URL(req.url),clientId=u.searchParams.get('client_id')||'',redirect=u.searchParams.get('redirect_uri')||'',state=u.searchParams.get('state')||'',challenge=u.searchParams.get('code_challenge')||'',method=u.searchParams.get('code_challenge_method')||'',resource=u.searchParams.get('resource')||'';
let client:any;
try{client=await get(`mcp_oauth_client:${clientId}`)}catch(e){return debug('redis_client_lookup_failed',{client_id_present:Boolean(clientId),client_id_length:clientId.length,redis:redisDiagnostics(e),exception:e instanceof Error?{name:e.name,message:safeDiagnosticText(e.message)}:{message:'Unknown exception'},checks:[{name:'redis_get_client',ok:false}]},500,req)}
if(!client||!Array.isArray(client.redirect_uris))return debug('oauth_client_not_found',{client_id_present:Boolean(clientId),client_id_length:clientId.length,checks:[{name:'client_record_found',ok:false}],possible_causes:['The client was not registered','Client registration expired','The request reached a different deployment']},400,req);
const redirectValid=redirectOk(redirect),redirectRegistered=client.redirect_uris.includes(redirect);
if(!redirectValid||!redirectRegistered)return debug('oauth_redirect_uri_rejected',{checks:[{name:'redirect_uri_https_and_valid',ok:redirectValid},{name:'redirect_uri_matches_registration',ok:redirectRegistered}],redirect_uri_length:redirect.length,registered_redirect_uri_count:client.redirect_uris.length},400,req);
if(u.searchParams.get('response_type')!=='code'||!state)return debug('oauth_authorization_request_invalid',{checks:[{name:'response_type_is_code',ok:u.searchParams.get('response_type')==='code'},{name:'state_parameter_present',ok:Boolean(state)}]},400,req);
const pkceMethodOk=method==='S256',pkceChallengeOk=/^[A-Za-z0-9_-]{43,128}$/.test(challenge);
if(!pkceMethodOk||!pkceChallengeOk)return debug('oauth_pkce_validation_failed',{checks:[{name:'pkce_method_is_s256',ok:pkceMethodOk,result:method||'missing'},{name:'pkce_challenge_format',ok:pkceChallengeOk,details:{present:Boolean(challenge),length:challenge.length}}]},400,req);
if(resource!==RESOURCE)return debug('oauth_resource_mismatch',{checks:[{name:'resource_matches_server_configuration',ok:false}],resource_parameter_present:Boolean(resource),reconnect_required:true},400,req);
const githubState=randomBytes(32).toString('base64url');
const record:OAuthState={client_id:clientId,redirect_uri:redirect,state,challenge,resource,scope:'github'};
try{await put(`mcp_oauth_state:${githubState}`,record,TTL.state)}catch(e){return debug('redis_state_store_failed',{state_fingerprint:createHash('sha256').update(githubState).digest('hex').slice(0,12),state_ttl_seconds:TTL.state,redis:redisDiagnostics(e),checks:[{name:'oauth_state_created',ok:true},{name:'redis_set_state',ok:false}]},500,req)}
console.info(JSON.stringify({event:'oauth_state_stored',timestamp:new Date().toISOString(),state_fingerprint:createHash('sha256').update(githubState).digest('hex').slice(0,12),state_ttl_seconds:TTL.state}));
const gh=new URL('https://github.com/login/oauth/authorize');
gh.searchParams.set('client_id',process.env.GITHUB_OAUTH_CLIENT_ID!);gh.searchParams.set('redirect_uri',GITHUB_CALLBACK);gh.searchParams.set('scope','read:user');gh.searchParams.set('state',githubState);gh.searchParams.set('allow_signup','false');
return Response.redirect(gh.toString(),302)}
async function githubCallback(req:Request){
if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment',ok:false,details:{missing:missing()}}]},503,req);
const u=new URL(req.url),state=u.searchParams.get('state')||'';
if(!state)return debug('oauth_state_parameter_missing',{checks:[{name:'github_state_parameter',ok:false,result:'missing'}],redis_lookup_attempted:false,diagnosis:['The callback URL did not include a state query parameter, so Redis was not queried.'],possible_causes:['The callback URL was opened directly','The state query parameter was lost before reaching this endpoint']},400,req);
const stateFingerprint=createHash('sha256').update(state).digest('hex').slice(0,12);
let observed:any;
try{observed=await takeDetailed(`mcp_oauth_state:${state}`)}catch(e){const command=e instanceof RedisDiagnosticError?e.command:'UNKNOWN';return debug(command==='DEL'?'redis_state_consume_failed':'redis_state_lookup_failed',{state_parameter_present:true,state_length:state.length,state_fingerprint:stateFingerprint,redis_key_prefix:'mcp_oauth_state:',redis:redisDiagnostics(e),exception:e instanceof Error?{name:e.name,message:safeDiagnosticText(e.message)}:{message:'Unknown exception'},checks:[{name:'github_state_parameter',ok:true},{name:command==='DEL'?'redis_delete_state':'redis_get_state',ok:false}]},500,req)}
if(!observed.observation.key_found)return debug('oauth_state_missing',{state_parameter_present:true,state_length:state.length,state_fingerprint:stateFingerprint,state_ttl_seconds:TTL.state,redis_key_prefix:'mcp_oauth_state:',redis_observation:observed.observation,checks:[{name:'github_state_parameter',ok:true},{name:'redis_get_state',ok:true,result:'GET returned null'},{name:'state_key_exists',ok:false,result:'not found'}],diagnosis:['Redis GET succeeded, but the state key does not exist. This is distinct from a Redis connection, authentication, or ACL failure.'],possible_causes:['The state key was never stored','The state expired after 600 seconds','The callback state differs from the state created by authorize','Another callback already consumed the one-time state']},400,req);
if(!observed.observation.json_parse_ok)return debug('oauth_state_record_corrupt',{state_fingerprint:stateFingerprint,redis_observation:observed.observation,checks:[{name:'redis_get_state',ok:true},{name:'state_json_parse',ok:false}]},500,req);
const record=observed.value as OAuthState|null;
if(!record||typeof record!=='object'||typeof record.client_id!=='string'||typeof record.redirect_uri!=='string'||typeof record.state!=='string'||typeof record.challenge!=='string'||typeof record.resource!=='string')return debug('oauth_state_record_invalid',{state_fingerprint:stateFingerprint,redis_observation:observed.observation,checks:[{name:'state_record_schema',ok:false}]},500,req);
console.info(JSON.stringify({event:'oauth_state_consumed',timestamp:new Date().toISOString(),state_fingerprint:stateFingerprint,redis_observation:observed.observation}));
if(u.searchParams.get('error')){const d=new URL(record.redirect_uri);d.searchParams.set('error','access_denied');d.searchParams.set('state',record.state);return Response.redirect(d.toString(),302)}
const code=u.searchParams.get('code');
if(!code)return debug('github_code_missing',{state_fingerprint:stateFingerprint,checks:[{name:'github_state_validation',ok:true},{name:'github_code_parameter',ok:false}]},400,req);
let token:any;
try{
const r=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded','User-Agent':'mcp-on-vercel'},body:new URLSearchParams({client_id:process.env.GITHUB_OAUTH_CLIENT_ID!,client_secret:process.env.GITHUB_OAUTH_CLIENT_SECRET!,code,redirect_uri:GITHUB_CALLBACK}).toString(),cache:'no-store'});
const raw=await r.text();let parsed:any=null;let parseOk=false;try{parsed=JSON.parse(raw);parseOk=true}catch{}token=parsed||{};
if(!r.ok||!token.access_token)return debug('github_token_exchange_rejected',{state_fingerprint:stateFingerprint,checks:[{name:'github_token_endpoint_http_status',ok:r.ok,result:String(r.status)},{name:'github_response_json_parse',ok:parseOk},{name:'github_access_token_returned',ok:Boolean(token.access_token)}],github_status:r.status,content_type:r.headers.get('content-type')||'unknown',response_bytes:raw.length,github_error:typeof token.error==='string'?safeDiagnosticText(token.error):'unknown',github_error_description:typeof token.error_description==='string'?safeDiagnosticText(token.error_description):undefined},502,req)
}catch(e){return debug('github_token_exchange_network_error',{state_fingerprint:stateFingerprint,exception:e instanceof Error?{name:e.name,message:safeDiagnosticText(e.message)}:{message:'Unknown exception'},checks:[{name:'github_token_exchange_request',ok:false}]},502,req)}
let user:any;
try{
const r=await fetch('https://api.github.com/user',{headers:{Authorization:`Bearer ${token.access_token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'mcp-on-vercel'},cache:'no-store'});
const raw=await r.text();let parsed:any=null;let parseOk=false;try{parsed=JSON.parse(raw);parseOk=true}catch{}user=parsed;
if(!r.ok||!user?.login)return debug('github_user_lookup_failed',{state_fingerprint:stateFingerprint,checks:[{name:'github_user_endpoint_http_status',ok:r.ok,result:String(r.status)},{name:'github_user_response_json_parse',ok:parseOk},{name:'github_login_returned',ok:Boolean(user?.login)}],github_status:r.status,content_type:r.headers.get('content-type')||'unknown',response_bytes:raw.length,github_message:typeof user?.message==='string'?safeDiagnosticText(user.message):undefined},502,req)
}catch(e){return debug('github_user_lookup_network_error',{state_fingerprint:stateFingerprint,exception:e instanceof Error?{name:e.name,message:safeDiagnosticText(e.message)}:{message:'Unknown exception'},checks:[{name:'github_user_lookup_request',ok:false}]},502,req)}
const allowed=(process.env.GITHUB_ALLOWED_LOGIN||'').toLowerCase();
if(user.login.toLowerCase()!==allowed)return debug('github_account_not_allowed',{state_fingerprint:stateFingerprint,checks:[{name:'github_login_allowlist_match',ok:false}],diagnosis:['GitHub authentication succeeded, but the returned login does not match the configured account allowlist.']},403,req);
const mcpCode=randomBytes(32).toString('base64url');
try{await put(`mcp_oauth_code:${mcpCode}`,{...record,login:user.login},TTL.code)}catch(e){return debug('redis_authorization_code_store_failed',{state_fingerprint:stateFingerprint,code_ttl_seconds:TTL.code,redis:redisDiagnostics(e),checks:[{name:'github_authentication',ok:true},{name:'redis_set_authorization_code',ok:false}]},500,req)}
const d=new URL(record.redirect_uri);d.searchParams.set('code',mcpCode);d.searchParams.set('state',record.state);
console.info(JSON.stringify({event:'oauth_authorization_code_created',timestamp:new Date().toISOString(),state_fingerprint:stateFingerprint,authorization_code_ttl_seconds:TTL.code}));
return Response.redirect(d.toString(),302)}
async function register(req:Request){if(!ready())return json({error:'server_not_configured',missing_environment:missing()},503);const b=await body(req),uris=b.redirect_uris;if(!Array.isArray(uris)||!uris.length||!uris.every(redirectOk))return err('invalid_client_metadata','redirect_uris must contain HTTPS callback URLs.');const id=randomBytes(32).toString('base64url');await put(`mcp_oauth_client:${id}`,{client_id:id,redirect_uris:uris,client_name:String(b.client_name||'MCP Client').slice(0,120)},TTL.client);return json({client_id:id,redirect_uris:uris,grant_types:['authorization_code','refresh_token'],response_types:['code'],token_endpoint_auth_method:'none'},201)}
async function token(req:Request){if(!ready())return err('server_error','OAuth is not configured.',503);const b=await body(req),id=String(b.client_id||''),resource=String(b.resource||'');if(!id||resource!==RESOURCE)return err('invalid_request','client_id and resource are required.');const client=await get(`mcp_oauth_client:${id}`);if(!client)return err('invalid_client','Unknown OAuth client.');if(b.grant_type==='authorization_code'){const c=await take(`mcp_oauth_code:${String(b.code||'')}`);if(!c||c.client_id!==id||c.redirect_uri!==String(b.redirect_uri||''))return err('invalid_grant','Invalid or expired authorization code.');const verifier=String(b.code_verifier||'');if(!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier))return err('invalid_grant','A valid PKCE verifier is required.');if(createHash('sha256').update(verifier).digest('base64url')!==c.challenge)return err('invalid_grant','PKCE verification failed.');const access=randomBytes(32).toString('base64url'),refresh=randomBytes(48).toString('base64url'),rec={client_id:id,login:c.login,scope:'github',resource:RESOURCE};await put(`mcp_access_token:${access}`,rec,TTL.access);await put(`mcp_refresh_token:${refresh}`,rec,TTL.refresh);return json({access_token:access,token_type:'Bearer',expires_in:TTL.access,refresh_token:refresh,scope:'github',resource:RESOURCE})}if(b.grant_type==='refresh_token'){const old=await take(`mcp_refresh_token:${String(b.refresh_token||'')}`);if(!old||old.client_id!==id||old.resource!==RESOURCE)return err('invalid_grant','Invalid or expired refresh token.');const access=randomBytes(32).toString('base64url'),refresh=randomBytes(48).toString('base64url');await put(`mcp_access_token:${access}`,old,TTL.access);await put(`mcp_refresh_token:${refresh}`,old,TTL.refresh);return json({access_token:access,token_type:'Bearer',expires_in:TTL.access,refresh_token:refresh,scope:'github',resource:RESOURCE})}return err('unsupported_grant_type','Use authorization_code or refresh_token.')}
async function handler(req:Request){if(req.method==='OPTIONS')return new Response(null,{status:204});const u=new URL(req.url);const route=u.searchParams.get('route');const aliases:Record<string,string>={'status':'/oauth/status','protected-resource':'/.well-known/oauth-protected-resource/mcp','authorization-server':'/.well-known/oauth-authorization-server','register':'/register','authorize':'/authorize','token':'/token','github-callback':'/oauth/github/callback'};const p=route?(aliases[route]||`/${route}`):u.pathname;try{if((p==='/status'||p==='/oauth/status')&&req.method==='GET'){const status:any={oauth_configured:ready(),missing_environment:missing(),issuer:BASE_URL,resource:RESOURCE,redis:{checked:false,url_configured:Boolean(process.env.UPSTASH_REDIS_REST_URL),token_configured:Boolean(process.env.UPSTASH_REDIS_REST_TOKEN)}};if(process.env.UPSTASH_REDIS_REST_URL&&process.env.UPSTASH_REDIS_REST_TOKEN){status.redis.checked=true;try{const reply=await redis(['PING']);status.redis.ok=reply==='PONG';status.redis.reply=typeof reply==='string'?reply.slice(0,24):'unexpected_reply_type';}catch(e){status.redis.ok=false;status.redis.diagnostics=redisDiagnostics(e);}}return json(status)}if((p==='/.well-known/oauth-protected-resource'||p==='/.well-known/oauth-protected-resource/mcp')&&req.method==='GET')return json({resource:RESOURCE,authorization_servers:[BASE_URL],scopes_supported:['github']});if(p==='/.well-known/oauth-authorization-server'&&req.method==='GET')return json({issuer:BASE_URL,authorization_endpoint:`${BASE_URL}/authorize`,token_endpoint:`${BASE_URL}/token`,registration_endpoint:`${BASE_URL}/register`,response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:['github']});if(p==='/register'){if(req.method==='POST')return await register(req);return debug('registration_method_not_allowed',{allowed_method:'POST',checks:[{name:'http_method_allowed',ok:false}]},405,req)}if(p==='/authorize'){if(req.method==='GET')return await authorize(req);return debug('authorization_method_not_allowed',{allowed_method:'GET',checks:[{name:'http_method_allowed',ok:false}]},405,req)}if(p==='/token'){if(req.method==='POST')return await token(req);return debug('token_method_not_allowed',{allowed_method:'POST',checks:[{name:'http_method_allowed',ok:false}]},405,req)}if(p==='/oauth/github/callback'){if(req.method==='GET')return await githubCallback(req);return debug('github_callback_method_not_allowed',{allowed_method:'GET',checks:[{name:'http_method_allowed',ok:false}]},405,req)}return debug('route_not_found',{checks:[{name:'route_matched',ok:false}],requested_path:u.pathname,route_alias_present:Boolean(route)},404,req)}catch(e){const exception=e instanceof Error?{name:e.name,message:safeDiagnosticText(e.message)}:{name:'UnknownError',message:safeDiagnosticText(e)};return debug('unhandled_exception',{exception,...(e instanceof RedisDiagnosticError?{redis:redisDiagnostics(e)}:{}),checks:[{name:'request_handler_completed',ok:false}]},500,req)}}
export { handler as GET, handler as POST, handler as DELETE };
