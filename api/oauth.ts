import { createHash, randomBytes } from 'node:crypto';

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
class RedisDiagnosticErrorclass RedisDiagnosticError extends Error {
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
    logEvent('oauth_redis_command_succeeded',{trace_id:traceId(),command,http_status:r.status,duration_ms:Date.now()-started,result_type:j.result===null?'null':Array.isArray(j.result)?'array':typeof j.result});
    return j.result;
  }catch(e){
    logEvent('oauth_redis_command_failed',{trace_id:traceId(),command,duration_ms:Date.now()-started,redis:redisDiagnostics(e),exception:exceptionInfo(e)});
    throw e;
  }
}
async function put(k:string,v:any,ttl:number){await redis(['SET',k,JSON.stringify(v),'EX',ttl])}
async function get(k:string){
  const v=await redis(['GET',k]);
  if(v===null)return null;
  if(typeof v!=='string')throw new RedisDiagnosticError('unexpected_get_result_type','GET',200,'Expected GET to return a string or null.');
  try{return JSON.parse(v)}catch{throw new RedisDiagnosticError('invalid_json_result','GET',200,'Stored Redis value is not valid JSON.')}
}
async function takeDetailed(k:string){
 const raw=await redis(['GET',k]);
 if(raw===null)return {value:null,observation:{key_found:false,redis_get_result_type:'null',json_parse_ok:null}};
 if(typeof raw!=='string')return {value:null,observation:{key_found:true,redis_get_result_type:typeof raw,json_parse_ok:false}};
 let value:any;try{value=JSON.parse(raw)}catch{return {value:null,observation:{key_found:true,redis_get_result_type:'string',json_parse_ok:false}}}
 const deleted=await redis(['DEL',k]);
 return {value,observation:{key_found:true,redis_get_result_type:'string',json_parse_ok:true,parsed_value_type:value===null?'null':Array.isArray(value)?'array':typeof value,redis_del_attempted:true,redis_del_result_type:deleted===null?'null':typeof deleted,...(typeof deleted==='number'?{redis_del_count:deleted}:{})}};
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
const authTraceId=traceFor(req);
const stateFingerprint=createHash('sha256').update(githubState).digest('hex').slice(0,12);
const record:OAuthState={client_id:clientId,redirect_uri:redirect,state,challenge,resource,scope:'github',trace_id:authTraceId};
try{await put(`mcp_oauth_state:${githubState}`,record,TTL.state)}catch(e){return debug('redis_state_store_failed',{state_fingerprint:createHash('sha256').update(githubState).digest('hex').slice(0,12),state_ttl_seconds:TTL.state,redis:redisDiagnostics(e),checks:[{name:'oauth_state_created',ok:true},{name:'redis_set_state',ok:false}]},500,req)}
logEvent('oauth_state_stored',{trace_id:traceFor(req),flow_id:authTraceId,state_fingerprint:stateFingerprint,state_ttl_seconds:TTL.state});
const gh=new URL('https://github.com/login/oauth/authorize');
gh.searchParams.set('client_id',process.env.GITHUB_OAUTH_CLIENT_ID!);gh.searchParams.set('redirect_uri',GITHUB_CALLBACK);gh.searchParams.set('scope','read:user');gh.searchParams.set('state',githubState);gh.searchParams.set('allow_signup','false');
logEvent('oauth_github_redirect_issued',{trace_id:traceFor(req),flow_id:authTraceId,state_fingerprint:stateFingerprint,callback_host:new URL(GITHUB_CALLBACK).host,callback_path:new URL(GITHUB_CALLBACK).pathname,github_authorization_host:gh.host,github_authorization_query_parameter_names:Array.from(gh.searchParams.keys()),redirect_status:302});
return Response.redirect(gh.toString(),302)}
async function githubCallback(req:Request){
if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment',ok:false,details:{missing:missing()}}]},503,req);
const u=new URL(req.url),state=u.searchParams.get('state')||'';
if(!state)return debug('oauth_state_parameter_missing',{checks:[{name:'github_state_parameter',ok:false,result:'missing'}],redis_lookup_attempted:false,callback_expected_host:new URL(GITHUB_CALLBACK).host,callback_expected_path:new URL(GITHUB_CALLBACK).pathname,callback_received_host:u.host,callback_received_path:u.pathname,callback_query_parameter_names:Array.from(u.searchParams.keys()),diagnosis:['The callback request reached the configured route without a state query parameter, so Redis was not queried.'],possible_causes:['The callback URL was opened directly','The browser/client navigated to the callback without GitHub returning code and state','An upstream redirect or client removed the callback query string']},400,req);
const stateFingerprint=createHash('sha256').update(state).digest('hex').slice(0,12);
let observed:any;
try{observed=await takeDetailed(`mcp_oauth_state:${state}`)}catch(e){const command=e instanceof RedisDiagnosticError?e.command:'UNKNOWN';return debug(command==='DEL'?'redis_state_consume_failed':'redis_state_lookup_failed',{state_parameter_present:true,state_length:state.length,state_fingerprint:stateFingerprint,redis_key_prefix:'mcp_oauth_state:',redis:redisDiagnostics(e),exception:e instanceof Error?{name:e.name,message:safeDiagnosticText(e.message)}:{message:'Unknown exception'},checks:[{name:'github_state_parameter',ok:true},{name:command==='DEL'?'redis_delete_state':'redis_get_state',ok:false}]},500,req)}
if(!observed.observation.key_found)return debug('oauth_state_missing',{state_parameter_present:true,state_length:state.length,state_fingerprint:stateFingerprint,state_ttl_seconds:TTL.state,redis_key_prefix:'mcp_oauth_state:',redis_observation:observed.observation,checks:[{name:'github_state_parameter',ok:true},{name:'redis_get_state',ok:true,result:'GET returned null'},{name:'state_key_exists',ok:false,result:'not found'}],diagnosis:['Redis GET succeeded, but the state key does not exist. This is distinct from a Redis connection, authentication, or ACL failure.'],possible_causes:['The state key was never stored','The state expired after 600 seconds','The callback state differs from the state created by authorize','Another callback already consumed the one-time state']},400,req);
if(!observed.observation.json_parse_ok)return debug('oauth_state_record_corrupt',{state_fingerprint:stateFingerprint,redis_observation:observed.observation,checks:[{name:'redis_get_state',ok:true},{name:'state_json_parse',ok:false}]},500,req);
const record=observed.value as OAuthState|null;
if(!record||typeof record!=='object'||typeof record.client_id!=='string'||typeof record.redirect_uri!=='string'||typeof record.state!=='string'||typeof record.challenge!=='string'||typeof record.resource!=='string')return debug('oauth_state_record_invalid',{state_fingerprint:stateFingerprint,redis_observation:observed.observation,checks:[{name:'state_record_schema',ok:false}]},500,req);
logEvent('oauth_state_consumed',{trace_id:traceFor(req),flow_id:record.trace_id||null,state_fingerprint:stateFingerprint,redis_observation:observed.observation});
if(u.searchParams.get('error')){const ghError=u.searchParams.get('error')||'unknown',ghDescription=u.searchParams.get('error_description')||'';logEvent('oauth_github_authorization_denied',{trace_id:traceFor(req),flow_id:record.trace_id||null,state_fingerprint:stateFingerprint,github_error:safeDiagnosticText(ghError),github_error_description:safeDiagnosticText(ghDescription),github_error_uri_present:Boolean(u.searchParams.get('error_uri')),callback_query_parameter_names:Array.from(u.searchParams.keys())});const d=new URL(record.redirect_uri);d.searchParams.set('error','access_denied');d.searchParams.set('state',record.state);return Response.redirect(d.toString(),302)}
const code=u.searchParams.get('code');
if(!code)return debug('github_code_missing',{flow_id:record.trace_id||null,state_fingerprint:stateFingerprint,github_error_parameter_present:Boolean(u.searchParams.get('error')),callback_query_parameter_names:Array.from(u.searchParams.keys()),checks:[{name:'github_state_validation',ok:true},{name:'github_code_parameter',ok:false}],diagnosis:['GitHub returned to the callback with a valid state, but supplied neither an authorization code nor an OAuth error.']},400,req);
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
logEvent('oauth_authorization_code_created',{trace_id:traceFor(req),flow_id:record.trace_id||null,state_fingerprint:stateFingerprint,authorization_code_ttl_seconds:TTL.code,github_login_allowlist_match:true});
return Response.redirect(d.toString(),302)}
async function register(req:Request){
  if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment',ok:false,details:{missing:missing()}}],diagnosis:['One or more required server environment variables are missing.']},503,req);
  let b:any;
  try{b=await body(req)}catch(e){return debug('oauth_registration_body_parse_failed',{exception:exceptionInfo(e),content_type:req.headers.get('content-type')||null,checks:[{name:'request_body_parse',ok:false}]},400,req)}
  if(!b||typeof b!=='object'||Array.isArray(b))return debug('oauth_registration_body_invalid',{body_type:b===null?'null':Array.isArray(b)?'array':typeof b,checks:[{name:'request_body_is_object',ok:false}]},400,req);
  const uris=b.redirect_uris;
  if(!Array.isArray(uris)||uris.length===0)return debug('oauth_redirect_uris_missing',{checks:[{name:'redirect_uris_is_nonempty_array',ok:false}],redirect_uris_type:Array.isArray(uris)?'array':typeof uris,redirect_uri_count:Array.isArray(uris)?uris.length:0},400,req);
  const redirectChecks=uris.map((v:any,i:number)=>({name:'redirect_uri_'+(i+1)+'_is_https_and_valid',ok:redirectOk(v),value_type:typeof v,length:typeof v==='string'?v.length:0}));
  if(redirectChecks.some((c:any)=>!c.ok))return debug('oauth_redirect_uri_rejected',{checks:redirectChecks,redirect_uri_count:uris.length,diagnosis:['Every redirect URI must be a valid HTTPS URL without username, password, or fragment.']},400,req);
  const id=randomBytes(32).toString('base64url');
  try{await put('mcp_oauth_client:'+id,{client_id:id,redirect_uris:uris,client_name:String(b.client_name||'MCP Client').slice(0,120)},TTL.client)}
  catch(e){return debug('redis_client_store_failed',{client_id_fingerprint:createHash('sha256').update(id).digest('hex').slice(0,12),redirect_uri_count:uris.length,redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:'redirect_uris_valid',ok:true},{name:'redis_set_client',ok:false}]},500,req)}
  logEvent('oauth_client_registered',{trace_id:traceFor(req),client_id_fingerprint:createHash('sha256').update(id).digest('hex').slice(0,12),redirect_uri_count:uris.length,client_ttl_seconds:TTL.client});
  return json({client_id:id,redirect_uris:uris,grant_types:['authorization_code','refresh_token'],response_types:['code'],token_endpoint_auth_method:'none'},201)
}
async function token(req:Request){
  if(!ready())return debug('oauth_environment_incomplete',{checks:[{name:'required_environment',ok:false,details:{missing:missing()}}],diagnosis:['One or more required server environment variables are missing.']},503,req);
  let b:any;
  try{b=await body(req)}catch(e){return debug('oauth_token_body_parse_failed',{exception:exceptionInfo(e),content_type:req.headers.get('content-type')||null,checks:[{name:'request_body_parse',ok:false}]},400,req)}
  if(!b||typeof b!=='object'||Array.isArray(b))return debug('oauth_token_body_invalid',{body_type:b===null?'null':Array.isArray(b)?'array':typeof b,checks:[{name:'request_body_is_object',ok:false}]},400,req);
  const id=typeof b.client_id==='string'?b.client_id:'';
  const grant=typeof b.grant_type==='string'?b.grant_type:'';
  const resource=typeof b.resource==='string'?b.resource:'';
  const clientIdOk=id.length>0,resourceOk=resource===RESOURCE;
  if(!clientIdOk||!resourceOk)return protocolFailure(req,'invalid_request','oauth_token_required_fields_invalid','client_id and the configured resource are required.',400,[{name:'client_id_present',ok:clientIdOk},{name:'resource_matches_server_configuration',ok:resourceOk}],{client_id_present:clientIdOk,resource_parameter_present:Boolean(resource),grant_type:grant||'missing',expected_resource_configured:Boolean(RESOURCE)});
  let client:any;
  try{client=await get('mcp_oauth_client:'+id)}catch(e){return debug('redis_client_lookup_failed',{grant_type:grant||'missing',client_id_fingerprint:createHash('sha256').update(id).digest('hex').slice(0,12),redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:'redis_get_client',ok:false}]},500,req)}
  if(!client||!Array.isArray(client.redirect_uris))return protocolFailure(req,'invalid_client','oauth_client_not_found','The client_id is unknown or its registration record is invalid.',401,[{name:'client_registration_found',ok:false}],{client_id_fingerprint:createHash('sha256').update(id).digest('hex').slice(0,12),grant_type:grant||'missing',possible_causes:['The client was not registered','The client record expired or was removed','The request reached a different Redis database or deployment']});
  if(grant==='authorization_code'){
    const code=typeof b.code==='string'?b.code:'';
    const redirect=typeof b.redirect_uri==='string'?b.redirect_uri:'';
    const verifier=typeof b.code_verifier==='string'?b.code_verifier:'';
    if(!code)return protocolFailure(req,'invalid_request','oauth_authorization_code_missing','The code field is required for the authorization_code grant.',400,[{name:'authorization_code_present',ok:false},{name:'grant_type_is_authorization_code',ok:true}],{grant_type:grant,redirect_uri_present:Boolean(redirect),code_verifier_present:Boolean(verifier)});
    if(!redirect)return protocolFailure(req,'invalid_request','oauth_token_redirect_uri_missing','redirect_uri is required for the authorization_code grant.',400,[{name:'redirect_uri_present',ok:false}],{grant_type:grant});
    const redirectRegistered=client.redirect_uris.includes(redirect);
    if(!redirectRegistered)return protocolFailure(req,'invalid_grant','oauth_token_redirect_uri_mismatch','redirect_uri does not match the URI registered for this client.',400,[{name:'redirect_uri_matches_registered_client',ok:false}],{grant_type:grant,redirect_uri_length:redirect.length,registered_redirect_uri_count:client.redirect_uris.length});
    const verifierFormatOk=/^[A-Za-z0-9._~-]{43,128}$/.test(verifier);
    if(!verifierFormatOk)return protocolFailure(req,'invalid_grant','oauth_pkce_verifier_invalid','A valid PKCE code_verifier of 43 to 128 allowed characters is required.',400,[{name:'code_verifier_format',ok:false}],{grant_type:grant,code_verifier_present:Boolean(verifier),code_verifier_length:verifier.length});
    let consumed:any;
    try{consumed=await takeDetailed('mcp_oauth_code:'+code)}catch(e){const command=e instanceof RedisDiagnosticError?e.command:'UNKNOWN';return debug(command==='DEL'?'redis_authorization_code_consume_failed':'redis_authorization_code_lookup_failed',{grant_type:grant,redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:command==='DEL'?'redis_delete_authorization_code':'redis_get_authorization_code',ok:false}]},500,req)}
    if(!consumed.observation.key_found)return protocolFailure(req,'invalid_grant','oauth_authorization_code_missing_or_expired','The authorization code was not found or its two-minute lifetime expired.',400,[{name:'authorization_code_found_in_redis',ok:false}],{grant_type:grant,authorization_code_ttl_seconds:TTL.code,redis_observation:consumed.observation,possible_causes:['The code was already exchanged','The code expired','The client sent a different code','The callback redirected to a different deployment']});
    if(!consumed.observation.json_parse_ok)return debug('oauth_authorization_code_record_corrupt',{redis_observation:consumed.observation,grant_type:grant,checks:[{name:'authorization_code_record_json_parse',ok:false}]},500,req);
    const c=consumed.value;
    if(!c||typeof c!=='object')return debug('oauth_authorization_code_record_invalid',{redis_observation:consumed.observation,grant_type:grant,checks:[{name:'authorization_code_record_schema',ok:false}]},500,req);
    const codeClientOk=c.client_id===id,codeRedirectOk=c.redirect_uri===redirect,codeResourceOk=c.resource===RESOURCE;
    if(!codeClientOk||!codeRedirectOk||!codeResourceOk)return protocolFailure(req,'invalid_grant','oauth_authorization_code_binding_mismatch','The one-time authorization code does not match this client, redirect URI, or resource.',400,[{name:'authorization_code_client_matches',ok:codeClientOk},{name:'authorization_code_redirect_uri_matches',ok:codeRedirectOk},{name:'authorization_code_resource_matches',ok:codeResourceOk}],{grant_type:grant,flow_id:c.trace_id||null,redis_observation:consumed.observation});
    const pkceMatch=createHash('sha256').update(verifier).digest('base64url')===c.challenge;
    if(!pkceMatch)return protocolFailure(req,'invalid_grant','oauth_pkce_verification_failed','The PKCE verifier does not match the S256 challenge sent during authorization.',400,[{name:'pkce_verifier_hash_matches_challenge',ok:false}],{grant_type:grant,flow_id:c.trace_id||null});
    const access=randomBytes(32).toString('base64url'),refresh=randomBytes(48).toString('base64url');
    const rec={client_id:id,login:c.login,scope:'github',resource:RESOURCE,trace_id:c.trace_id||null};
    try{await put('mcp_access_token:'+access,rec,TTL.access)}catch(e){return debug('redis_access_token_store_failed',{grant_type:grant,flow_id:c.trace_id||null,redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:'pkce_verification',ok:true},{name:'redis_set_access_token',ok:false}]},500,req)}
    try{await put('mcp_refresh_token:'+refresh,rec,TTL.refresh)}catch(e){try{await redis(['DEL','mcp_access_token:'+access])}catch{}return debug('redis_refresh_token_store_failed',{grant_type:grant,flow_id:c.trace_id||null,redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:'access_token_stored',ok:true},{name:'redis_set_refresh_token',ok:false}]},500,req)}
    logEvent('oauth_token_pair_issued',{trace_id:traceFor(req),flow_id:c.trace_id||null,grant_type:grant,scope:'github',access_token_ttl_seconds:TTL.access,refresh_token_ttl_seconds:TTL.refresh,login_allowlist_match:true});
    return json({access_token:access,token_type:'Bearer',expires_in:TTL.access,refresh_token:refresh,scope:'github',resource:RESOURCE})
  }
  if(grant==='refresh_token'){
    const oldToken=typeof b.refresh_token==='string'?b.refresh_token:'';
    if(!oldToken)return protocolFailure(req,'invalid_request','oauth_refresh_token_missing','The refresh_token field is required for the refresh_token grant.',400,[{name:'refresh_token_present',ok:false}],{grant_type:grant});
    let consumed:any;
    try{consumed=await takeDetailed('mcp_refresh_token:'+oldToken)}catch(e){const command=e instanceof RedisDiagnosticError?e.command:'UNKNOWN';return debug(command==='DEL'?'redis_refresh_token_consume_failed':'redis_refresh_token_lookup_failed',{grant_type:grant,redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:command==='DEL'?'redis_delete_refresh_token':'redis_get_refresh_token',ok:false}]},500,req)}
    if(!consumed.observation.key_found)return protocolFailure(req,'invalid_grant','oauth_refresh_token_missing_or_expired','The refresh token was not found or its 30-day lifetime expired.',400,[{name:'refresh_token_found_in_redis',ok:false}],{grant_type:grant,refresh_token_ttl_seconds:TTL.refresh,redis_observation:consumed.observation});
    if(!consumed.observation.json_parse_ok)return debug('oauth_refresh_token_record_corrupt',{grant_type:grant,redis_observation:consumed.observation,checks:[{name:'refresh_token_record_json_parse',ok:false}]},500,req);
    const old=consumed.value;
    if(!old||typeof old!=='object')return debug('oauth_refresh_token_record_invalid',{grant_type:grant,checks:[{name:'refresh_token_record_schema',ok:false}]},500,req);
    const clientOk=old.client_id===id,resourceMatch=old.resource===RESOURCE;
    if(!clientOk||!resourceMatch)return protocolFailure(req,'invalid_grant','oauth_refresh_token_binding_mismatch','The refresh token is not valid for this client or configured resource.',400,[{name:'refresh_token_client_matches',ok:clientOk},{name:'refresh_token_resource_matches',ok:resourceMatch}],{grant_type:grant,flow_id:old.trace_id||null});
    const access=randomBytes(32).toString('base64url'),refresh=randomBytes(48).toString('base64url');
    const rec={...old,trace_id:old.trace_id||null};
    try{await put('mcp_access_token:'+access,rec,TTL.access)}catch(e){return debug('redis_access_token_store_failed',{grant_type:grant,flow_id:old.trace_id||null,redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:'refresh_token_validated',ok:true},{name:'redis_set_access_token',ok:false}]},500,req)}
    try{await put('mcp_refresh_token:'+refresh,rec,TTL.refresh)}catch(e){try{await redis(['DEL','mcp_access_token:'+access])}catch{}return debug('redis_refresh_token_store_failed',{grant_type:grant,flow_id:old.trace_id||null,redis:redisDiagnostics(e),exception:exceptionInfo(e),checks:[{name:'access_token_stored',ok:true},{name:'redis_set_refresh_token',ok:false}]},500,req)}
    logEvent('oauth_token_pair_refreshed',{trace_id:traceFor(req),flow_id:old.trace_id||null,grant_type:grant,scope:old.scope||'github',access_token_ttl_seconds:TTL.access,refresh_token_ttl_seconds:TTL.refresh});
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
      const aliases:Record<string,string>={'status':'/oauth/status','protected-resource':'/.well-known/oauth-protected-resource/mcp','authorization-server':'/.well-known/oauth-authorization-server','register':'/register','authorize':'/authorize','token':'/token','github-callback':'/oauth/github/callback'};
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
          try{const reply=await redis(['PING']);status.redis.ok=reply==='PONG';status.redis.reply_type=typeof reply;status.redis.reply=reply==='PONG'?'PONG':'unexpected_reply';checks.push({name:'upstash_redis_ping',ok:reply==='PONG',reply_type:typeof reply});}
          catch(e){status.redis.ok=false;status.redis.diagnostics=redisDiagnostics(e);checks.push({name:'upstash_redis_ping',ok:false,diagnostics:redisDiagnostics(e)});}
        }else checks.push({name:'upstash_redis_ping',ok:false,result:'required Redis environment variables missing'});
        status.failed_checks=checks.filter((c:any)=>!c.ok).map((c:any)=>c.name);
        status.healthy=status.failed_checks.length===0;
        logEvent('oauth_health_check_completed',{trace_id:id,healthy:status.healthy,failed_checks:status.failed_checks,redis_ok:status.redis.ok===true});
        response=json(status);
      }
      else if((p==='/.well-known/oauth-protected-resource'||p==='/.well-known/oauth-protected-resource/mcp')&&req.method==='GET')response=json({resource:RESOURCE,authorization_servers:[BASE_URL],scopes_supported:['github']});
      else if(p==='/.well-known/oauth-authorization-server'&&req.method==='GET')response=json({issuer:BASE_URL,authorization_endpoint:BASE_URL+'/authorize',token_endpoint:BASE_URL+'/token',registration_endpoint:BASE_URL+'/register',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:['github']});
      else if(p==='/register'){if(req.method==='POST')response=await register(req);else response=debug('registration_method_not_allowed',{allowed_method:'POST',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
      else if(p==='/authorize'){if(req.method==='GET')response=await authorize(req);else response=debug('authorization_method_not_allowed',{allowed_method:'GET',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
      else if(p==='/token'){if(req.method==='POST')response=await token(req);else response=debug('token_method_not_allowed',{allowed_method:'POST',checks:[{name:'http_method_allowed',ok:false,result:req.method}]},405,req)}
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
export { handler as GET, handler as POST, handler as DELETE };
