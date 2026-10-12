import { createHash, randomBytes } from 'node:crypto';

const BASE_URL = (process.env.MCP_PUBLIC_BASE_URL || 'https://mcp-on-vercel-msaiful0404-5024s-projects.vercel.app').replace(/\/+$/, '');
const RESOURCE = process.env.MCP_RESOURCE_URL || BASE_URL + '/mcp';
const METADATA_URL = BASE_URL + '/.well-known/oauth-protected-resource/mcp';

type Diagnostic = { kind:string; command:string; http_status:number; url_configured:boolean; token_configured:boolean; detail?:string; content_type?:string; response_bytes?:number };
class StorageDiagnosticError extends Error {
  constructor(readonly diagnostic:Diagnostic){super(diagnostic.kind)}
}
const traceId=()=>randomBytes(8).toString('hex');
function safeText(value:unknown){
  let out=String(value??'unknown');
  for(const secret of [process.env.GITHUB_OAUTH_CLIENT_SECRET,process.env.GITHUB_PAT,process.env.PROXY_SECRET,process.env.UPSTASH_REDIS_REST_TOKEN,process.env.UPSTASH_REDIS_REST_URL].filter((v):v is string=>Boolean(v)))out=out.split(secret).join('[redacted]');
  return out.replace(/Bearer\s+\S+/gi,'Bearer [redacted]').replace(/\bgithub_pat_[A-Za-z0-9_]+\b/g,'[GitHub token redacted]').replace(/https?:\/\/\S+/gi,'[URL redacted]').slice(0,320);
}
function requestInfo(req:Request){
  const u=new URL(req.url),names:string[]=[];
  u.searchParams.forEach((_v,k)=>{if(!names.includes(k))names.push(k)});
  return {method:req.method,path:u.pathname,query_parameter_names:names,host:req.headers.get('host')||u.host,forwarded_host:req.headers.get('x-forwarded-host')||null,forwarded_proto:req.headers.get('x-forwarded-proto')||null,content_type:req.headers.get('content-type')||null,vercel_request_id:req.headers.get('x-vercel-id')||null,user_agent:safeText(req.headers.get('user-agent')||'unknown')};
}
function log(event:string,data:Record<string,unknown>={}){
  console.info(JSON.stringify({event,timestamp:new Date().toISOString(),...data}));
}
function response(status:number,payload:unknown,trace:string,extraHeaders:Record<string,string>={}){
  return new Response(JSON.stringify(payload),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','x-mcp-trace-id':trace,...extraHeaders}});
}
function withTrace(res:Response,trace:string){
  const headers=new Headers(res.headers);headers.set('x-mcp-trace-id',trace);headers.set('Cache-Control','no-store');
  return new Response(res.body,{status:res.status,statusText:res.statusText,headers});
}
function challenge(trace:string,stage:string,checks:any[],details:Record<string,unknown>={}):Response{
  const payload={error:'invalid_token',stage,trace_id:trace,checks,...details,diagnosis:'Provide a valid OAuth access token issued by this server.'};
  return response(401,payload,trace,{'WWW-Authenticate':'Bearer resource_metadata="'+METADATA_URL+'", scope="github", error="invalid_token"'});
}
function storageDetails(e:unknown):Diagnostic{
  if(e instanceof StorageDiagnosticError)return e.diagnostic;
  const envError=e as any;
  return {kind:typeof envError?.kind==='string'?envError.kind:'unknown_error',command:typeof envError?.command==='string'?envError.command:'GET',http_status:typeof envError?.status==='number'?envError.status:0,url_configured:Boolean(process.env.UPSTASH_REDIS_REST_URL),token_configured:Boolean(process.env.UPSTASH_REDIS_REST_TOKEN),...(envError?.message?{detail:safeText(envError.message)}:{})};
}
async function redisGet(key:string,trace:string):Promise<any|null>{
  const url=process.env.UPSTASH_REDIS_REST_URL,token=process.env.UPSTASH_REDIS_REST_TOKEN;
  if(!url&&!token)throw new StorageDiagnosticError({kind:'missing_url_and_token',command:'GET',http_status:0,url_configured:false,token_configured:false});
  if(!url)throw new StorageDiagnosticError({kind:'missing_url',command:'GET',http_status:0,url_configured:false,token_configured:true});
  if(!token)throw new StorageDiagnosticError({kind:'missing_token',command:'GET',http_status:0,url_configured:true,token_configured:false});
  const started=Date.now();
  try{
    let r:Response;
    try{r=await fetch(url,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(['GET',key]),cache:'no-store'});}
    catch(e:any){throw new StorageDiagnosticError({kind:'network_error',command:'GET',http_status:0,url_configured:true,token_configured:true,detail:safeText(e?.name||'fetch_failed')});}
    const contentType=r.headers.get('content-type')||'unknown';
    let raw:string;
    try{raw=await r.text();}catch(e:any){throw new StorageDiagnosticError({kind:'response_read_error',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,detail:safeText(e?.name||'body_read_failed')});}
    let parsed:any;
    try{parsed=JSON.parse(raw)}catch{throw new StorageDiagnosticError({kind:'non_json_response',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,response_bytes:raw.length});}
    if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new StorageDiagnosticError({kind:'invalid_response_shape',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,response_bytes:raw.length});
    if(parsed.error)throw new StorageDiagnosticError({kind:'redis_error',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,response_bytes:raw.length,detail:safeText(parsed.error)});
    if(!r.ok)throw new StorageDiagnosticError({kind:'http_error',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,response_bytes:raw.length});
    if(!Object.prototype.hasOwnProperty.call(parsed,'result'))throw new StorageDiagnosticError({kind:'missing_result',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,response_bytes:raw.length});
    if(parsed.result===null){log('mcp_auth_redis_lookup_completed',{trace_id:trace,command:'GET',duration_ms:Date.now()-started,key_found:false});return null;}
    if(typeof parsed.result!=='string')throw new StorageDiagnosticError({kind:'unexpected_get_result_type',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,detail:'Expected a string or null Redis GET result.'});
    try{const value=JSON.parse(parsed.result);log('mcp_auth_redis_lookup_completed',{trace_id:trace,command:'GET',duration_ms:Date.now()-started,key_found:true,record_type:value===null?'null':Array.isArray(value)?'array':typeof value});return value;}
    catch{throw new StorageDiagnosticError({kind:'invalid_json_result',command:'GET',http_status:r.status,url_configured:true,token_configured:true,content_type:contentType,detail:'Stored OAuth access-token record is not valid JSON.'});}
  }catch(e){const diagnostic=storageDetails(e);log('mcp_auth_redis_lookup_failed',{trace_id:trace,duration_ms:Date.now()-started,redis:diagnostic});throw e;}
}
async function handler(request:Request):Promise<Response>{
  const trace=traceId(),started=Date.now(),info=requestInfo(request);
  const authHeader=request.headers.get('authorization')||'';
  const match=/^Bearer\s+([A-Za-z0-9_-]{32,})$/i.exec(authHeader);
  const tokenFingerprint=match?createHash('sha256').update(match[1]).digest('hex').slice(0,12):null;
  log('mcp_auth_request_started',{trace_id:trace,request:info,bearer_header_present:Boolean(authHeader),bearer_format_valid:Boolean(match),token_fingerprint:tokenFingerprint});
  let res:Response;
  try{
    if(request.method==='OPTIONS')res=new Response(null,{status:204,headers:{'Cache-Control':'no-store','x-mcp-trace-id':trace}});
    else if(!match){
      const hasBearer=/^Bearer\s+/i.test(authHeader);
      log('mcp_auth_rejected',{trace_id:trace,stage:hasBearer?'mcp_bearer_format_invalid':'mcp_bearer_missing',checks:[{name:'authorization_header_present',ok:Boolean(authHeader)},{name:'bearer_scheme_present',ok:hasBearer},{name:'bearer_token_format_valid',ok:false}]});
      res=challenge(trace,hasBearer?'mcp_bearer_format_invalid':'mcp_bearer_missing',[{name:'authorization_header_present',ok:Boolean(authHeader)},{name:'bearer_token_format_valid',ok:false}]);
    }else{
      const missing=['UPSTASH_REDIS_REST_URL','UPSTASH_REDIS_REST_TOKEN','PROXY_SECRET'].filter(k=>!process.env[k]);
      if(missing.length){
        log('mcp_auth_configuration_failed',{trace_id:trace,stage:'mcp_auth_environment_incomplete',missing_environment:missing});
        res=response(503,{error:'server_not_configured',stage:'mcp_auth_environment_incomplete',trace_id:trace,missing_environment:missing,checks:[{name:'required_auth_environment',ok:false,missing}]},trace);
      }else{
        let record:any;
        try{record=await redisGet('mcp_access_token:'+match[1],trace)}
        catch(e){
          const redis=storageDetails(e);
          log('mcp_auth_failed',{trace_id:trace,stage:'mcp_auth_redis_lookup_failed',redis,exception_name:e instanceof Error?e.name:'UnknownError'});
          res=response(503,{error:'authentication_storage_unavailable',stage:'mcp_auth_redis_lookup_failed',trace_id:trace,redis,checks:[{name:'redis_access_token_lookup',ok:false,redis}]},trace);
          log('mcp_auth_request_completed',{trace_id:trace,status:res.status,duration_ms:Date.now()-started,stage:'mcp_auth_redis_lookup_failed'});
          return withTrace(res,trace);
        }
        if(!record){
          const checks=[{name:'access_token_record_found',ok:false},{name:'resource_matches',ok:false,result:'not_checked'},{name:'scope_is_github',ok:false,result:'not_checked'},{name:'login_matches_allowlist',ok:false,result:'not_checked'}];
          log('mcp_auth_rejected',{trace_id:trace,flow_id:null,stage:'mcp_access_token_not_found_or_expired',token_fingerprint:tokenFingerprint,checks});
          res=challenge(trace,'mcp_access_token_not_found_or_expired',checks,{token_fingerprint:tokenFingerprint});
        }else{
          const allowed=(process.env.GITHUB_ALLOWED_LOGIN||'').trim().toLowerCase();
          const resourceOk=record.resource===RESOURCE,scopeOk=record.scope==='github',loginTypeOk=typeof record.login==='string',loginOk=loginTypeOk&&record.login.toLowerCase()===allowed;
          const checks=[{name:'access_token_record_found',ok:true},{name:'resource_matches',ok:resourceOk},{name:'scope_is_github',ok:scopeOk},{name:'login_field_is_string',ok:loginTypeOk},{name:'login_matches_allowlist',ok:loginOk}];
          const failed=checks.find(c=>!c.ok);
          if(failed){
            const stage=!resourceOk?'mcp_access_token_resource_mismatch':!scopeOk?'mcp_access_token_scope_mismatch':!loginTypeOk?'mcp_access_token_login_missing':'mcp_account_allowlist_mismatch';
            log('mcp_auth_rejected',{trace_id:trace,flow_id:typeof record.trace_id==='string'?record.trace_id:null,stage,token_fingerprint:tokenFingerprint,checks});
            res=challenge(trace,stage,checks,{flow_id:typeof record.trace_id==='string'?record.trace_id:null,token_fingerprint:tokenFingerprint});
          }else{
            log('mcp_auth_validated',{trace_id:trace,flow_id:typeof record.trace_id==='string'?record.trace_id:null,token_fingerprint:tokenFingerprint,checks});
            const upstream=new URL(BASE_URL+'/api/server');
            upstream.searchParams.set('key',process.env.PROXY_SECRET!);
            const headers=new Headers(request.headers);headers.delete('host');headers.delete('authorization');headers.set('x-mcp-parent-trace-id',trace);
            let upstreamResponse:Response;
            try{
              upstreamResponse=await fetch(upstream,{method:request.method,headers,body:request.method==='GET'||request.method==='HEAD'?undefined:await request.arrayBuffer(),redirect:'manual',cache:'no-store'});
            }catch(e){
              const exception={name:e instanceof Error?e.name:'UnknownError',message:safeText(e instanceof Error?e.message:e)};
              log('mcp_upstream_request_failed',{trace_id:trace,flow_id:typeof record.trace_id==='string'?record.trace_id:null,stage:'mcp_upstream_network_error',exception,upstream_path:'/api/server'});
              res=response(502,{error:'upstream_unavailable',stage:'mcp_upstream_network_error',trace_id:trace,flow_id:typeof record.trace_id==='string'?record.trace_id:null,exception},trace);
              log('mcp_auth_request_completed',{trace_id:trace,status:res.status,duration_ms:Date.now()-started,stage:'mcp_upstream_network_error'});
              return withTrace(res,trace);
            }
            const responseHeaders=new Headers(upstreamResponse.headers);responseHeaders.set('Cache-Control','no-store');responseHeaders.set('x-mcp-trace-id',trace);
            log(upstreamResponse.status>=500?'mcp_upstream_response_failed':'mcp_upstream_response_received',{trace_id:trace,flow_id:typeof record.trace_id==='string'?record.trace_id:null,upstream_status:upstreamResponse.status,upstream_content_type:upstreamResponse.headers.get('content-type')||null,upstream_vercel_request_id:upstreamResponse.headers.get('x-vercel-id')||null,duration_ms:Date.now()-started});
            res=new Response(upstreamResponse.body,{status:upstreamResponse.status,statusText:upstreamResponse.statusText,headers:responseHeaders});
          }
        }
      }
    }
  }catch(e){
    const exception={name:e instanceof Error?e.name:'UnknownError',message:safeText(e instanceof Error?e.message:e)};
    log('mcp_auth_unhandled_exception',{trace_id:trace,exception});
    res=response(500,{error:'internal_auth_error',stage:'mcp_auth_unhandled_exception',trace_id:trace,exception},trace);
  }
  log(res.status>=400?'mcp_auth_request_completed_with_error':'mcp_auth_request_completed',{trace_id:trace,status:res.status,duration_ms:Date.now()-started,request_path:new URL(request.url).pathname});
  return withTrace(res,trace);
}

export { handler as GET, handler as POST, handler as DELETE };
