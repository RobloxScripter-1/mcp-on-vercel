import { createHash, randomBytes } from 'node:crypto';
import { verifyOAuthClaims } from './oauth-crypto';

const BASE_URL = (process.env.MCP_PUBLIC_BASE_URL || 'https://mcp-on-vercel-msaiful0404-5024s-projects.vercel.app').replace(/\/+$/, '');
const RESOURCE = process.env.MCP_RESOURCE_URL || BASE_URL + '/mcp';
const METADATA_URL = BASE_URL + '/.well-known/oauth-protected-resource/mcp';

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
async function handler(request:Request):Promise<Response>{
  const trace=traceId(),started=Date.now(),info=requestInfo(request);
  const authHeader=request.headers.get('authorization')||'';
  const match=/^Bearer\s+([A-Za-z0-9._-]{32,})$/i.exec(authHeader);
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
      const missing=['GITHUB_OAUTH_CLIENT_SECRET','GITHUB_ALLOWED_LOGIN','PROXY_SECRET'].filter(k=>!process.env[k]);
      if(missing.length){
        log('mcp_auth_configuration_failed',{trace_id:trace,stage:'mcp_auth_environment_incomplete',missing_environment:missing});
        res=response(503,{error:'server_not_configured',stage:'mcp_auth_environment_incomplete',trace_id:trace,missing_environment:missing,checks:[{name:'required_auth_environment',ok:false,missing}]},trace);
      }else{
        const record=verifyOAuthClaims(match[1],'access_token');
        if(!record){
          const checks=[{name:'access_token_signature_valid',ok:false},{name:'access_token_not_expired',ok:false}];
          log('mcp_auth_rejected',{trace_id:trace,flow_id:null,stage:'mcp_access_token_invalid_or_expired',token_fingerprint:tokenFingerprint,checks});
          res=challenge(trace,'mcp_access_token_invalid_or_expired',checks,{token_fingerprint:tokenFingerprint});
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
            const headers=new Headers(request.headers);headers.delete('host');headers.delete('authorization');headers.set('x-mcp-parent-trace-id',trace);if(typeof record.trace_id==='string'&&/^[a-f0-9]{16}$/i.test(record.trace_id))headers.set('x-mcp-flow-id',record.trace_id);else headers.delete('x-mcp-flow-id');
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
