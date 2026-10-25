import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { handleRequest } from '../worker/worker.mjs';
const ORIGIN='https://eliyashtraser.github.io';
const key=n=>'sk-test_'+n.repeat(35);
function setup(options={}){
  const sql=new DatabaseSync(':memory:');sql.exec(fs.readFileSync(new URL('../worker/schema.sql',import.meta.url),'utf8'));
  const db={prepare(query){let args=[];return {bind(...values){args=values;return this;},async first(){return sql.prepare(query).get(...args)||null;},async run(){return sql.prepare(query).run(...args);}};},async batch(statements){sql.exec('BEGIN');try{const results=[];for(const st of statements)results.push(await st.run());sql.exec('COMMIT');return results;}catch(e){sql.exec('ROLLBACK');throw e;}}};
  const env={DB:db,VAULT_KEY:Buffer.alloc(32,7).toString('base64url'),...options};const calls=[];
  let nextFlag=false,nextStatus=200,nextIncomplete=false;
  const provider=async(url,request)=>{calls.push({url,key:request.headers.Authorization,payload:JSON.parse(request.body)});if(nextStatus!==200)return Response.json({error:{message:'DO NOT ECHO A SECRET'}},{status:nextStatus});if(url.endsWith('/moderations'))return Response.json({results:[{flagged:nextFlag}]});return Response.json({status:nextIncomplete?'incomplete':'completed',output:[{type:'message',role:'assistant',content:[{type:'output_text',text:'קודם נזהה את מקום הספרה.'}]}]});};
  async function call(path,data={},token,origin=ORIGIN){const wait=[];const request=new Request('https://example.workers.dev'+path,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(data)});const response=await handleRequest(request,env,provider,{waitUntil(p){wait.push(p);}});const result=await response.json();await Promise.all(wait);return {status:response.status,data:result,headers:response.headers};}
  const create=apiKey=>call('/api/families',{apiKey,adultConsent:true});
  return {sql,env,calls,call,create,flag:()=>nextFlag=true,reject:status=>nextStatus=status,incomplete:()=>nextIncomplete=true};
}
test('two families always use their own encrypted key; no key appears in responses or model prompts',async()=>{
  const x=setup();const a=await x.create(key('a')),b=await x.create(key('b'));assert.equal(a.status,201);assert.equal(b.status,201);
  assert.equal(JSON.stringify(a.data).includes(key('a')),false);
  const ciphers=x.sql.prepare('SELECT key_cipher,parent_hash,child_hash FROM families').all();
  for(const row of ciphers){assert.equal(JSON.stringify(row).includes('sk-test_'),false);assert.equal(JSON.stringify(row).includes(a.data.parentCode),false);}
  await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.sessionToken);
  await x.call('/api/tutor',{questionId:'fractions-2',mode:'explain'},b.data.sessionToken);
  assert.deepEqual(x.calls.map(c=>c.key),['Bearer '+key('a'),'Bearer '+key('a'),'Bearer '+key('b'),'Bearer '+key('b')]);
  for(const c of x.calls){assert.equal(JSON.stringify(c.payload).includes(a.data.sessionToken),false);assert.equal(JSON.stringify(c.payload).includes(key('a')),false);}
  assert.equal(x.calls[0].payload.store,false);assert.equal(x.calls[0].payload.model,'gpt-6-astra');
  assert.equal((await x.call('/api/parent',{action:'status'},a.data.sessionToken)).status,401);
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.parentCode)).status,401);
});
test('missing authentication, hostile origin and arbitrary prompts never invoke a model',async()=>{
  const x=setup();const a=await x.create(key('a'));
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint'})).status,401);
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.sessionToken,'https://evil.example')).status,403);
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint',prompt:'arbitrary free text'},a.data.sessionToken)).status,400);
  assert.equal((await x.call('/api/tutor',{questionId:'unknown',mode:'hint'},a.data.sessionToken)).status,400);
  assert.equal(x.calls.length,0);
});
test('daily caps are atomic and failed keys never fall back to another family',async()=>{
  const x=setup({DAILY_FAMILY_LIMIT:'2'});const a=await x.create(key('a'));
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.sessionToken)).status,200);
  assert.equal((await x.call('/api/tutor',{questionId:'place-1',mode:'hint'},a.data.sessionToken)).status,200);
  const blocked=await x.call('/api/tutor',{questionId:'place-2',mode:'explain'},a.data.sessionToken);assert.equal(blocked.status,429);assert.equal(blocked.data.error,'DAILY');assert.equal(x.calls.length,4);
  const y=setup();const b=await y.create(key('b'));y.reject(401);
  const rejected=await y.call('/api/tutor',{questionId:'place-0',mode:'hint'},b.data.sessionToken);assert.equal(rejected.data.error,'KEY_INVALID');assert.equal(y.calls.length,1);assert.equal(JSON.stringify(rejected).includes('DO NOT ECHO'),false);
  assert.equal(y.sql.prepare('SELECT busy_until FROM families').get().busy_until,0);
});
test('rotating the child code invalidates all child sessions and the old pairing code',async()=>{
  const x=setup();const a=await x.create(key('a'));
  const paired=await x.call('/api/pair',{childCode:a.data.childCode});assert.equal(paired.status,200);
  const rotated=await x.call('/api/parent',{action:'rotateChild'},a.data.parentCode);assert.equal(rotated.status,200);
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.sessionToken)).status,401);
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},paired.data.sessionToken)).status,401);
  assert.equal((await x.call('/api/pair',{childCode:a.data.childCode})).status,401);
  assert.equal((await x.call('/api/pair',{childCode:rotated.data.childCode})).status,200);
});
test('key replacement and family deletion are authorized only by that family parent code',async()=>{
  const x=setup();const a=await x.create(key('a')),b=await x.create(key('b'));
  assert.equal((await x.call('/api/parent',{action:'replaceKey',apiKey:key('c')},a.data.parentCode)).status,200);
  await x.call('/api/tutor',{questionId:'order-1',mode:'hint'},a.data.sessionToken);assert.equal(x.calls[0].key,'Bearer '+key('c'));
  assert.equal((await x.call('/api/parent',{action:'delete'},a.data.parentCode)).status,200);
  assert.equal((await x.call('/api/parent',{action:'status'},a.data.parentCode)).status,401);
  assert.equal((await x.call('/api/tutor',{questionId:'order-1',mode:'hint'},a.data.sessionToken)).status,401);
  assert.equal((await x.call('/api/parent',{action:'status'},b.data.parentCode)).status,200);
});
test('unsafe, incomplete or unmoderated model output is never displayed',async()=>{
  const x=setup();const a=await x.create(key('a'));x.flag();const flagged=await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.sessionToken);assert.equal(flagged.status,422);assert.equal(flagged.data.text,undefined);
  const y=setup();const b=await y.create(key('b'));y.incomplete();const incomplete=await y.call('/api/tutor',{questionId:'place-0',mode:'hint'},b.data.sessionToken);assert.equal(incomplete.status,502);assert.equal(y.calls.length,1);assert.equal(incomplete.data.text,undefined);
});
test('ciphertext cannot be swapped across families, and a busy family cannot issue parallel requests',async()=>{
  const x=setup();const a=await x.create(key('a'));await x.create(key('b'));const rows=x.sql.prepare('SELECT id,key_cipher FROM families ORDER BY created_at').all();x.sql.prepare('UPDATE families SET key_cipher=? WHERE id=?').run(rows[1].key_cipher,rows[0].id);
  const bad=await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.sessionToken);assert.equal(bad.status,503);assert.equal(bad.data.error,'VAULT');assert.equal(x.calls.length,0);
  x.sql.prepare('UPDATE families SET busy_until=?').run(Math.floor(Date.now()/1000)+100);
  assert.equal((await x.call('/api/tutor',{questionId:'place-0',mode:'hint'},a.data.sessionToken)).data.error,'BUSY');
});
test('setup and parent-consent failures stay closed',async()=>{
  const x=setup();assert.equal((await x.call('/api/families',{apiKey:key('a'),adultConsent:false})).status,400);
  const y=setup({VAULT_KEY:'not-a-secret'});assert.equal((await y.create(key('a'))).status,503);assert.equal(y.calls.length,0);
});
