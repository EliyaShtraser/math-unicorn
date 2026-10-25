/** Math Unicorn: private API keys, family sessions, fixed math prompts only. */
const DEFAULTS = Object.freeze({
  origin: 'https://eliyashtraser.github.io',
  model: 'gpt-6-astra',
  familyDailyLimit: 30,
  sessionDays: 30,
});
const SYSTEM = `את מורה פרטית למתמטיקה לילדה בת 11, בעברית ובלשון נקבה.
הסבירי בעדינות, בקצרה ובמילים פשוטות. עסקי רק בתרגיל המתמטי שסופק.
השתמשי בנתוני התרגיל ובפתרון המאומת שסופקו. אל תמציאי עובדות או תוצאות סותרות.
במצב hint: תני רמז אחד או שניים, בלי לגלות את התשובה הסופית.
במצב explain: הסבירי בדרך נוספת עד ארבעה שלבים קצרים, כולל התוצאה.
אל תשאלי לשם, לגיל מדויק, למקום מגורים, לפרטי קשר או לכל מידע אישי.
אל תבקשי לעבור לאתר אחר ואל תייצרי קישורים.
כתבי טקסט פשוט. בלי HTML, בלי Markdown ובלי LaTeX.
כתבי שברים כך: 3/4. כתבי ביטויים מתמטיים בשורה נפרדת כדי שלא יתהפכו בעברית.
אם חסר נתון, הסבירי מה חסר. אל תטעני שאת אדם או שהסבר AI תמיד נכון.`;
const encoder = new TextEncoder();
const API = 'https://api.openai.com/v1/';
class Problem extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
const fail = (status, code, message) => { throw new Problem(status, code, message); };
const now = () => Math.floor(Date.now() / 1000);
function base64(bytes) { let s=''; for (const byte of bytes) s+=String.fromCharCode(byte); return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,''); }
function unbase64(s) { const raw=atob(s.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-s.length%4)%4));return Uint8Array.from(raw,x=>x.charCodeAt(0)); }
function randomToken(prefix, size=32) { return prefix+base64(crypto.getRandomValues(new Uint8Array(size))); }
async function digest(text) { return base64(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)))); }
async function vaultKey(env) {
  if (typeof env.VAULT_KEY !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(env.VAULT_KEY)) fail(503,'SETUP','חיבור ה־AI עדיין לא הוגדר. יש לפנות למפעיל האתר.');
  return crypto.subtle.importKey('raw',unbase64(env.VAULT_KEY),'AES-GCM',false,['encrypt','decrypt']);
}
async function seal(env, familyId, apiKey) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const bytes=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(familyId)},await vaultKey(env),encoder.encode(apiKey));
  return 'v1.'+base64(iv)+'.'+base64(new Uint8Array(bytes));
}
async function unseal(env, family) {
  try { const [version,iv,data]=family.key_cipher.split('.'); if(version!=='v1') throw Error();
    const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:unbase64(iv),additionalData:encoder.encode(family.id)},await vaultKey(env),unbase64(data));
    return new TextDecoder().decode(bytes);
  } catch(e) { if(e instanceof Problem)throw e; fail(503,'VAULT','לא ניתן לפתוח את החיבור המשפחתי. יש לפנות למפעיל האתר.'); }
}
function checkApiKey(key) { if(typeof key!=='string'||!/^sk-[A-Za-z0-9_-]{20,510}$/.test(key)) fail(400,'KEY_FORMAT','יש להזין מפתח API ייעודי של OpenAI, ולא סיסמת ChatGPT.'); }
async function body(request, allowed) {
  if(!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) fail(415,'JSON','נדרש JSON.');
  const declared=Number(request.headers.get('content-length')||0); if(declared>4096)fail(413,'SIZE','הבקשה גדולה מדי.');
  const reader=request.body?.getReader(); if(!reader)fail(400,'JSON','חסר תוכן הבקשה.');
  const parts=[];let length=0;
  while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>4096){await reader.cancel();fail(413,'SIZE','הבקשה גדולה מדי.');}parts.push(value);}
  const bytes=new Uint8Array(length);let offset=0;for(const p of parts){bytes.set(p,offset);offset+=p.length;}
  let data;try{data=JSON.parse(new TextDecoder().decode(bytes));}catch{fail(400,'JSON','תוכן הבקשה אינו תקין.');}
  if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(k=>!allowed.includes(k)))fail(400,'FIELDS','שדות הבקשה אינם תקינים.');
  return data;
}
function bearer(request, prefix) {const h=request.headers.get('authorization')||'';const token=h.startsWith('Bearer ')?h.slice(7):'';if(!new RegExp('^'+prefix+'[A-Za-z0-9_-]{43}$').test(token))fail(401,'AUTH','נדרש חיבור משפחתי תקין.');return token;}
async function parentFamily(request,env) {
  const h=await digest(bearer(request,'p_'));
  const row=await env.DB.prepare('SELECT * FROM families WHERE parent_hash = ?').bind(h).first();
  if(!row)fail(401,'PARENT_AUTH','קוד ההורים אינו תקין.');return row;
}
async function studentFamily(request,env) {
  const h=await digest(bearer(request,'s_'));
  const row=await env.DB.prepare('SELECT f.* FROM families f JOIN sessions s ON s.family_id=f.id WHERE s.token_hash=? AND s.expires_at>?').bind(h,now()).first();
  if(!row)fail(401,'PAIR','החיבור המשפחתי פג או בוטל. בקשי מהורה לחבר מחדש.');return row;
}
async function consume(env,bucket,limit,expiresAt,code='LIMIT') {
  const row=await env.DB.prepare(`INSERT INTO usage (bucket,count,expires_at) VALUES (?,1,?)
    ON CONFLICT(bucket) DO UPDATE SET count=count+1 WHERE count<? RETURNING count`).bind(bucket,expiresAt,limit).first();
  if(!row)fail(429,code,'הגעתן למגבלת הבקשות. נסו שוב מאוחר יותר.');return row.count;
}
async function ipLimit(request,env,kind,limit,seconds) {
  const ip=request.headers.get('CF-Connecting-IP')||'unknown';
  const slot=Math.floor(now()/seconds);
  const h=await digest(env.VAULT_KEY+':'+ip);
  await consume(env,`ip:${kind}:${slot}:${h}`,limit,(slot+2)*seconds,'RATE');
}
async function newSession(env,familyId) {
  const token=randomToken('s_'); const expiresAt=now()+DEFAULTS.sessionDays*86400;
  await env.DB.prepare('INSERT INTO sessions (token_hash,family_id,expires_at) VALUES (?,?,?)').bind(await digest(token),familyId,expiresAt).run();
  return {sessionToken:token,expiresAt};
}
async function upstream(path,key,payload,fetcher,timeoutMs=35000) {
  let response;
  try {response=await fetcher(API+path,{method:'POST',headers:{'Authorization':'Bearer '+key,'Content-Type':'application/json'},body:JSON.stringify(payload),signal:AbortSignal.timeout(timeoutMs)});}
  catch{fail(504,'UPSTREAM_TIMEOUT','ה־AI לא ענה בזמן. אפשר לנסות שוב.');}
  if(!response.ok){
    if(response.status===401)fail(400,'KEY_INVALID','מפתח ה־API אינו תקין או בוטל. הורה צריך לעדכן אותו.');
    if(response.status===403||response.status===404)fail(400,'KEY_PERMISSION','למפתח אין גישה למודל או לפעולה הנדרשת. יש לבדוק הרשאות וחשבונית בחשבון OpenAI.');
    if(response.status===429)fail(429,'PROVIDER_LIMIT','חשבון ה־API הגיע למכסה או למגבלה. הורה צריך לבדוק את החשבון.');
    fail(502,'PROVIDER','שירות ה־AI לא זמין כרגע. אפשר להמשיך בתרגול הרגיל.');
  }
  try{return await response.json();}catch{fail(502,'PROVIDER','התקבלה תשובה לא תקינה משירות ה־AI.');}
}
function responseText(data) {
  if(data.status!=='completed')fail(502,'INCOMPLETE','ההסבר לא הושלם. נסי שוב, או השתמשי בפתרון המובנה.');
  const text=(Array.isArray(data.output)?data.output:[]).filter(x=>x.type==='message'&&x.role==='assistant').flatMap(x=>Array.isArray(x.content)?x.content:[]).filter(x=>x.type==='output_text'&&typeof x.text==='string').map(x=>x.text).join('\n').trim();
  if(!text||text.length>5000)fail(502,'EMPTY','לא התקבל הסבר מלא. אפשר להשתמש בפתרון המובנה.');return text;
}
function json(data,status,origin) {
  const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Vary':'Origin'};
  if(origin)headers['Access-Control-Allow-Origin']=origin;
  return new Response(JSON.stringify(data),{status,headers});
}
export async function handleRequest(request,env,fetcher=fetch,ctx={waitUntil(){}}) {
  const origin=request.headers.get('origin');const allowed=env.ALLOWED_ORIGIN||DEFAULTS.origin;
  const cors=origin===allowed?origin:null;const path=new URL(request.url).pathname;
  try {
    if(request.method==='GET'&&path==='/health'){
      let ready=false;try{await vaultKey(env);if(env.DB){await env.DB.prepare('SELECT id FROM families LIMIT 1').first();ready=true;}}catch{}
      return json({ready,version:1},ready?200:503,cors);
    }
    if(origin!==allowed)fail(403,'ORIGIN','מקור הבקשה אינו מורשה.');
    if(request.method==='OPTIONS'){
      if(request.headers.get('Access-Control-Request-Method')!=='POST')fail(405,'METHOD','פעולה לא נתמכת.');
      const headers=(request.headers.get('Access-Control-Request-Headers')||'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean);
      if(headers.some(h=>!['authorization','content-type'].includes(h)))fail(403,'HEADERS','כותרת לא מורשית.');
      return new Response(null,{status:204,headers:{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Max-Age':'600','Vary':'Origin'}});
    }
    if(request.method!=='POST')fail(405,'METHOD','פעולה לא נתמכת.');
    if(!env.DB)fail(503,'SETUP','חיבור ה־AI עדיין לא הוגדר.');await vaultKey(env);
    if(path==='/api/families'){
      await ipLimit(request,env,'create',5,86400);
      const data=await body(request,['apiKey','adultConsent']);checkApiKey(data.apiKey);
      if(data.adultConsent!==true)fail(400,'CONSENT','הגדרת חיבור AI מיועדת להורה בלבד ודורשת אישור מפורש.');
      const id=randomToken('f_',18),parentCode=randomToken('p_'),childCode=randomToken('c_');
      const cipher=await seal(env,id,data.apiKey);
      await env.DB.prepare('INSERT INTO families (id,parent_hash,child_hash,key_cipher,created_at) VALUES (?,?,?,?,?)').bind(id,await digest(parentCode),await digest(childCode),cipher,now()).run();
      const session=await newSession(env,id);
      return json({parentCode,childCode,...session,keyVerified:false},201,cors);
    }
    if(path==='/api/pair'){
      await ipLimit(request,env,'pair',15,60);
      const data=await body(request,['childCode']);
      if(typeof data.childCode!=='string'||!/^c_[A-Za-z0-9_-]{43}$/.test(data.childCode))fail(401,'PAIR','הקוד המשפחתי אינו תקין.');
      const family=await env.DB.prepare('SELECT id FROM families WHERE child_hash=?').bind(await digest(data.childCode)).first();
      if(!family)fail(401,'PAIR','הקוד המשפחתי אינו תקין או הוחלף.');
      return json(await newSession(env,family.id),200,cors);
    }
    if(path==='/api/parent'){
      const family=await parentFamily(request,env);
      await ipLimit(request,env,'parent',20,60);
      const data=await body(request,['action','apiKey']);
      if(data.action==='status'){
        const used=await env.DB.prepare('SELECT count FROM usage WHERE bucket=?').bind(`family:${family.id}:${Math.floor(now()/86400)}`).first();
        return json({connected:true,usedToday:used?.count||0,dailyLimit:familyLimit(env),model:env.OPENAI_MODEL||DEFAULTS.model},200,cors);
      }
      if(data.action==='replaceKey'){
        checkApiKey(data.apiKey);const cipher=await seal(env,family.id,data.apiKey);
        await env.DB.prepare('UPDATE families SET key_cipher=? WHERE id=?').bind(cipher,family.id).run();
        return json({updated:true,keyVerified:false},200,cors);
      }
      if(data.action==='rotateChild'){
        const childCode=randomToken('c_');
        await env.DB.batch([env.DB.prepare('UPDATE families SET child_hash=? WHERE id=?').bind(await digest(childCode),family.id),env.DB.prepare('DELETE FROM sessions WHERE family_id=?').bind(family.id)]);
        return json({childCode,revokedSessions:true},200,cors);
      }
      if(data.action==='delete'){
        await env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE family_id=?').bind(family.id),env.DB.prepare('DELETE FROM families WHERE id=?').bind(family.id)]);
        return json({deleted:true},200,cors);
      }
      fail(400,'ACTION','פעולת ההורים אינה תקינה.');
    }
    if(path==='/api/tutor'){
      const family=await studentFamily(request,env);
      const data=await body(request,['questionId','mode']);
      const question=typeof data.questionId==='string'?CATALOG[data.questionId]:null;
      if(!question||!['hint','explain'].includes(data.mode))fail(400,'QUESTION','אפשר לקבל עזרה רק בתרגילים הקיימים באתר.');
      const lock=randomToken('lock_',16),time=now();
      const locked=await env.DB.prepare('UPDATE families SET busy_token=?,busy_until=? WHERE id=? AND busy_until<=? RETURNING id').bind(lock,time+75,family.id,time).first();
      if(!locked)fail(429,'BUSY','כבר מתבקש הסבר למשפחה הזאת. המתיני לסיום הבקשה.');
      try {
        await consume(env,`family:${family.id}:${Math.floor(time/86400)}`,familyLimit(env),(Math.floor(time/86400)+2)*86400,'DAILY');
        const key=await unseal(env,family);
        // Only trusted curriculum data is sent. No child answer, identity or session token.
        const input=JSON.stringify({mode:data.mode,topic:question.topic,question:question.prompt,options:question.options,verifiedAnswer:question.answer,verifiedExplanation:question.explain});
        const result=await upstream('responses',key,{model:env.OPENAI_MODEL||DEFAULTS.model,reasoning:{effort:'low'},instructions:SYSTEM,input,store:false,max_output_tokens:1400},fetcher);
        const text=responseText(result);
        const moderation=await upstream('moderations',key,{model:'omni-moderation-latest',input:text},fetcher,15000);
        if(!Array.isArray(moderation.results)||moderation.results.length!==1||moderation.results[0].flagged!==false)fail(422,'FILTERED','ההסבר לא הוצג. השתמשי בפתרון המובנה או בקשי עזרה מהורה.');
        return json({text,mode:data.mode},200,cors);
      } finally {await env.DB.prepare('UPDATE families SET busy_token=NULL,busy_until=0 WHERE id=? AND busy_token=?').bind(family.id,lock).run();}
    }
    fail(404,'NOT_FOUND','הפעולה אינה קיימת.');
  } catch(error) {
    if(error instanceof Problem)return json({error:error.code,message:error.message},error.status,cors);
    // Never echo upstream payloads, API keys, SQL errors or exception messages.
    return json({error:'SERVER',message:'לא ניתן להשלים את הבקשה. אפשר להמשיך בתרגול הרגיל ולפנות להורה.'},500,cors);
  } finally {
    if(env.DB)ctx.waitUntil(Promise.allSettled([
      env.DB.prepare('DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE expires_at<? LIMIT 25)').bind(now()).run(),
      env.DB.prepare('DELETE FROM usage WHERE bucket IN (SELECT bucket FROM usage WHERE expires_at<? LIMIT 25)').bind(now()).run()
    ]));
  }
}
function familyLimit(env){const n=Number(env.DAILY_FAMILY_LIMIT||DEFAULTS.familyDailyLimit);return Number.isInteger(n)&&n>0&&n<=200?n:DEFAULTS.familyDailyLimit;}
export default {fetch(request,env,ctx){return handleRequest(request,env,fetch,ctx);}};
// Catalog is generated from the exact deployed learning material.
