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

const CATALOG = {
  "place-0": {
    "topic": "מבנה עשרוני",
    "prompt": "מה ערך הספרה 6 במספר 46,215?",
    "answer": "6000",
    "explain": "הספרה 6 נמצאת במקום האלפים: 6 × 1,000 = 6,000.",
    "options": null
  },
  "place-1": {
    "topic": "מבנה עשרוני",
    "prompt": "איזו ספרה נמצאת במקום המאות במספר 83,749?",
    "answer": "7",
    "explain": "מימין: 9 יחידות, 4 עשרות, 7 מאות, 3 אלפים ו־8 עשרות אלפים.",
    "options": null
  },
  "place-2": {
    "topic": "מבנה עשרוני",
    "prompt": "הרכיבי מספר: 20,000 + 300 + 8",
    "answer": "20308",
    "explain": "יש 2 עשרות אלפים, 0 אלפים, 3 מאות, 0 עשרות ו־8 יחידות.",
    "options": null
  },
  "place-3": {
    "topic": "מבנה עשרוני",
    "prompt": "איזה מספר גדול יותר?",
    "answer": "50,209",
    "explain": "משווים משמאל: בעשרות האלפים ובאלפים יש שוויון; במקום המאות, 2 גדול מ־0.",
    "options": [
      "50,029",
      "50,209"
    ]
  },
  "place-4": {
    "topic": "מבנה עשרוני",
    "prompt": "עגלי את 6,748 למאות הקרובות.",
    "answer": "6700",
    "explain": "ספרת העשרות היא 4, לכן מעגלים למטה ל־6,700.",
    "options": null
  },
  "place-5": {
    "topic": "מבנה עשרוני",
    "prompt": "כמה עשרות שלמות יש ב־350?",
    "answer": "35",
    "explain": "350 ÷ 10 = 35. שימי לב: ספרת העשרות היא 5, אבל במספר כולו יש 35 עשרות.",
    "options": null
  },
  "order-0": {
    "topic": "סדר פעולות חשבון",
    "prompt": "7 + 3 × 4 = ?",
    "answer": "19",
    "explain": "קודם כפל: 3 × 4 = 12. אחר כך 7 + 12 = 19.",
    "options": null
  },
  "order-1": {
    "topic": "סדר פעולות חשבון",
    "prompt": "(7 + 3) × 4 = ?",
    "answer": "40",
    "explain": "קודם סוגריים: 7 + 3 = 10. אחר כך 10 × 4 = 40.",
    "options": null
  },
  "order-2": {
    "topic": "סדר פעולות חשבון",
    "prompt": "24 ÷ 6 × 2 = ?",
    "answer": "8",
    "explain": "כפל וחילוק משמאל לימין: 24 ÷ 6 = 4, ואז 4 × 2 = 8.",
    "options": null
  },
  "order-3": {
    "topic": "סדר פעולות חשבון",
    "prompt": "20 − 8 + 3 = ?",
    "answer": "15",
    "explain": "חיבור וחיסור משמאל לימין: 20 − 8 = 12, ואז 12 + 3 = 15.",
    "options": null
  },
  "order-4": {
    "topic": "סדר פעולות חשבון",
    "prompt": "36 ÷ (3 + 3) + 2 = ?",
    "answer": "8",
    "explain": "בסוגריים 3 + 3 = 6. אחר כך 36 ÷ 6 = 6, ובסוף 6 + 2 = 8.",
    "options": null
  },
  "order-5": {
    "topic": "סדר פעולות חשבון",
    "prompt": "50 − 4 × (6 + 2) = ?",
    "answer": "18",
    "explain": "בסוגריים מקבלים 8. הכפל נותן 32. לבסוף 50 − 32 = 18.",
    "options": null
  },
  "whole-0": {
    "topic": "פעולות חשבון בשלמים",
    "prompt": "368 + 257 = ?",
    "answer": "625",
    "explain": "ביחידות: 8 + 7 = 15. בעשרות: 6 + 5 + 1 = 12. במאות: 3 + 2 + 1 = 6.",
    "options": null
  },
  "whole-1": {
    "topic": "פעולות חשבון בשלמים",
    "prompt": "502 − 278 = ?",
    "answer": "224",
    "explain": "אחרי ההמרה יש 4 מאות, 9 עשרות ו־12 יחידות. מחסרים ומקבלים 224.",
    "options": null
  },
  "whole-2": {
    "topic": "פעולות חשבון בשלמים",
    "prompt": "24 × 13 = ?",
    "answer": "312",
    "explain": "24 × 10 = 240, ו־24 × 3 = 72. מחברים: 240 + 72 = 312.",
    "options": null
  },
  "whole-3": {
    "topic": "פעולות חשבון בשלמים",
    "prompt": "168 ÷ 6 = ?",
    "answer": "28",
    "explain": "ב־16 יש פעמיים 6 ונשאר 4. מורידים 8, מקבלים 48, ו־48 ÷ 6 = 8. בדיקה: 28 × 6 = 168.",
    "options": null
  },
  "whole-4": {
    "topic": "פעולות חשבון בשלמים",
    "prompt": "מה השארית בחילוק 29 ב־4?",
    "answer": "1",
    "explain": "4 × 7 = 28, ונשאר 1. השארית 1 קטנה מהמחלק 4.",
    "options": null
  },
  "whole-5": {
    "topic": "פעולות חשבון בשלמים",
    "prompt": "איזו פעולה אסורה?",
    "answer": "חילוק ב־0",
    "explain": "אי אפשר לחלק ב־0. לעומת זאת 0 חלקי מספר שאינו 0 שווה 0.",
    "options": [
      "כפל ב־0",
      "חיבור 0",
      "חילוק ב־0",
      "חיסור 0"
    ]
  },
  "prime-0": {
    "topic": "מספר ראשוני או פריק?",
    "prompt": "איזה מהמספרים הבאים ראשוני?",
    "answer": "13",
    "explain": "ל־13 יש בדיוק שני מחלקים חיוביים: 1 ו־13. שאר האפשרויות פריקות.",
    "options": [
      "9",
      "13",
      "15",
      "21"
    ]
  },
  "prime-1": {
    "topic": "מספר ראשוני או פריק?",
    "prompt": "מה נכון לגבי המספר 1?",
    "answer": "לא ראשוני ולא פריק",
    "explain": "ל־1 יש רק מחלק חיובי אחד, ולכן הוא אינו עומד בהגדרה של מספר ראשוני או פריק.",
    "options": [
      "ראשוני",
      "פריק",
      "לא ראשוני ולא פריק"
    ]
  },
  "prime-2": {
    "topic": "מספר ראשוני או פריק?",
    "prompt": "כמה מחלקים חיוביים יש ל־12?",
    "answer": "6",
    "explain": "המחלקים הם 1, 2, 3, 4, 6, 12 — שישה מחלקים.",
    "options": null
  },
  "prime-3": {
    "topic": "מספר ראשוני או פריק?",
    "prompt": "איזה מספר זוגי הוא ראשוני?",
    "answer": "2",
    "explain": "2 מתחלק רק ב־1 ובעצמו. כל מספר זוגי גדול מ־2 מתחלק גם ב־2.",
    "options": null
  },
  "prime-4": {
    "topic": "מספר ראשוני או פריק?",
    "prompt": "מדוע 27 הוא מספר פריק?",
    "answer": "כי 27 = 3 × 9",
    "explain": "הפירוק 3 × 9 מראה שיש ל־27 מחלקים נוספים מלבד 1 ו־27.",
    "options": [
      "כי הוא אי־זוגי",
      "כי 27 = 3 × 9",
      "כי הוא גדול מ־10"
    ]
  },
  "prime-5": {
    "topic": "מספר ראשוני או פריק?",
    "prompt": "איזו מכפלה היא פירוק של 18 לגורמים ראשוניים?",
    "answer": "2 × 3 × 3",
    "explain": "2, 3 ו־3 הם מספרים ראשוניים, והמכפלה שלהם היא 18.",
    "options": [
      "2 × 9",
      "3 × 6",
      "2 × 3 × 3",
      "1 × 18"
    ]
  },
  "fractions-0": {
    "topic": "חיבור, חיסור וכפל בשברים",
    "prompt": "(2/9) + (4/9) = ?",
    "answer": "2/3",
    "explain": "מחברים מונים: 6/9. מצמצמים ב־3 ומקבלים 2/3. גם 6/9 היא תשובה נכונה.",
    "options": null
  },
  "fractions-1": {
    "topic": "חיבור, חיסור וכפל בשברים",
    "prompt": "(5/6) − (1/3) = ?",
    "answer": "1/2",
    "explain": "מרחיבים: 1/3 = 2/6. מחסרים 5/6 − 2/6 = 3/6 = 1/2.",
    "options": null
  },
  "fractions-2": {
    "topic": "חיבור, חיסור וכפל בשברים",
    "prompt": "(1/4) + (1/2) = ?",
    "answer": "3/4",
    "explain": "חצי הוא 2/4, ולכן 1/4 + 2/4 = 3/4.",
    "options": null
  },
  "fractions-3": {
    "topic": "חיבור, חיסור וכפל בשברים",
    "prompt": "(2/3) × (3/5) = ?",
    "answer": "2/5",
    "explain": "מונה כפול מונה ומכנה כפול מכנה: 6/15. מצמצמים ב־3 ומקבלים 2/5.",
    "options": null
  },
  "fractions-4": {
    "topic": "חיבור, חיסור וכפל בשברים",
    "prompt": "3 × (2/7) = ?",
    "answer": "6/7",
    "explain": "כותבים 3/1 ומכפילים: (3 × 2)/(1 × 7) = 6/7.",
    "options": null
  },
  "fractions-5": {
    "topic": "חיבור, חיסור וכפל בשברים",
    "prompt": "(3/4) + (2/3) = ?",
    "answer": "17/12",
    "explain": "המכנה המשותף הוא 12: 9/12 + 8/12 = 17/12, שהם 1 ו־5/12.",
    "options": null
  },
  "decimal-0": {
    "topic": "מכירות מספר עשרוני",
    "prompt": "מה ערך הספרה 7 במספר 4.72?",
    "answer": "0.7",
    "explain": "ה־7 נמצאת במקום העשיריות, ולכן ערכה שבע עשיריות: 0.7.",
    "options": null
  },
  "decimal-1": {
    "topic": "מכירות מספר עשרוני",
    "prompt": "כתבי במספר עשרוני: 9 מאיות.",
    "answer": "0.09",
    "explain": "מאיות הן המקום השני מימין לנקודה. כותבים 0 בעשיריות ו־9 במאיות.",
    "options": null
  },
  "decimal-2": {
    "topic": "מכירות מספר עשרוני",
    "prompt": "איזה מספר גדול יותר?",
    "answer": "0.8",
    "explain": "כותבים 0.8 = 0.80. שמונים מאיות גדולות משבעים וחמש מאיות.",
    "options": [
      "0.8",
      "0.75"
    ]
  },
  "decimal-3": {
    "topic": "מכירות מספר עשרוני",
    "prompt": "איזה מספר שווה ל־2.5?",
    "answer": "2.50",
    "explain": "אפס בסוף החלק העשרוני לא משנה את הערך.",
    "options": [
      "2.05",
      "2.50",
      "2.005",
      "25.0"
    ]
  },
  "decimal-4": {
    "topic": "מכירות מספר עשרוני",
    "prompt": "כתבי במספר עשרוני: 3 שלמים ו־6 מאיות.",
    "answer": "3.06",
    "explain": "3 שלמים, 0 עשיריות ו־6 מאיות הם 3.06.",
    "options": null
  },
  "decimal-5": {
    "topic": "מכירות מספר עשרוני",
    "prompt": "איזה מספר נמצא בין 0.4 ל־0.5?",
    "answer": "0.45",
    "explain": "0.45 גדול מ־0.40 וקטן מ־0.50.",
    "options": [
      "0.35",
      "0.45",
      "0.54",
      "0.04"
    ]
  },
  "decimal-ops-0": {
    "topic": "חיבור וחיסור עשרוני",
    "prompt": "3.4 + 2.15 = ?",
    "answer": "5.55",
    "explain": "מיישרים את הנקודה וכותבים 3.40 + 2.15 = 5.55.",
    "options": null
  },
  "decimal-ops-1": {
    "topic": "חיבור וחיסור עשרוני",
    "prompt": "7.2 − 3.85 = ?",
    "answer": "3.35",
    "explain": "כותבים 7.20 − 3.85. ממירים ופועלים בטורים. התוצאה 3.35.",
    "options": null
  },
  "decimal-ops-2": {
    "topic": "חיבור וחיסור עשרוני",
    "prompt": "0.68 + 0.57 = ?",
    "answer": "1.25",
    "explain": "8 + 7 מאיות הן 15 מאיות; 6 + 5 + 1 עשיריות הן 12 עשיריות. התוצאה 1.25.",
    "options": null
  },
  "decimal-ops-3": {
    "topic": "חיבור וחיסור עשרוני",
    "prompt": "10 − 4.76 = ?",
    "answer": "5.24",
    "explain": "כותבים 10.00 ומחסרים 4.76. בדיקה: 5.24 + 4.76 = 10.",
    "options": null
  },
  "decimal-ops-4": {
    "topic": "חיבור וחיסור עשרוני",
    "prompt": "מחברת עולה 8.50 ₪ ועט עולה 3.75 ₪. כמה עולים שניהם יחד?",
    "answer": "12.25",
    "explain": "8.50 + 3.75 = 12.25 שקלים.",
    "options": null
  },
  "decimal-ops-5": {
    "topic": "חיבור וחיסור עשרוני",
    "prompt": "היו לך 20 ₪ ושילמת 12.65 ₪. כמה עודף תקבלי?",
    "answer": "7.35",
    "explain": "20.00 − 12.65 = 7.35 שקלים.",
    "options": null
  },
  "triangles-0": {
    "topic": "סוגי משולשים",
    "prompt": "אורכי הצלעות הם 5, 5, 8 ס״מ. מהו התיאור המדויק לפי צלעות?",
    "answer": "שווה־שוקיים",
    "explain": "יש בדיוק שתי צלעות שוות, ולכן המשולש שווה־שוקיים.",
    "options": [
      "שווה־צלעות",
      "שווה־שוקיים",
      "שונה־צלעות"
    ]
  },
  "triangles-1": {
    "topic": "סוגי משולשים",
    "prompt": "הזוויות הן 30°, 60°, 90°. מהו הסוג לפי זוויות?",
    "answer": "ישר־זווית",
    "explain": "יש זווית אחת בת 90°, ולכן המשולש ישר־זווית.",
    "options": [
      "חד־זוויות",
      "ישר־זווית",
      "קהה־זווית"
    ]
  },
  "triangles-2": {
    "topic": "סוגי משולשים",
    "prompt": "במשולש שתי זוויות הן 50° ו־65°. מה גודל הזווית השלישית? כתבי מספר בלבד.",
    "answer": "65",
    "explain": "סכום הזוויות 180°. מחשבים 180 − 50 − 65 = 65.",
    "options": null
  },
  "triangles-3": {
    "topic": "סוגי משולשים",
    "prompt": "אורכי הצלעות הם 4, 4, 4 ס״מ. מהו התיאור המדויק ביותר?",
    "answer": "שווה־צלעות",
    "explain": "כל שלוש הצלעות שוות, לכן התיאור המדויק ביותר הוא שווה־צלעות.",
    "options": [
      "שווה־צלעות",
      "שונה־צלעות",
      "ישר־זווית"
    ]
  },
  "triangles-4": {
    "topic": "סוגי משולשים",
    "prompt": "הזוויות הן 110°, 40°, 30°. מהו הסוג לפי זוויות?",
    "answer": "קהה־זווית",
    "explain": "110° היא זווית קהה, גדולה מ־90°.",
    "options": [
      "חד־זוויות",
      "ישר־זווית",
      "קהה־זווית"
    ]
  },
  "triangles-5": {
    "topic": "סוגי משולשים",
    "prompt": "האם משולש יכול להיות גם שווה־שוקיים וגם ישר־זווית?",
    "answer": "כן",
    "explain": "למשל, זוויות 45°, 45°, 90° יוצרות משולש כזה.",
    "options": [
      "כן",
      "לא"
    ]
  },
  "area-0": {
    "topic": "שטח משולש ושטח מלבן",
    "prompt": "אורך מלבן 8 ס״מ ורוחבו 3 ס״מ. מה שטחו בסמ״ר?",
    "answer": "24",
    "explain": "שטח מלבן = אורך × רוחב = 8 × 3 = 24 סמ״ר.",
    "options": null
  },
  "area-1": {
    "topic": "שטח משולש ושטח מלבן",
    "prompt": "בסיס משולש 10 ס״מ והגובה אליו 4 ס״מ. מה שטחו בסמ״ר?",
    "answer": "20",
    "explain": "10 × 4 ÷ 2 = 20 סמ״ר.",
    "options": null
  },
  "area-2": {
    "topic": "שטח משולש ושטח מלבן",
    "prompt": "למשולש בסיס 6 ס״מ, גובה מתאים 4 ס״מ וצלע משופעת 5 ס״מ. מה שטחו בסמ״ר?",
    "answer": "12",
    "explain": "משתמשים בבסיס ובגובה המתאים: 6 × 4 ÷ 2 = 12. לא משתמשים ב־5.",
    "options": null
  },
  "area-3": {
    "topic": "שטח משולש ושטח מלבן",
    "prompt": "באיזו יחידה מודדים שטח?",
    "answer": "סמ״ר",
    "explain": "סמ״ר הוא סנטימטר רבוע — יחידת שטח. ס״מ מודד אורך.",
    "options": [
      "ס״מ",
      "סמ״ר",
      "מעלות"
    ]
  },
  "area-4": {
    "topic": "שטח משולש ושטח מלבן",
    "prompt": "שטח מלבן הוא 35 סמ״ר. אורכו 7 ס״מ. מה רוחבו בס״מ?",
    "answer": "5",
    "explain": "אורך × רוחב = שטח. לכן הרוחב הוא 35 ÷ 7 = 5 ס״מ.",
    "options": null
  },
  "area-5": {
    "topic": "שטח משולש ושטח מלבן",
    "prompt": "בסיס משולש 9 ס״מ והגובה אליו 6 ס״מ. מה שטחו בסמ״ר?",
    "answer": "27",
    "explain": "כופלים בסיס בגובה ומחלקים ב־2: 9 × 6 ÷ 2 = 27 סמ״ר.",
    "options": null
  },
  "quads-0": {
    "topic": "תכונות מרובעים",
    "prompt": "איזו תכונה נכונה לכל מלבן?",
    "answer": "ארבע זוויות ישרות",
    "explain": "לכל מלבן ארבע זוויות ישרות. הצלעות הנגדיות שוות, אבל לא חייב להיות שוויון בין כל הצלעות.",
    "options": [
      "כל הצלעות שוות",
      "ארבע זוויות ישרות",
      "בדיוק זוג אחד של צלעות מקבילות"
    ]
  },
  "quads-1": {
    "topic": "תכונות מרובעים",
    "prompt": "איזה משפט נכון?",
    "answer": "כל ריבוע הוא מלבן",
    "explain": "בריבוע יש ארבע זוויות ישרות, ולכן הוא מקיים את הגדרת המלבן.",
    "options": [
      "כל מלבן הוא ריבוע",
      "כל ריבוע הוא מלבן",
      "כל מקבילית היא ריבוע"
    ]
  },
  "quads-2": {
    "topic": "תכונות מרובעים",
    "prompt": "איזו תכונה חייבת להתקיים בכל מעוין?",
    "answer": "כל ארבע הצלעות שוות",
    "explain": "מעוין מוגדר על ידי ארבע צלעות שוות. הזוויות שלו אינן חייבות להיות ישרות.",
    "options": [
      "כל ארבע הצלעות שוות",
      "כל הזוויות ישרות",
      "כל האלכסונים שווים"
    ]
  },
  "quads-3": {
    "topic": "תכונות מרובעים",
    "prompt": "למרובע בדיוק זוג אחד של צלעות נגדיות מקבילות. מה שמו לפי ההגדרה במסלול?",
    "answer": "טרפז",
    "explain": "לפי ההגדרה כאן, לטרפז יש בדיוק זוג אחד של צלעות נגדיות מקבילות.",
    "options": [
      "מלבן",
      "מקבילית",
      "טרפז",
      "ריבוע"
    ]
  },
  "quads-4": {
    "topic": "תכונות מרובעים",
    "prompt": "במרובע שלוש זוויות הן 80°, 100°, 90°. מה גודל הרביעית? כתבי מספר בלבד.",
    "answer": "90",
    "explain": "סכום זוויות במרובע 360°. לכן 360 − 80 − 100 − 90 = 90.",
    "options": null
  },
  "quads-5": {
    "topic": "תכונות מרובעים",
    "prompt": "מה נכון לגבי האלכסונים של כל ריבוע?",
    "answer": "שווים, מאונכים וחוצים זה את זה",
    "explain": "ריבוע הוא גם מלבן וגם מעוין, ולכן מתקיימות בו כל שלוש התכונות.",
    "options": [
      "שווים בלבד",
      "מאונכים בלבד",
      "שווים, מאונכים וחוצים זה את זה"
    ]
  }
};
