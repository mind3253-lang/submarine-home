export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    async function saveMember(member) {
      const key = "system/members.json";
      let members = [];
      try { const o = await env.IMAGES.get(key); if (o) members = JSON.parse(await o.text()); } catch {}
      const now = new Date().toISOString();const banned=members.find(x=>(x.provider===member.provider&&x.id===member.id)||(member.phone&&x.phone===member.phone)||(member.email&&x.email&&x.email.toLowerCase()===member.email.toLowerCase()));if(banned?.status==="expelled")throw new Error("강퇴된 회원입니다.");
      let i = members.findIndex(x => x.provider === member.provider && x.id === member.id);
      if (i < 0 && member.phone) i = members.findIndex(x => x.phone && x.phone === member.phone);
      if (i < 0 && member.email) i = members.findIndex(x => x.email && x.email.toLowerCase() === member.email.toLowerCase());
      if (i >= 0) {
        const old = members[i], providers = Array.from(new Set([...(old.providers||[old.provider]).filter(Boolean),member.provider]));
        members[i] = {...old,...member,provider:old.provider||member.provider,providers,lastLoginAt:now};
        await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
        return members[i];
      }
      const saved={...member,providers:[member.provider],memberNo:"U"+String(members.length+1).padStart(5,"0"),joinedAt:now,lastLoginAt:now,cash:0,point:5000};
      members.push(saved);
      await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
      return saved;
    }
    async function makeSession(member) {
      const payload=btoa(unescape(encodeURIComponent(JSON.stringify(member)))).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
      const sessionKey=String(env.NAVER_CLIENT_SECRET||env.KAKAO_REST_API_KEY);
      const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(sessionKey),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
      const sigBytes=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(payload)));
      const sig=btoa(String.fromCharCode(...sigBytes)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
      return "submarine_session="+payload+"."+sig+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000";
    }
    async function hashPassword(password,salt){
      const data=new TextEncoder().encode(salt+"|"+password);
      const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",data));
      return Array.from(digest,b=>b.toString(16).padStart(2,"0")).join("");
    }
    async function adminConfig(){
      try{const o=await env.IMAGES.get("system/admin-auth.json");if(o){const cfg=JSON.parse(await o.text());if(cfg?.salt&&cfg?.passwordHash)return cfg}}catch{}
      return null;
    }
    async function adminSessionValid(){
      try{const cookie=request.headers.get("Cookie")||"",token=(cookie.match(/(?:^|;\\s*)submarine_admin=([^;]+)/)||[])[1];if(!token)return false;const o=await env.IMAGES.get("system/admin-sessions/"+token+".json");if(!o)return false;const s=JSON.parse(await o.text());if(!s.expiresAt||Date.now()>s.expiresAt){await env.IMAGES.delete("system/admin-sessions/"+token+".json");return false}return true}catch{return false}
    }
    async function requireAdmin(){return await adminSessionValid()?null:Response.json({ok:false,error:"관리자 로그인이 필요합니다."},{status:401})}
    if (url.pathname === "/api/auth/local/register" && request.method === "POST") {
      try {
        const d=await request.json(),name=String(d.name||"").trim(),phone=String(d.phone||"").replace(/[^0-9]/g,""),password=String(d.password||""),licenses=Array.isArray(d.licenses)?d.licenses:[];
        if(!name||phone.length<10||password.length<6)return Response.json({ok:false,error:"이름, 휴대폰번호, 비밀번호 6자 이상을 입력해 주세요."},{status:400});
        if(!d.licenseConfirmed)return Response.json({ok:false,error:"자격증 정보를 확인해 주세요."},{status:400});
        const key="system/members.json";let members=[];try{const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text())}catch{}
        let m=members.find(x=>String(x.phone||"").replace(/[^0-9]/g,"")===phone);
        if(m&&(m.identities||[]).some(x=>x.provider==="local"))return Response.json({ok:false,error:"이미 일반회원으로 가입된 휴대폰번호입니다."},{status:409});
        const salt=crypto.randomUUID(),passwordHash=await hashPassword(password,salt),now=new Date().toISOString();
        if(m){m.identities=[...(m.identities||[]),{provider:"local",id:phone}];m.localSalt=salt;m.localPasswordHash=passwordHash;m.name=m.name||name;m.licenses=licenses;m.profileCompleted=true;}
        else{m={provider:"local",id:phone,identities:[{provider:"local",id:phone}],providers:["local"],memberNo:"U"+String(members.length+1).padStart(5,"0"),name,phone,email:"",joinedAt:now,lastLoginAt:now,cash:0,point:5000,licenses,profileCompleted:true,localSalt:salt,localPasswordHash:passwordHash};members.push(m)}
        await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
        const safe={provider:"local",id:phone,memberNo:m.memberNo,name:m.name,phone:m.phone,profileCompleted:!!m.profileCompleted};
        return Response.json({ok:true},{headers:{"Set-Cookie":await makeSession(safe)}});
      }catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/auth/local/login" && request.method === "POST") {
      try {
        const d=await request.json(),phone=String(d.phone||"").replace(/[^0-9]/g,""),password=String(d.password||"");
        const o=await env.IMAGES.get("system/members.json"),members=o?JSON.parse(await o.text()):[],m=members.find(x=>String(x.phone||"").replace(/[^0-9]/g,"")===phone&&(x.identities||[]).some(v=>v.provider==="local"));
        if(!m||!m.localSalt||await hashPassword(password,m.localSalt)!==m.localPasswordHash)return Response.json({ok:false,error:"휴대폰번호 또는 비밀번호를 확인해 주세요."},{status:401});
        m.lastLoginAt=new Date().toISOString();await env.IMAGES.put("system/members.json",JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
        const safe={provider:"local",id:phone,memberNo:m.memberNo,name:m.name,phone:m.phone,profileCompleted:!!m.profileCompleted};
        return Response.json({ok:true},{headers:{"Set-Cookie":await makeSession(safe)}});
      }catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/auth/naver" && request.method === "GET") {
      if (!env.NAVER_CLIENT_ID || !env.NAVER_CLIENT_SECRET) return new Response("NAVER OAuth 환경변수가 없습니다.", { status: 503 });
      const state = crypto.randomUUID().replaceAll("-", "");
      const redirectUri = "https://submarine.asia/api/auth/naver/callback";
      const q = new URLSearchParams({ response_type: "code", client_id: env.NAVER_CLIENT_ID, redirect_uri: redirectUri, state });
      return new Response(null, { status: 302, headers: {
        Location: "https://nid.naver.com/oauth2.0/authorize?" + q.toString(),
        "Set-Cookie": "naver_oauth_state=" + state + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"
      }});
    }

    if (url.pathname === "/api/auth/naver/callback" && request.method === "GET") {
      try {
        const code = url.searchParams.get("code"), state = url.searchParams.get("state");
        const cookie = request.headers.get("Cookie") || "";
        const savedState = (cookie.match(/(?:^|;\s*)naver_oauth_state=([^;]+)/) || [])[1];
        if (!code || !state || !savedState || state !== savedState) return new Response("네이버 로그인 상태값이 일치하지 않습니다.", { status: 400 });
        const tq = new URLSearchParams({ grant_type:"authorization_code", client_id:env.NAVER_CLIENT_ID, client_secret:env.NAVER_CLIENT_SECRET, code, state });
        const tr = await fetch("https://nid.naver.com/oauth2.0/token?" + tq.toString());
        const token = await tr.json();
        if (!tr.ok || !token.access_token) throw new Error(token.error_description || token.error || "토큰 발급 실패");
        const pr = await fetch("https://openapi.naver.com/v1/nid/me", { headers:{ Authorization:"Bearer " + token.access_token }});
        const profile = await pr.json();
        if (!pr.ok || profile.resultcode !== "00" || !profile.response?.id) throw new Error(profile.message || "프로필 조회 실패");
        const member = { provider:"naver", id:profile.response.id, name:profile.response.name || profile.response.nickname || "네이버 회원", email:profile.response.email || "", phone:profile.response.mobile || "" };
        await saveMember(member);
        const payload = btoa(unescape(encodeURIComponent(JSON.stringify(member)))).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
        const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.NAVER_CLIENT_SECRET), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
        const sigBytes = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
        const sig = btoa(String.fromCharCode(...sigBytes)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
        return new Response(null, { status:302, headers:{
          Location:"https://submarine.asia/",
          "Set-Cookie":"submarine_session=" + payload + "." + sig + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"
        }});
      } catch(e) {
        return new Response("네이버 로그인 처리 실패: " + (e?.message || String(e)), { status:500 });
      }
    }

    if (url.pathname === "/api/auth/kakao" && request.method === "GET") {
      if (!env.KAKAO_REST_API_KEY) return new Response("KAKAO OAuth 환경변수가 없습니다.", { status: 503 });
      const state = crypto.randomUUID().replaceAll("-", "");
      const redirectUri = "https://submarine.asia/api/auth/kakao/callback";
      const q = new URLSearchParams({ response_type:"code", client_id:env.KAKAO_REST_API_KEY, redirect_uri:redirectUri, state });
      return new Response(null, { status:302, headers:{
        Location:"https://kauth.kakao.com/oauth/authorize?" + q.toString(),
        "Set-Cookie":"kakao_oauth_state=" + state + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"
      }});
    }

    if (url.pathname === "/api/auth/kakao/callback" && request.method === "GET") {
      try {
        const code=url.searchParams.get("code"), state=url.searchParams.get("state");
        if(!code||!state) return new Response("카카오 로그인 인증값이 없습니다.",{status:400});
        const body=new URLSearchParams({grant_type:"authorization_code",client_id:env.KAKAO_REST_API_KEY,redirect_uri:"https://submarine.asia/api/auth/kakao/callback",code});
        const tr=await fetch("https://kauth.kakao.com/oauth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded;charset=utf-8"},body});
        const token=await tr.json();
        if(!tr.ok||!token.access_token) throw new Error(token.error_description||token.error||"토큰 발급 실패");
        const pr=await fetch("https://kapi.kakao.com/v2/user/me",{headers:{Authorization:"Bearer "+token.access_token}});
        const profile=await pr.json();
        if(!pr.ok||!profile.id) throw new Error(profile.msg||"프로필 조회 실패");
        const account=profile.kakao_account||{}, p=account.profile||{};
        const member={provider:"kakao",id:String(profile.id),name:account.name||p.nickname||"카카오 회원",email:account.email||"",phone:account.phone_number||""};
        await saveMember(member);
        const payload=btoa(unescape(encodeURIComponent(JSON.stringify(member)))).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
        const sessionKey=String(env.NAVER_CLIENT_SECRET||env.KAKAO_REST_API_KEY);
        const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(sessionKey),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
        const sigBytes=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(payload)));
        const sig=btoa(String.fromCharCode(...sigBytes)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
        return new Response(null,{status:302,headers:{Location:"https://submarine.asia/","Set-Cookie":"submarine_session="+payload+"."+sig+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"}});
      } catch(e) {
        return new Response("카카오 로그인 처리 실패: "+(e?.message||String(e)),{status:500});
      }
    }

    if (url.pathname === "/api/admin/instructor-accounting" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),instructors=Array.isArray(d.instructors)?d.instructors:[],settlements=Array.isArray(d.settlements)?d.settlements:[],closings=Array.isArray(d.closings)?d.closings:[];await Promise.all([env.IMAGES.put("system/instructors.json",JSON.stringify(instructors),{httpMetadata:{contentType:"application/json"}}),env.IMAGES.put("system/instructor-settlements.json",JSON.stringify(settlements),{httpMetadata:{contentType:"application/json"}}),env.IMAGES.put("system/instructor-closings.json",JSON.stringify(closings),{httpMetadata:{contentType:"application/json"}})]);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/instructor-accounting" && request.method === "GET") {const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});try{const [io,so,co]=await Promise.all([env.IMAGES.get("system/instructors.json"),env.IMAGES.get("system/instructor-settlements.json"),env.IMAGES.get("system/instructor-closings.json")]),instructors=io?JSON.parse(await io.text()):[],settlements=so?JSON.parse(await so.text()):[],closings=co?JSON.parse(await co.text()):[],no=String(member.memberNo||""),inst=instructors.find(x=>String(x.memberNo||"")===no),iid=inst?String(inst.id):"";return Response.json({ok:true,isInstructor:!!inst,settlements:settlements.filter(x=>String(x.memberNo||"")===no||(iid&&String(x.instructorId)===iid)),closings:closings.filter(x=>String(x.memberNo||"")===no||(iid&&String(x.instructorId)===iid))})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/analytics/track"&&request.method==="POST"){try{const d=await request.json(),now=new Date(),day=now.toISOString().slice(0,10),cf=request.cf||{},ref=String(d.referrer||""),utm=String(d.utm_source||"").toLowerCase();let source=utm||"직접접속";if(!utm&&ref){try{const h=new URL(ref).hostname.toLowerCase();source=h.includes("naver")?"네이버":h.includes("google")?"구글":h.includes("instagram")?"인스타그램":h.includes("youtube")?"유튜브":h.includes("kakao")?"카카오":h.includes("submarine.asia")?"내부이동":h}catch{}}const raw=(request.headers.get("CF-Connecting-IP")||"")+"|"+(request.headers.get("User-Agent")||"")+"|"+day,visitor=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(raw)))).map(b=>b.toString(16).padStart(2,"0")).join("").slice(0,24),key="analytics/"+day+".json";let rows=[];try{const o=await env.IMAGES.get(key);if(o)rows=JSON.parse(await o.text())}catch{}let route=source;if(ref){try{const u=new URL(ref),h=u.hostname.toLowerCase(),kw=u.searchParams.get("query")||u.searchParams.get("q")||"";if(h.includes("place.naver")||h.includes("map.naver"))route="네이버 플레이스"+(kw?" · "+kw:"");else if(h.includes("naver"))route="네이버 검색"+(kw?" · "+kw:" · 검색어 확인불가");else if(h.includes("google"))route="구글 검색"+(kw?" · "+kw:" · 검색어 확인불가");else if(h.includes("instagram"))route="인스타그램";else if(h.includes("youtube"))route="유튜브";else if(h.includes("kakao"))route="카카오톡"}catch{}}if(utm)route=utm;rows.push({t:now.toISOString(),visitor,sid:String(d.sid||""),page:String(d.page||"/"),source,route,region:String(cf.region||""),city:String(cf.city||""),country:String(cf.country||""),event:"pageview"});await env.IMAGES.put(key,JSON.stringify(rows.slice(-20000)),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true})}catch{return Response.json({ok:false},{status:400})}}
    if(url.pathname==="/api/admin/analytics"&&request.method==="GET"){const denied=await requireAdmin();if(denied)return denied;try{
      const RESET_AT=Date.parse("2026-09-30T00:00:00+09:00");if(Date.now()<RESET_AT+24*60*60*1000)return Response.json({ok:true,source:"reset",summary:{visitors:0,requests:0,pageviews:0,registrations:0,reservations:0},daily:[],sources:[],regions:[],cities:[],countries:[]});
      const days=Math.min(365,Math.max(7,Number(url.searchParams.get("days"))||7)),now=new Date(),analyticsStart=new Date("2026-09-30T00:00:00+09:00"),requestedSince=new Date(now.getTime()-(days-1)*86400000),since=requestedSince<analyticsStart?analyticsStart:requestedSince,date_geq=since.toISOString().slice(0,10),date_leq=now.toISOString().slice(0,10),zoneTag=String(env.CLOUDFLARE_ZONE_ID||""),token=String(env.CLOUDFLARE_ANALYTICS_TOKEN||"");
      if(!zoneTag||!token)return Response.json({ok:false,error:"Cloudflare Analytics 연결정보가 없습니다."},{status:503});
      const query=`query($zoneTag:String!,$date_geq:Date!,$date_leq:Date!){viewer{zones(filter:{zoneTag:$zoneTag}){httpRequests1dGroups(limit:366,orderBy:[date_ASC],filter:{date_geq:$date_geq,date_leq:$date_leq}){dimensions{date}sum{requests pageViews}uniq{uniques}} httpRequestsAdaptiveGroups(limit:5000,filter:{datetime_geq:"${since.toISOString()}",datetime_leq:"${now.toISOString()}"},orderBy:[count_DESC]){count dimensions{clientCountryName clientRequestHTTPHost}}}}}`;
      const cr=await fetch("https://api.cloudflare.com/client/v4/graphql",{method:"POST",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({query,variables:{zoneTag,date_geq,date_leq}})}),cj=await cr.json();
      if(!cr.ok||cj.errors?.length)return Response.json({ok:false,error:cj.errors?.[0]?.message||"Cloudflare Analytics API 오류"},{status:502});
      const z=cj.data?.viewer?.zones?.[0]||{},dailyRaw=z.httpRequests1dGroups||[],dailyMap=Object.fromEntries(dailyRaw.map(x=>[x.dimensions?.date,{count:Number(x.uniq?.uniques||0),pageviews:Number(x.sum?.pageViews||0),requests:Number(x.sum?.requests||0)}])),daily=[];
      for(let n=0;n<days;n++){const d=new Date(since.getTime()+n*86400000).toISOString().slice(0,10),v=dailyMap[d]||{};daily.push({date:d,count:v.count||0})}
      const visitors=dailyRaw.reduce((a,x)=>a+Number(x.uniq?.uniques||0),0),pageviews=dailyRaw.reduce((a,x)=>a+Number(x.sum?.pageViews||0),0),requests=dailyRaw.reduce((a,x)=>a+Number(x.sum?.requests||0),0);
      const sourceMap={},countryMap={};for(const x of z.httpRequestsAdaptiveGroups||[]){const n=Number(x.count)||0,h=String(x.dimensions?.clientRequestHTTPHost||"").toLowerCase(),country=String(x.dimensions?.clientCountryName||"기타");let source=!h?"직접접속":h.includes("naver")?"네이버":h.includes("google")?"구글":h.includes("instagram")?"인스타그램":h.includes("youtube")?"유튜브":h.includes("kakao")?"카카오":h.includes("submarine.asia")?"내부이동":h;if(source!=="내부이동")sourceMap[source]=(sourceMap[source]||0)+n;countryMap[country]=(countryMap[country]||0)+n}
      const rank=o=>Object.entries(o).map(([name,count])=>({name,count})).sort((a,b)=>b.count-a.count);
      let registrations=0,reservations=0;const start=since.getTime(),finish=now.getTime();try{const o=await env.IMAGES.get("system/members.json"),x=o?JSON.parse(await o.text()):[];registrations=x.filter(v=>{const t=new Date(v.joinedAt||v.createdAt||0).getTime();return t>=start&&t<=finish}).length}catch{}try{const o=await env.IMAGES.get("system/reservations.json"),x=o?JSON.parse(await o.text()):[];reservations=x.filter(v=>{const t=new Date(v.createdAt||0).getTime();return t>=start&&t<=finish&&v.status!=="cancelled"}).length}catch{}
      let geo=[];const dates=[];for(let n=days-1;n>=0;n--){const d=new Date();d.setUTCDate(d.getUTCDate()-n);dates.push(d.toISOString().slice(0,10))}const local=[];await Promise.all(dates.map(async day=>{try{const o=await env.IMAGES.get("analytics/"+day+".json");if(o)local.push(...JSON.parse(await o.text()))}catch{}}));const gm={};for(const x of local){if(String(x.country||"").toUpperCase()!=="KR")continue;const city=String(x.city||"").toLowerCase(),region=String(x.region||"").toLowerCase();let k="";if(city.includes("bucheon"))k="부천시";else if(city.includes("incheon"))k="인천시";else if(city.includes("gwangmyeong"))k="광명시";else if(city.includes("anyang"))k="안양시";else if(city.includes("gimpo"))k="김포시";else if(city.includes("goyang"))k="고양시";else if(city.includes("siheung"))k="시흥시";else if(region.includes("seoul")||city.includes("seoul")){const n=city.replace(/[^a-z]/g,"");if(/jongno|junggu|yongsan/.test(n))k="서울 도심권";else if(/seongdong|gwangjin|dongdaemun|jungnang|seongbuk|gangbuk|dobong|nowon/.test(n))k="서울 동북권";else if(/eunpyeong|seodaemun|mapo/.test(n))k="서울 서북권";else if(/yangcheon|gangseo|guro|geumcheon|yeongdeungpo|dongjak|gwanak/.test(n))k="서울 서남권";else if(/seocho|gangnam|songpa|gangdong/.test(n))k="서울 동남권"}else if(region.includes("gyeonggi"))k="그 외 지역";if(k)gm[k]=(gm[k]||0)+1}geo=rank(gm);const rv={};for(const x of local){const k=String(x.route||x.source||"직접접속"),v=String(x.visitor||x.sid||"");if(!rv[k])rv[k]=new Set();if(v)rv[k].add(v)}const routes=Object.entries(rv).map(([name,set])=>({name,count:set.size})).sort((a,b)=>b.count-a.count).slice(0,10);
      return Response.json({ok:true,source:"cloudflare",summary:{visitors,requests,pageviews,registrations,reservations},daily,sources:routes,regions:geo,cities:geo,countries:rank(countryMap)});
    }catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}


    if (url.pathname === "/api/admin/naver-keywords" && request.method === "GET") {
      const denied=await requireAdmin();if(denied)return denied;
      try{
        const secret=String(env.NAVER_AD_SECRET_KEY||"").trim();
        if(!secret) return Response.json({ok:false,error:"NAVER_AD_SECRET_KEY 환경변수가 없습니다."},{status:503});
        const hint=String(url.searchParams.get("q")||"프리다이빙").trim().slice(0,100);
        if(!hint) return Response.json({ok:false,error:"검색어를 입력해 주세요."},{status:400});
        const uri="/keywordstool",method="GET",timestamp=Date.now().toString();
        const msg=timestamp+"."+method+"."+uri;
        const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
        const sigBytes=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(msg)));
        const signature=btoa(String.fromCharCode(...sigBytes));
        const apiUrl="https://api.searchad.naver.com"+uri+"?hintKeywords="+encodeURIComponent(hint)+"&showDetail=1";
        const nr=await fetch(apiUrl,{headers:{"Content-Type":"application/json; charset=UTF-8","X-Timestamp":timestamp,"X-API-KEY":"0100000000d845c1eb8416c6305eaec3188fb8d0b2105ee185fb05862b9af7f683d7dcb853","X-Customer":"4435245","X-Signature":signature}});
        const raw=await nr.text();let data;try{data=JSON.parse(raw)}catch{data={message:raw}}
        if(!nr.ok) return Response.json({ok:false,error:data.detail||data.message||("네이버 API 오류 "+nr.status),status:nr.status},{status:502});
        const rows=Array.isArray(data.keywordList)?data.keywordList:[];
        return Response.json({ok:true,query:hint,keywords:rows.map(x=>({keyword:x.relKeyword||"",pc:x.monthlyPcQcCnt??0,mobile:x.monthlyMobileQcCnt??0,pcClick:x.monthlyAvePcClkCnt??0,mobileClick:x.monthlyAveMobileClkCnt??0,pcCtr:x.monthlyAvePcCtr??0,mobileCtr:x.monthlyAveMobileCtr??0,competition:x.compIdx||"",adDepth:x.plAvgDepth??0}))});
      }catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      try {
        const member=await sessionMember();
        if(!member) return Response.json({ok:false},{status:401});
        let stored=null;try{const o=await env.IMAGES.get("system/members.json");const ms=o?JSON.parse(await o.text()):[];stored=ms.find(x=>(member.memberNo&&x.memberNo===member.memberNo)||(x.provider===member.provider&&x.id===member.id)||(member.phone&&String(x.phone||"").replace(/[^0-9]/g,"")===String(member.phone||"").replace(/[^0-9]/g,"")))||null}catch{}
        return Response.json({ok:true,member:stored||member});
      } catch { return Response.json({ok:false},{status:401}); }
    }

    if (url.pathname === "/api/member/profile" && request.method === "POST") {
      try {
        const member=await sessionMember();
        if(!member) return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
        const data=await request.json(), licenses=Array.isArray(data.licenses)?data.licenses:[];
        if(!licenses.length) return Response.json({ok:false,error:"보유 자격증을 하나 이상 등록해 주세요."},{status:400});
        const key="system/members.json"; let members=[];
        try{const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text())}catch{}
        let i=members.findIndex(x=>(x.provider===member.provider&&x.id===member.id)||(member.phone&&x.phone===member.phone));
        if(i<0) return Response.json({ok:false,error:"회원 정보를 찾을 수 없습니다."},{status:404});
        members[i]={...members[i],licenses,profileCompleted:true,profileUpdatedAt:new Date().toISOString()};
        await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true,member:members[i]});
      } catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      return Response.json({ok:true},{headers:{"Set-Cookie":"submarine_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}});
    }

    if (url.pathname === "/api/popup" && request.method === "GET") {try{const o=await env.IMAGES.get("system/popup.json");return Response.json({ok:true,popup:o?JSON.parse(await o.text()):{enabled:false}})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin/popup" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),popup={enabled:!!d.enabled,title:String(d.title||""),image:String(d.image||""),link:String(d.link||"")};await env.IMAGES.put("system/popup.json",JSON.stringify(popup),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true,popup})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if (url.pathname === "/api/brand-assets" && request.method === "GET") {
      try{const o=await env.IMAGES.get("system/brand-assets.json");return Response.json({ok:true,assets:o?JSON.parse(await o.text()):{}})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/admin/brand-assets" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try{const d=await request.json(),assets={hero:String(d.hero||""),headerLogo:String(d.headerLogo||""),wordmark:String(d.wordmark||"")};await env.IMAGES.put("system/brand-assets.json",JSON.stringify(assets),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true,assets})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    async function readSiteContent(){try{const o=await env.IMAGES.get("system/site-content.json");return o?JSON.parse(await o.text()):{}}catch{return {}}}
    if (url.pathname === "/api/site-content" && request.method === "GET") {return Response.json({ok:true,content:await readSiteContent()})}
    if (url.pathname === "/api/admin/site-content" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),content=d.content&&typeof d.content==="object"?d.content:{};await env.IMAGES.put("system/site-content.json",JSON.stringify(content),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin/members" && request.method === "GET") {
      const denied=await requireAdmin(); if(denied)return denied;
      try {
        const o = await env.IMAGES.get("system/members.json");
        const members = o ? JSON.parse(await o.text()) : [];
        return Response.json({ok:true,members});
      } catch(e) {
        return Response.json({ok:false,error:e?.message||String(e)},{status:500});
      }
    }

    if (url.pathname === "/api/admin/member-expel" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),memberNo=String(d.memberNo||""),key="system/members.json";const o=await env.IMAGES.get(key),members=o?JSON.parse(await o.text()):[],i=members.findIndex(x=>x.memberNo===memberNo);if(i<0)return Response.json({ok:false,error:"회원을 찾을 수 없습니다."},{status:404});members[i].status="expelled";members[i].expelledAt=new Date().toISOString();await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    async function readReservations(){try{const o=await env.IMAGES.get("system/reservations.json");return o?JSON.parse(await o.text()):[]}catch{return []}}
    async function writeReservations(rows){await env.IMAGES.put("system/reservations.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    if (url.pathname === "/api/reservations" && request.method === "GET") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      const rows=await readReservations();return Response.json({ok:true,reservations:rows.filter(x=>x.memberNo===member.memberNo)});
    }
    if (url.pathname === "/api/reservations/public" && request.method === "GET") {const rows=await readReservations();return Response.json({ok:true,reservations:rows.filter(x=>x.status!=="cancelled").map(x=>({date:x.date,time:x.time,type:x.type,people:x.people,status:x.status||"confirmed"}))})}
    if (url.pathname === "/api/admin/reservations" && request.method === "GET") {if(!await adminSessionValid())return Response.json({ok:false,error:"관리자 로그인이 필요합니다."},{status:401});const rows=await readReservations();return Response.json({ok:true,reservations:rows.filter(x=>x.status!=="cancelled")})}
    if (url.pathname === "/api/admin/reservations/edit" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readReservations(),i=rows.findIndex(x=>x.id===d.id);if(i<0)return Response.json({ok:false,error:"예약을 찾을 수 없습니다."},{status:404});if(d.date)rows[i].date=String(d.date);if(d.time)rows[i].time=String(d.time);if(d.type&&["강습","스킬업","펀다","독립군"].includes(d.type))rows[i].type=d.type;if(d.people!=null){const people=Math.max(0,Math.floor(Number(d.people)||0));if(people===0){const removed=rows[i];rows.splice(i,1);await writeReservations(rows);return Response.json({ok:true,deleted:true,reservation:removed})}rows[i].people=people}rows[i].adminEditedAt=new Date().toISOString();await writeReservations(rows);return Response.json({ok:true,reservation:rows[i]})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin/reservations/add" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),people=Math.max(1,Math.floor(Number(d.people)||1));if(!d.date||!d.time||!["강습","스킬업","펀다","독립군"].includes(d.type))return Response.json({ok:false,error:"예약 정보를 확인해 주세요."},{status:400});const rows=await readReservations(),row={id:crypto.randomUUID(),memberNo:"ADMIN",name:String(d.name||"관리자입력"),date:String(d.date),time:String(d.time),type:d.type,people,status:"confirmed",adminManual:true,createdAt:new Date().toISOString()};rows.push(row);await writeReservations(rows);return Response.json({ok:true,reservation:row})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if (url.pathname === "/api/reservations" && request.method === "POST") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{const d=await request.json(),people=Math.max(1,Math.floor(Number(d.people)||1));if(!d.date||!d.time||!["강습","스킬업","펀다","독립군"].includes(d.type))return Response.json({ok:false,error:"예약 정보를 확인해 주세요."},{status:400});
        const mk="system/members.json",mo=await env.IMAGES.get(mk),members=mo?JSON.parse(await mo.text()):[],mi=members.findIndex(x=>(member.memberNo&&x.memberNo===member.memberNo)||(x.provider===member.provider&&x.id===member.id)||(member.phone&&String(x.phone||"").replace(/[^0-9]/g,"")===String(member.phone||"").replace(/[^0-9]/g,"")));
        if(mi<0)return Response.json({ok:false,error:"회원 정보를 찾을 수 없습니다."},{status:404});
        const useDate=new Date(String(d.date)+"T00:00:00"),weekend=useDate.getDay()===0||useDate.getDay()===6,holiday=["2026-01-01","2026-02-16","2026-02-17","2026-02-18","2026-03-01","2026-03-02","2026-05-05","2026-05-24","2026-05-25","2026-06-03","2026-06-06","2026-08-15","2026-08-17","2026-09-24","2026-09-25","2026-09-26","2026-10-03","2026-10-05","2026-10-09","2026-12-25"].includes(String(d.date)),unit=weekend||holiday?55000:40000,cost=unit*people,point=Number(members[mi].point||0),cash=Number(members[mi].cash||0);
        if(point+cash<cost)return Response.json({ok:false,error:"마일리지가 부족합니다.",balance:point+cash,required:cost},{status:400});
        const usePoint=Math.min(point,cost),useCash=cost-usePoint;members[mi].point=point-usePoint;members[mi].cash=cash-useCash;members[mi].balanceUpdatedAt=new Date().toISOString();
        const rows=await readReservations(),row={id:crypto.randomUUID(),memberNo:members[mi].memberNo,name:members[mi].name||member.name||"회원",date:d.date,time:d.time,type:d.type,people,cost,usePoint,useCash,status:"confirmed",createdAt:new Date().toISOString()};
        rows.push(row);await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});try{await writeReservations(rows)}catch(e){members[mi].point=point;members[mi].cash=cash;await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});throw e}return Response.json({ok:true,reservation:row,balance:members[mi].point+members[mi].cash})
      }catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    async function readRequests(){try{const o=await env.IMAGES.get("system/service-requests.json");return o?JSON.parse(await o.text()):[]}catch{return []}}
    async function writeRequests(rows){await env.IMAGES.put("system/service-requests.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    if (url.pathname === "/api/reservations/cancel" && request.method === "POST") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{const d=await request.json(),reservations=await readReservations(),booking=reservations.find(x=>x.id===d.id&&x.memberNo===member.memberNo);if(!booking)return Response.json({ok:false,error:"예약을 찾을 수 없습니다."},{status:404});const requests=await readRequests();if(requests.some(x=>x.kind==="reservation_cancel"&&x.reservationId===booking.id&&x.status==="requested"))return Response.json({ok:false,error:"이미 취소 접수된 예약입니다."},{status:409});requests.unshift({id:crypto.randomUUID(),kind:"reservation_cancel",status:"requested",reservationId:booking.id,memberNo:member.memberNo,name:booking.name||member.name||"회원",date:booking.date,time:booking.time,type:booking.type,people:booking.people,cost:booking.cost||0,submittedAt:new Date().toISOString()});await writeRequests(requests);return Response.json({ok:true,requested:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/admin/service-requests" && request.method === "GET") {const denied=await requireAdmin();if(denied)return denied;return Response.json({ok:true,requests:await readRequests()})}
    if (url.pathname === "/api/admin/service-requests/complete" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readRequests(),i=rows.findIndex(x=>x.id===d.id);if(i<0)return Response.json({ok:false,error:"접수내역을 찾을 수 없습니다."},{status:404});rows[i].status="completed";rows[i].completedAt=new Date().toISOString();await writeRequests(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/refund-request" && request.method === "POST") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{const d=await request.json(),key="system/refund-requests.json";let rows=[];try{const o=await env.IMAGES.get(key);if(o)rows=JSON.parse(await o.text())}catch{}const req={id:crypto.randomUUID(),memberNo:member.memberNo,name:member.name||"회원",program:String(d.program||"교육 프로그램"),type:"education",status:"requested",submittedAt:new Date().toISOString(),termsAcknowledged:true};rows.push(req);await env.IMAGES.put(key,JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}});const requests=await readRequests();requests.unshift({id:req.id,kind:"education_refund",status:"requested",memberNo:req.memberNo,name:req.name,program:req.program,submittedAt:req.submittedAt});await writeRequests(requests);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    async function readPayments(){try{const o=await env.IMAGES.get("system/payments.json");return o?JSON.parse(await o.text()):[]}catch{return []}}
    async function writePayments(rows){await env.IMAGES.put("system/payments.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    if (url.pathname === "/api/payments" && request.method === "POST") {const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});try{const d=await request.json(),amount=Math.max(0,Number(d.amount)||0);if(!d.product||!amount)return Response.json({ok:false,error:"상품과 금액을 확인해 주세요."},{status:400});const quantity=Math.max(1,Math.floor(Number(d.quantity)||1)),unitAmount=Math.max(0,Number(d.unitAmount)||0),products=await readA3Products(),product=products.find(x=>String(x.title||"")===String(d.product||"")),rewardRate=Math.max(0,Number(product?.rate)||0),rewardPoint=Math.round(amount*rewardRate/100),rows=await readPayments(),row={id:crypto.randomUUID(),memberNo:member.memberNo,name:member.name||"회원",phone:member.phone||"",product:String(d.product),quantity,unitAmount,amount,payerName:String(d.payerName||member.name||"").trim(),method:"bank",rewardRate,rewardPoint,status:"pending",createdAt:new Date().toISOString()};rows.unshift(row);await writePayments(rows);return Response.json({ok:true,payment:row})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin/payments" && request.method === "GET") {const denied=await requireAdmin();if(denied)return denied;return Response.json({ok:true,payments:await readPayments()})}
    if (url.pathname === "/api/admin/payments/complete" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readPayments(),i=rows.findIndex(x=>x.id===d.id);if(i<0)return Response.json({ok:false,error:"결제내역을 찾을 수 없습니다."},{status:404});if(rows[i].status==="completed")return Response.json({ok:true,payment:rows[i]});const products=await readA3Products(),product=products.find(x=>String(x.title||"")===String(rows[i].product||"")),rate=rows[i].rewardRate!=null?Math.max(0,Number(rows[i].rewardRate)||0):Math.max(0,Number(product?.rate)||0),reward=rows[i].rewardPoint!=null?Math.max(0,Number(rows[i].rewardPoint)||0):Math.round(Number(rows[i].amount||0)*rate/100),mk="system/members.json";let members=[];const mo=await env.IMAGES.get(mk);if(mo)members=JSON.parse(await mo.text());const mi=members.findIndex(x=>x.memberNo===rows[i].memberNo);if(mi<0)return Response.json({ok:false,error:"결제 회원을 찾을 수 없습니다."},{status:404});members[mi].point=Number(members[mi].point||0)+reward;members[mi].balanceUpdatedAt=new Date().toISOString();rows[i].status="completed";rows[i].rewardRate=rate;rows[i].rewardPoint=reward;rows[i].completedAt=new Date().toISOString();await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});try{await writePayments(rows)}catch(e){members[mi].point=Math.max(0,Number(members[mi].point||0)-reward);await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});throw e}return Response.json({ok:true,payment:rows[i],rewardPoint:reward,memberPoint:members[mi].point})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin/payments/delete" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readPayments(),i=rows.findIndex(x=>x.id===d.id);if(i<0)return Response.json({ok:false,error:"결제내역을 찾을 수 없습니다."},{status:404});if(rows[i].status==="completed")return Response.json({ok:false,error:"결제완료 내역은 삭제할 수 없습니다."},{status:400});rows.splice(i,1);await writePayments(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if (url.pathname === "/api/admin/member-balance-adjust" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try{const d=await request.json(),memberNo=String(d.memberNo||""),cashDelta=Number(d.cashDelta)||0,pointDelta=Number(d.pointDelta)||0,key="system/members.json";let members=[];const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text());const i=members.findIndex(x=>x.memberNo===memberNo);if(i<0)return Response.json({ok:false,error:"회원을 찾을 수 없습니다."},{status:404});const nc=Number(members[i].cash||0)+cashDelta,np=Number(members[i].point||0)+pointDelta;if(nc<0||np<0)return Response.json({ok:false,error:"잔액이 부족합니다."},{status:400});members[i].cash=nc;members[i].point=np;members[i].balanceUpdatedAt=new Date().toISOString();await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true,member:members[i]})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/admin/member-balance" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try{const d=await request.json(),memberNo=String(d.memberNo||""),cash=Math.max(0,Number(d.cash)||0),point=Math.max(0,Number(d.point)||0),key="system/members.json";let members=[];const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text());const i=members.findIndex(x=>x.memberNo===memberNo);if(i<0)return Response.json({ok:false,error:"회원을 찾을 수 없습니다."},{status:404});members[i].cash=Number(members[i].cash||0)+cash;members[i].point=Number(members[i].point||0)+point;members[i].balanceUpdatedAt=new Date().toISOString();await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true,member:members[i]})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/member/withdraw" && request.method === "POST") {
      try {
        const member=await sessionMember();
        if(!member) return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
        const key="system/members.json"; let members=[];
        try{const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text())}catch{}
        members=members.filter(x=>!(x.providers||[x.provider]).includes(member.provider)||x.id!==member.id);
        await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true},{headers:{"Set-Cookie":"submarine_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}});
      } catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    async function readWaivers() {
      const key = "system/waivers.json";
      let rows = [];
      try { const o = await env.IMAGES.get(key); if (o) rows = JSON.parse(await o.text()); } catch {}
      const cutoff1y = Date.now() - 365 * 24 * 60 * 60 * 1000;
      const cutoff2y = Date.now() - 730 * 24 * 60 * 60 * 1000;
      const kept = rows.filter(x => x.hold === true || new Date(x.submittedAt || 0).getTime() >= (x.waiverCode === "D-3" ? cutoff2y : cutoff1y));
      if (kept.length !== rows.length) await env.IMAGES.put(key, JSON.stringify(kept), {httpMetadata:{contentType:"application/json"}});
      return kept;
    }
    async function writeWaivers(rows) {
      await env.IMAGES.put("system/waivers.json", JSON.stringify(rows), {httpMetadata:{contentType:"application/json"}});
    }
    async function sessionMember() {
      try {
        const cookie=request.headers.get("Cookie")||"", raw=(cookie.match(/(?:^|;\\s*)submarine_session=([^;]+)/)||[])[1];
        if(!raw) return null;
        const [payload,sig]=raw.split(".");
        if(!payload||!sig) return null;
        const sessionKey=String(env.NAVER_CLIENT_SECRET||env.KAKAO_REST_API_KEY||"");
        const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(sessionKey),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
        const pad=sig.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-sig.length%4)%4);
        const bytes=Uint8Array.from(atob(pad),c=>c.charCodeAt(0));
        if(!await crypto.subtle.verify("HMAC",key,bytes,new TextEncoder().encode(payload))) return null;
        const pp=payload.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-payload.length%4)%4);
        return JSON.parse(decodeURIComponent(escape(atob(pp))));
      } catch { return null; }
    }
    if (url.pathname === "/api/waivers" && request.method === "POST") {
      try {
        const member=await sessionMember();
        if(!member) return Response.json({ok:false,error:"로그인 후 약정서를 제출할 수 있습니다."},{status:401});
        const data=await request.json();
        if(!["D-1","D-2","D-3"].includes(data.waiverCode)||!data.lessonDate||(data.waiverCode!=="D-3"&&!data.lessonTime)||!data.signatureData) return Response.json({ok:false,error:"약정서 제출정보가 부족합니다."},{status:400});
        const selected=new Date(String(data.lessonDate)+"T00:00:00"),n=new Date(),today=new Date(n.getFullYear(),n.getMonth(),n.getDate());if(selected<today)return Response.json({ok:false,error:"지난 날짜에는 약정서를 제출할 수 없습니다."},{status:400});
        const rows=await readWaivers(), now=new Date().toISOString();
        const row={id:crypto.randomUUID(),waiverCode:data.waiverCode,lessonDate:String(data.lessonDate),lessonTime:data.waiverCode==="D-3"?"":String(data.lessonTime).replace(/[^1-5]/g,"").slice(0,1),educationLevel:data.waiverCode==="D-2"?String(data.educationLevel||""):"",instructorName:data.waiverCode==="D-2"?String(data.instructorName||"").trim().slice(0,100):"",memberNo:member.memberNo||"",memberName:member.name||"회원",provider:member.provider||"",memberId:member.id||"",agreementHtml:String(data.agreementHtml||"").slice(0,200000),signatureData:String(data.signatureData||"").slice(0,500000),submittedAt:now,hold:false};
        rows.push(row); await writeWaivers(rows);
        return Response.json({ok:true,id:row.id});
      } catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/admin/waivers" && request.method === "GET") {
      const denied=await requireAdmin(); if(denied)return denied;
      try { return Response.json({ok:true,waivers:await readWaivers()}); }
      catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/admin/waivers/hold" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try {
        const data=await request.json(), rows=await readWaivers(), x=rows.find(v=>v.id===data.id);
        if(!x) return Response.json({ok:false,error:"약정서를 찾을 수 없습니다."},{status:404});
        x.hold=!!data.hold; x.holdUpdatedAt=new Date().toISOString(); await writeWaivers(rows);
        return Response.json({ok:true,hold:x.hold});
      } catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    async function readA3Products(){try{const o=await env.IMAGES.get("system/a3-products.json");let rows=o?JSON.parse(await o.text()):[];return Array.isArray(rows)?rows.slice(0,20):[]}catch{return []}}
    async function writeA3Products(rows){await env.IMAGES.put("system/a3-products.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    if (url.pathname === "/api/a3-products" && request.method === "GET") {const rows=(await readA3Products()).filter(x=>x.published!==false&&x.title);return Response.json({ok:true,products:rows})}
    if (url.pathname === "/api/admin/a3-products" && request.method === "GET") {const denied=await requireAdmin();if(denied)return denied;return Response.json({ok:true,products:await readA3Products()})}
    if (url.pathname === "/api/admin/a3-products" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=Array.isArray(d.products)?d.products:[];const clean=rows.slice(0,20).map(x=>({category:String(x.category||""),title:String(x.title||""),price:String(x.price||""),npay:Number(x.npay)||0,rate:Number(x.rate)||0,desc:String(x.desc||""),tag:String(x.tag||""),detail:String(x.detail||""),options:String(x.options||""),extras:String(x.extras||""),published:x.published!==false,image:String(x.image||"")}));await writeA3Products(clean);return Response.json({ok:true,products:clean})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    async function readEducationPosts(){try{const o=await env.IMAGES.get("system/education-posts.json");if(!o)return [];const rows=JSON.parse(await o.text());const clean=rows.filter(x=>String(x.title||"").trim()!=="한 줄, 상위 카테고리");if(clean.length!==rows.length)await env.IMAGES.put("system/education-posts.json",JSON.stringify(clean),{httpMetadata:{contentType:"application/json"}});return clean}catch{return []}}
    async function writeEducationPosts(rows){await env.IMAGES.put("system/education-posts.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    if (url.pathname === "/api/education-posts" && request.method === "GET") {const rows=(await readEducationPosts()).filter(x=>x.published!==false);return Response.json({ok:true,posts:rows})}
    if (url.pathname === "/api/admin/education-posts" && request.method === "GET") {const denied=await requireAdmin();if(denied)return denied;return Response.json({ok:true,posts:await readEducationPosts()})}
    if (url.pathname === "/api/admin/education-posts" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readEducationPosts(),id=String(d.id||crypto.randomUUID()),i=rows.findIndex(x=>String(x.id)===id),old=i>=0?rows[i]:{},post={...old,id,category:String(d.category||""),title:String(d.title||""),bodyHtml:String(d.bodyHtml||""),image:String(d.image||""),tags:Array.isArray(d.tags)?d.tags.map(String):[],published:d.published!==false,createdAt:old.createdAt||new Date().toISOString(),updatedAt:new Date().toISOString()};if(i>=0)rows[i]=post;else rows.push(post);await writeEducationPosts(rows);return Response.json({ok:true,post})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin/education-posts/delete" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=(await readEducationPosts()).filter(x=>String(x.id)!==String(d.id));await writeEducationPosts(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if (url.pathname === "/api/upload-image" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try {
        const form = await request.formData();
        const file = form.get("file");
        if (!file || typeof file === "string") {
          return Response.json({ ok: false, error: "이미지 파일이 없습니다." }, { status: 400 });
        }
        if (file.size > 3145728) {
          return Response.json({ ok: false, error: "파일당 최대 3MB까지 업로드할 수 있습니다." }, { status: 413 });
        }
        if (!file.type || !file.type.startsWith("image/")) {
          return Response.json({ ok: false, error: "이미지 파일만 업로드할 수 있습니다." }, { status: 415 });
        }
        const extMap = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" };
        const ext = extMap[file.type] || "img";
        const key = "uploads/" + new Date().toISOString().slice(0,10) + "/" + crypto.randomUUID() + "." + ext;
        await env.IMAGES.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
        return Response.json({ ok: true, url: "https://pub-8216b63561af42ecb148b7864ed54e6b.r2.dev/" + key });
      } catch (e) {
        return Response.json({ ok: false, error: "R2 업로드 실패: " + (e?.message || String(e)) }, { status: 500 });
      }
    }

    if (url.pathname === "/api/admin-password" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try{
        const data=await request.json(),password=String(data.password||"");
        if(password.length<8)return Response.json({ok:false,error:"비밀번호는 8자 이상 입력해 주세요."},{status:400});
        const salt=crypto.randomUUID(),passwordHash=await hashPassword(password,salt);
        await env.IMAGES.put("system/admin-auth.json",JSON.stringify({salt,passwordHash}),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true});
      }catch(e){return Response.json({ok:false,error:"비밀번호 변경에 실패했습니다."},{status:500})}
    }

    if (url.pathname === "/api/admin-login" && request.method === "POST") {
      try {
        const data=await request.json();let cfg=await adminConfig();
        if(!cfg){
          if(String(data.id||"")!=="submarine"||String(data.password||"").length<8)return Response.json({ok:false},{status:401});
          const salt=crypto.randomUUID(),passwordHash=await hashPassword(String(data.password||""),salt);
          cfg={salt,passwordHash};
          await env.IMAGES.put("system/admin-auth.json",JSON.stringify(cfg),{httpMetadata:{contentType:"application/json"}});
        }
        const valid=String(data.id||"")==="submarine" && await hashPassword(String(data.password||""),cfg.salt)===cfg.passwordHash;
        if(!valid)return Response.json({ok:false},{status:401});
        const token=crypto.randomUUID()+crypto.randomUUID().replaceAll("-",""),expiresAt=Date.now()+12*60*60*1000;
        await env.IMAGES.put("system/admin-sessions/"+token+".json",JSON.stringify({expiresAt}),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true},{headers:{"Set-Cookie":"submarine_admin="+token+"; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200"}});
      } catch { return Response.json({ok:false},{status:400}); }
    }
    if (url.pathname === "/api/admin-session" && request.method === "GET") {
      return Response.json({ok:await adminSessionValid()},{status:await adminSessionValid()?200:401});
    }
    if (url.pathname === "/api/admin-logout" && request.method === "POST") {
      const cookie=request.headers.get("Cookie")||"",token=(cookie.match(/(?:^|;\\s*)submarine_admin=([^;]+)/)||[])[1];if(token)try{await env.IMAGES.delete("system/admin-sessions/"+token+".json")}catch{}
      return Response.json({ok:true},{headers:{"Set-Cookie":"submarine_admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"}});
    }

    const response = await env.ASSETS.fetch(request);
    if (url.pathname.endsWith(".html") || url.pathname === "/") {
      const fresh = new Response(response.body, response);
      fresh.headers.set("Cache-Control", "no-store, no-cache, must-revalidate");
      return fresh;
    }
    return response;
  }
};