export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    async function bonusPhoneKey(phone){const normalized=String(phone||"").replace(/[^0-9]/g,"");if(!normalized)return "";const secret=String(env.NAVER_CLIENT_SECRET||env.KAKAO_REST_API_KEY||"submarine");const data=new TextEncoder().encode(secret+"|signup-bonus|"+normalized);const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",data));return Array.from(digest,b=>b.toString(16).padStart(2,"0")).join("")}
    async function signupBonusEligible(phone){const h=await bonusPhoneKey(phone);if(!h)return false;const o=await env.IMAGES.get("system/signup-bonus-history.json");const rows=o?JSON.parse(await o.text()):[];return !rows.some(x=>x.phoneHash===h)}
    async function markSignupBonus(phone){const h=await bonusPhoneKey(phone);if(!h)return;const key="system/signup-bonus-history.json",o=await env.IMAGES.get(key),rows=o?JSON.parse(await o.text()):[];if(!rows.some(x=>x.phoneHash===h)){rows.push({phoneHash:h,grantedAt:new Date().toISOString()});await env.IMAGES.put(key,JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}}
    async function saveMember(member) {
      const key = "system/members.json";
      let members = [];
      try { const o = await env.IMAGES.get(key); if (o) members = JSON.parse(await o.text()); } catch {}
      const now = new Date().toISOString(),phone=String(member.phone||"").replace(/[^0-9]/g,"");
      const sameIdentity=x=>(x.provider===member.provider&&x.id===member.id)||(x.identities||[]).some(v=>v.provider===member.provider&&v.id===member.id);
      const i=members.findIndex(sameIdentity),duplicate=members.find((x,index)=>index!==i&&phone&&String(x.phone||"").replace(/[^0-9]/g,"")===phone);
      if((i>=0&&members[i].status==="expelled")||duplicate?.status==="expelled")throw new Error("강퇴된 회원입니다.");
      if(i<0&&duplicate){const error=new Error("이미 가입되어 있는 회원입니다. 기존 가입 방식으로 로그인해 주세요.");error.status=409;throw error;}
      if (i >= 0) {
        const old = members[i], providers = Array.from(new Set([...(old.providers||[old.provider]).filter(Boolean),member.provider]));
        members[i] = {...old,...member,provider:old.provider||member.provider,providers,lastLoginAt:now};
        await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
        return members[i];
      }
      const bonus=await signupBonusEligible(phone)?5000:0,saved={...member,providers:[member.provider],memberNo:"U"+String(Math.max(0,...members.map(x=>Number(String(x.memberNo||"").replace(/^U/,""))||0))+1).padStart(5,"0"),joinedAt:now,lastLoginAt:now,cash:0,point:bonus};
      members.push(saved);
      await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
      if(bonus)await markSignupBonus(phone);
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
      try{const cookie=request.headers.get("Cookie")||"",token=(cookie.match(/(?:^|;\s*)submarine_admin=([^;]+)/)||[])[1];if(!token)return false;const o=await env.IMAGES.get("system/admin-sessions/"+token+".json");if(!o)return false;const s=JSON.parse(await o.text());if(!s.expiresAt||Date.now()>s.expiresAt){await env.IMAGES.delete("system/admin-sessions/"+token+".json");return false}return true}catch{return false}
    }
    async function requireAdmin(){return await adminSessionValid()?null:Response.json({ok:false,error:"관리자 로그인이 필요합니다."},{status:401})}
    // KakaoPay online payment DEV probe. Secret stays in Worker env, never in browser/GitHub.
    if (url.pathname === "/api/payment/kakaopay/dev-probe" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      if(!env.KAKAOPAY_SECRET_KEY_DEV) return Response.json({ok:false,stage:"config",error:"KAKAOPAY_SECRET_KEY_DEV 환경변수가 없습니다."},{status:503});
      try{
        const origin="https://submarine.asia";
        const body={
          cid:"TC0ONETIME",
          partner_order_id:"SUBMARINE-DEV-"+Date.now(),
          partner_user_id:"admin-dev-probe",
          item_name:"SUBMARINE 카카오페이 개발연동 테스트",
          quantity:1,
          total_amount:100,
          tax_free_amount:0,
          approval_url:origin+"/?kakaopay=success",
          cancel_url:origin+"/?kakaopay=cancel",
          fail_url:origin+"/?kakaopay=fail"
        };
        const r=await fetch("https://open-api.kakaopay.com/online/v1/payment/ready",{
          method:"POST",
          headers:{"Authorization":"SECRET_KEY "+env.KAKAOPAY_SECRET_KEY_DEV,"Content-Type":"application/json"},
          body:JSON.stringify(body)
        });
        const raw=await r.text(); let data; try{data=JSON.parse(raw)}catch{data={raw:raw.slice(0,1000)}}
        const safe=data&&typeof data==="object"?{...data}:data;
        // A successful Ready response proves DEV online-payment access. Keep tid server-side only.
        if(r.ok&&data?.tid){
          await env.IMAGES.put("system/kakaopay-dev-probe.json",JSON.stringify({tid:data.tid,partner_order_id:body.partner_order_id,partner_user_id:body.partner_user_id,createdAt:new Date().toISOString()}),{httpMetadata:{contentType:"application/json"}});
        }
        if(safe&&typeof safe==="object"){delete safe.tid;delete safe.next_redirect_app_url;delete safe.next_redirect_mobile_url;delete safe.next_redirect_pc_url;delete safe.android_app_scheme;delete safe.ios_app_scheme}
        return Response.json({ok:r.ok,httpStatus:r.status,stage:"ready",onlineDevAccess:r.ok,response:safe},{status:r.ok?200:r.status,headers:{"Cache-Control":"no-store"}});
      }catch(e){return Response.json({ok:false,stage:"network",error:e?.message||String(e)},{status:502,headers:{"Cache-Control":"no-store"}})}
    }

    if (url.pathname === "/api/auth/local/register" && request.method === "POST") {
      try {
        const d=await request.json(),name=String(d.name||"").trim(),phone=String(d.phone||"").replace(/[^0-9]/g,""),password=String(d.password||""),licenses=Array.isArray(d.licenses)?d.licenses:[];
        if(!name||phone.length<10||password.length<6)return Response.json({ok:false,error:"이름, 휴대폰번호, 비밀번호 6자 이상을 입력해 주세요."},{status:400});
        if(!d.licenseConfirmed)return Response.json({ok:false,error:"자격증 정보를 확인해 주세요."},{status:400});
        const key="system/members.json";let members=[];try{const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text())}catch{}
        let m=members.find(x=>String(x.phone||"").replace(/[^0-9]/g,"")===phone);
        if(m)return Response.json({ok:false,error:"이미 가입되어 있는 회원입니다. 기존 가입 방식으로 로그인해 주세요."},{status:409});
        const salt=crypto.randomUUID(),passwordHash=await hashPassword(password,salt),now=new Date().toISOString();
        const bonus=await signupBonusEligible(phone)?5000:0;m={provider:"local",id:phone,identities:[{provider:"local",id:phone}],providers:["local"],memberNo:"U"+String(Math.max(0,...members.map(x=>Number(String(x.memberNo||"").replace(/^U/,""))||0))+1).padStart(5,"0"),name,phone,email:"",joinedAt:now,lastLoginAt:now,cash:0,point:bonus,licenses,profileCompleted:true,localSalt:salt,localPasswordHash:passwordHash};members.push(m);
        await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});if(bonus)await markSignupBonus(phone);
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

    if(url.pathname==="/api/auth/naver/signup"&&["GET","POST","DELETE"].includes(request.method)){
      const token=(request.headers.get("Cookie")||"").match(/(?:^|;\s*)submarine_naver_signup=([a-f0-9-]+)/)?.[1];
      const key=token?"system/naver-signups/"+token+".json":"";
      const clear="submarine_naver_signup=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
      if(request.method!=="GET"&&request.headers.get("Origin")!==url.origin)return Response.json({ok:false,error:"잘못된 요청입니다."},{status:403});
      if(request.method==="DELETE"){if(key)await env.IMAGES.delete(key);return Response.json({ok:true},{headers:{"Set-Cookie":clear}})}
      const o=key?await env.IMAGES.get(key):null,pending=o?JSON.parse(await o.text()):null;
      if(!pending||pending.expiresAt<Date.now()){if(key&&o)await env.IMAGES.delete(key);return Response.json({ok:false,error:"가입 확인 시간이 만료되었습니다. 네이버로 다시 로그인해 주세요."},{status:401,headers:{"Cache-Control":"no-store"}})}
      if(request.method==="GET"){const m=pending.member;return Response.json({ok:true,member:{name:m.name,gender:m.gender,birthday:m.birthday,birthyear:m.birthyear,phone:m.phone}},{headers:{"Cache-Control":"no-store"}})}
      try{const d=await request.json();if(d.confirmed!==true)return Response.json({ok:false,error:"회원가입에 동의해 주세요."},{status:400});
        const member=await saveMember(pending.member);await env.IMAGES.delete(key);
        const headers=new Headers({"Content-Type":"application/json","Cache-Control":"no-store"});headers.append("Set-Cookie",await makeSession(member));headers.append("Set-Cookie",clear);
        return new Response(JSON.stringify({ok:true}),{headers});
      }catch(e){return Response.json({ok:false,error:e?.message||"회원가입에 실패했습니다."},{status:e?.status||500})}
    }
    if(url.pathname==="/api/auth/kakao/signup"&&["GET","POST","DELETE"].includes(request.method)){
      const token=(request.headers.get("Cookie")||"").match(/(?:^|;\s*)submarine_kakao_signup=([a-f0-9-]+)/)?.[1];
      const key=token?"system/kakao-signups/"+token+".json":"";
      const clear="submarine_kakao_signup=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
      if(request.method!=="GET"&&request.headers.get("Origin")!==url.origin)return Response.json({ok:false,error:"잘못된 요청입니다."},{status:403});
      if(request.method==="DELETE"){if(key)await env.IMAGES.delete(key);return Response.json({ok:true},{headers:{"Set-Cookie":clear}})}
      const o=key?await env.IMAGES.get(key):null,pending=o?JSON.parse(await o.text()):null;
      if(!pending||pending.expiresAt<Date.now()){if(key&&o)await env.IMAGES.delete(key);return Response.json({ok:false,error:"가입 확인 시간이 만료되었습니다. 카카오로 다시 로그인해 주세요."},{status:401,headers:{"Cache-Control":"no-store"}})}
      if(request.method==="GET"){const m=pending.member;return Response.json({ok:true,member:{name:m.name,gender:m.gender,birthday:m.birthday,birthyear:m.birthyear,phone:m.phone}},{headers:{"Cache-Control":"no-store"}})}
      try{const d=await request.json();if(d.confirmed!==true)return Response.json({ok:false,error:"회원가입에 동의해 주세요."},{status:400});
        if(!pending.member.name||!pending.member.phone||!pending.member.birthyear||!pending.member.gender)return Response.json({ok:false,error:"카카오 회원정보 제공 권한이 아직 준비되지 않았습니다. 일반 회원가입을 이용해 주세요."},{status:400});
        const member=await saveMember(pending.member);await env.IMAGES.delete(key);
        const headers=new Headers({"Content-Type":"application/json","Cache-Control":"no-store"});headers.append("Set-Cookie",await makeSession(member));headers.append("Set-Cookie",clear);
        return new Response(JSON.stringify({ok:true}),{headers});
      }catch(e){return Response.json({ok:false,error:e?.message||"회원가입에 실패했습니다."},{status:e?.status||500})}
    }
    if (url.pathname === "/api/auth/naver" && request.method === "GET") {
      if (!env.NAVER_CLIENT_ID || !env.NAVER_CLIENT_SECRET) return new Response("NAVER OAuth 환경변수가 없습니다.", { status: 503 });
      const state = crypto.randomUUID().replaceAll("-", "");
      const redirectUri = "https://submarine.asia/api/auth/naver/callback";
      const signupMode=url.searchParams.get("mode")==="signup";
      const q = new URLSearchParams({ response_type: "code", client_id: env.NAVER_CLIENT_ID, redirect_uri: redirectUri, state, auth_type:"reauthenticate" });
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
        let member = { provider:"naver", id:profile.response.id, name:profile.response.name || profile.response.nickname || "네이버 회원", email:profile.response.email || "", phone:profile.response.mobile || "", gender:profile.response.gender || "", birthday:profile.response.birthday || "", birthyear:profile.response.birthyear || "" };
        let members=[];const existingObject=await env.IMAGES.get("system/members.json");if(existingObject)members=JSON.parse(await existingObject.text());
        const normalizedPhone=String(member.phone||"").replace(/[^0-9]/g,"");
        let existing=members.find(x=>(x.provider==="naver"&&x.id===member.id)||(x.identities||[]).some(v=>v.provider==="naver"&&v.id===member.id));
        if(!existing&&normalizedPhone)existing=members.find(x=>String(x.phone||"").replace(/[^0-9]/g,"")===normalizedPhone);
        if(existing){
          const identities=Array.isArray(existing.identities)?existing.identities:[];
          if(!identities.some(v=>v.provider==="naver"&&v.id===member.id))identities.push({provider:"naver",id:member.id});
          existing.identities=identities;
          existing.providers=Array.from(new Set([...(existing.providers||[existing.provider]).filter(Boolean),"naver"]));
          existing.email=existing.email||member.email;existing.gender=existing.gender||member.gender;existing.birthday=existing.birthday||member.birthday;existing.birthyear=existing.birthyear||member.birthyear;existing.lastLoginAt=new Date().toISOString();
          await env.IMAGES.put("system/members.json",JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
          const sessionMember={...existing,provider:existing.provider||"naver"};
          const headers=new Headers({Location:"https://submarine.asia/"});headers.append("Set-Cookie",await makeSession(sessionMember));headers.append("Set-Cookie","submarine_naver_signup=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
          return new Response(null,{status:302,headers});
        }
        if(!existing){
          const token=crypto.randomUUID();await env.IMAGES.put("system/naver-signups/"+token+".json",JSON.stringify({member,expiresAt:Date.now()+600000}),{httpMetadata:{contentType:"application/json"}});
          return new Response(null,{status:302,headers:{Location:"https://submarine.asia/?naverSignup=1","Set-Cookie":"submarine_naver_signup="+token+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"}});
        }
        member=await saveMember(member);
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
        const savedState=(request.headers.get("Cookie")||"").match(/(?:^|;\s*)kakao_oauth_state=([^;]+)/)?.[1];
        if(!code||!state||state!==savedState) return new Response("카카오 로그인 상태값이 일치하지 않습니다.",{status:400});
        const body=new URLSearchParams({grant_type:"authorization_code",client_id:env.KAKAO_REST_API_KEY,redirect_uri:"https://submarine.asia/api/auth/kakao/callback",code});
        if(env.KAKAO_CLIENT_SECRET)body.set("client_secret",env.KAKAO_CLIENT_SECRET);
        const tr=await fetch("https://kauth.kakao.com/oauth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded;charset=utf-8"},body});
        const token=await tr.json();
        if(!tr.ok||!token.access_token) throw new Error(token.error_description||token.error||"토큰 발급 실패");
        const pr=await fetch("https://kapi.kakao.com/v2/user/me",{headers:{Authorization:"Bearer "+token.access_token}});
        const profile=await pr.json();
        if(!pr.ok||!profile.id) throw new Error(profile.msg||"프로필 조회 실패");
        const account=profile.kakao_account||{}, p=account.profile||{};
        let member={provider:"kakao",id:String(profile.id),name:account.name||"",phone:String(account.phone_number||"").replace(/^\+82\s*/,"0").replace(/[^0-9]/g,""),gender:account.gender==="male"?"M":account.gender==="female"?"F":"",birthyear:account.birthyear||""};
        const existingObject=await env.IMAGES.get("system/members.json"),members=existingObject?JSON.parse(await existingObject.text()):[];
        const existing=members.find(x=>(x.provider==="kakao"&&x.id===member.id)||(x.identities||[]).some(v=>v.provider==="kakao"&&v.id===member.id));
        if(!existing){
          const token=crypto.randomUUID();await env.IMAGES.put("system/kakao-signups/"+token+".json",JSON.stringify({member,expiresAt:Date.now()+600000}),{httpMetadata:{contentType:"application/json"}});
          return new Response(null,{status:302,headers:{Location:"https://submarine.asia/?kakaoSignup=1","Set-Cookie":"submarine_kakao_signup="+token+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"}});
        }
        member=await saveMember(member);
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
    if (url.pathname === "/api/instructor-membership" && request.method === "GET") {
      const member=await sessionMember();if(!member)return Response.json({ok:true,loggedIn:false,grade:"일반회원",isInstructor:false});
      const o=await env.IMAGES.get("system/instructors.json"),rows=o?JSON.parse(await o.text()):[];
      const no=String(member.memberNo||"").trim();
      const matched=!!no&&rows.some(x=>String(x.memberNo||"").trim()===no);
      return Response.json({ok:true,loggedIn:true,grade:matched?"강사회원":"일반회원",isInstructor:matched});
    }
    if (url.pathname === "/api/instructor-accounting" && request.method === "GET") {const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});try{const [io,so,co]=await Promise.all([env.IMAGES.get("system/instructors.json"),env.IMAGES.get("system/instructor-settlements.json"),env.IMAGES.get("system/instructor-closings.json")]),instructors=io?JSON.parse(await io.text()):[],settlements=so?JSON.parse(await so.text()):[],closings=co?JSON.parse(await co.text()):[],no=String(member.memberNo||""),inst=instructors.find(x=>String(x.memberNo||"")===no),iid=inst?String(inst.id):"";return Response.json({ok:true,isInstructor:!!inst,settlements:settlements.filter(x=>String(x.memberNo||"")===no||(iid&&String(x.instructorId)===iid)),closings:closings.filter(x=>String(x.memberNo||"")===no||(iid&&String(x.instructorId)===iid))})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    async function analyticsHash(value){return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)))).map(b=>b.toString(16).padStart(2,"0")).join("")}
    async function analyticsExclusions(){const o=await env.IMAGES.get("system/analytics-exclusions.json");return o?JSON.parse(await o.text()):{ipHashes:[],visitorHashes:[],sids:[]}}
    if(url.pathname==="/api/admin/analytics/exclude-self"&&request.method==="POST"){const denied=await requireAdmin();if(denied)return denied;try{const ip=request.headers.get("CF-Connecting-IP");if(!ip)return Response.json({ok:false,error:"현재 접속 IP를 확인할 수 없습니다."},{status:400});const d=await request.json(),cfg=await analyticsExclusions(),ua=request.headers.get("User-Agent")||"",ipHash=await analyticsHash(ip),visitors=new Set(cfg.visitorHashes||[]);for(let n=0;n<366;n++){const day=new Date(Date.now()-n*86400000).toISOString().slice(0,10);visitors.add((await analyticsHash(ip+"|"+ua+"|"+day)).slice(0,24))}const sid=String(d.sid||"");await env.IMAGES.put("system/analytics-exclusions.json",JSON.stringify({ipHashes:[...new Set([...(cfg.ipHashes||[]),ipHash])],visitorHashes:[...visitors],sids:[...new Set([...(cfg.sids||[]),...(sid?[sid]:[])])]}),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true})}catch{return Response.json({ok:false,error:"접속 제외 설정을 저장하지 못했습니다."},{status:500})}}
    if(url.pathname==="/api/analytics/track"&&request.method==="POST"){try{if(await adminSessionValid())return Response.json({ok:true,excluded:true});const ip=request.headers.get("CF-Connecting-IP")||"",ipHash=ip?await analyticsHash(ip):"",exclusions=await analyticsExclusions();if(ipHash&&(exclusions.ipHashes||[]).includes(ipHash))return Response.json({ok:true,excluded:true});const d=await request.json();if((exclusions.sids||[]).includes(String(d.sid||"")))return Response.json({ok:true,excluded:true});const now=new Date(),day=now.toISOString().slice(0,10),cf=request.cf||{},ref=String(d.referrer||""),utm=String(d.utm_source||"").toLowerCase();let source=utm||"직접접속";if(!utm&&ref){try{const h=new URL(ref).hostname.toLowerCase();source=h.includes("naver")?"네이버":h.includes("google")?"구글":h.includes("instagram")?"인스타그램":h.includes("youtube")?"유튜브":h.includes("kakao")?"카카오":h.includes("submarine.asia")?"내부이동":h}catch{}}const raw=(request.headers.get("CF-Connecting-IP")||"")+"|"+(request.headers.get("User-Agent")||"")+"|"+day,visitor=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(raw)))).map(b=>b.toString(16).padStart(2,"0")).join("").slice(0,24),key="analytics/"+day+".json";let rows=[];try{const o=await env.IMAGES.get(key);if(o)rows=JSON.parse(await o.text())}catch{}let route=source;if(ref){try{const u=new URL(ref),h=u.hostname.toLowerCase(),kw=u.searchParams.get("query")||u.searchParams.get("q")||"";if(h.includes("place.naver")||h.includes("map.naver"))route="네이버 플레이스"+(kw?" · "+kw:"");else if(h.includes("naver"))route="네이버 검색"+(kw?" · "+kw:" · 검색어 확인불가");else if(h.includes("google"))route="구글 검색"+(kw?" · "+kw:" · 검색어 확인불가");else if(h.includes("instagram"))route="인스타그램";else if(h.includes("youtube"))route="유튜브";else if(h.includes("kakao"))route="카카오톡"}catch{}}if(utm)route=utm;rows.push({t:now.toISOString(),visitor,ipHash,sid:String(d.sid||""),page:String(d.page||"/"),source,route,region:String(cf.region||""),city:String(cf.city||""),country:String(cf.country||""),latitude:String(cf.latitude||""),longitude:String(cf.longitude||""),postalCode:String(cf.postalCode||""),regionCode:String(cf.regionCode||""),event:"pageview"});await env.IMAGES.put(key,JSON.stringify(rows.slice(-20000)),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true})}catch{return Response.json({ok:false},{status:400})}}
    if(url.pathname==="/api/admin/analytics"&&request.method==="GET"){const denied=await requireAdmin();if(denied)return denied;try{
      const days=Math.min(365,Math.max(7,Number(url.searchParams.get("days"))||7)),now=new Date(),analyticsStart=new Date("2026-09-30T00:00:00+09:00"),requestedSince=new Date(now.getTime()-(days-1)*86400000),since=requestedSince<analyticsStart?analyticsStart:requestedSince;
      const dates=[];for(let n=0;n<days;n++){const d=new Date(since.getTime()+n*86400000).toISOString().slice(0,10);dates.push(d)}
      const local=[];await Promise.all(dates.map(async day=>{try{const o=await env.IMAGES.get("analytics/"+day+".json");if(o)local.push(...JSON.parse(await o.text()))}catch{}}));
      const exclusions=await analyticsExclusions(),excludedIps=new Set(exclusions.ipHashes||[]),excludedVisitors=new Set(exclusions.visitorHashes||[]),excludedSids=new Set(exclusions.sids||[]);const filtered=local.filter(x=>{const t=new Date(x.t||0).getTime();return t>=analyticsStart.getTime()&&t<=now.getTime()&&!excludedIps.has(x.ipHash)&&!excludedVisitors.has(x.visitor)&&!excludedSids.has(x.sid)});
      const visitorSet=new Set(),sidSet=new Set(),dailySets={},rv={},gm={},unknownGeo={};
      for(const x of filtered){const v=String(x.visitor||"");if(v)visitorSet.add(v);const sid=String(x.sid||"");if(sid)sidSet.add(sid);const day=String(x.t||"").slice(0,10);if(day){if(!dailySets[day])dailySets[day]=new Set();if(v)dailySets[day].add(v)}
        const route=String(x.route||x.source||"직접접속");if(!rv[route])rv[route]=new Set();if(v)rv[route].add(v);
        if(String(x.country||"").toUpperCase()==="KR"){
          const city=String(x.city||"").toLowerCase().replace(/[^a-z가-힣]/g,""),region=String(x.region||"").toLowerCase().replace(/[^a-z가-힣]/g,""),code=String(x.regionCode||"").toLowerCase();
          const has=(...words)=>words.some(w=>city.includes(w));
          const inIncheon=region.includes("incheon")||region.includes("인천")||code==="28";
          const inGyeonggi=region.includes("gyeonggi")||region.includes("경기")||code==="41";
          const inSeoul=region.includes("seoul")||region.includes("서울")||code==="11";
          let k="";
          if(has("bucheon","부천"))k="부천시";
          else if(has("incheon","인천")||inIncheon)k="인천시";
          else if(has("gwangmyeong","광명"))k="광명시";
          else if(has("anyang","안양"))k="안양시";
          else if(has("gimpo","김포"))k="김포시";
          else if(has("goyang","ilsandong","ilsanseo","ilsan","deogyang","고양","일산","덕양"))k="고양시";
          else if(has("siheung","시흥"))k="시흥시";
          else if(inSeoul||has("seoul","서울")){
            if(has("jongno","junggu","yongsan","종로","중구","용산"))k="서울 도심권";
            else if(has("seongdong","gwangjin","dongdaemun","jungnang","seongbuk","gangbuk","dobong","nowon","성동","광진","동대문","중랑","성북","강북","도봉","노원"))k="서울 동북권";
            else if(has("eunpyeong","seodaemun","mapo","은평","서대문","마포"))k="서울 서북권";
            else if(has("yangcheon","gangseo","guro","geumcheon","yeongdeungpo","dongjak","gwanak","양천","강서","구로","금천","영등포","동작","관악"))k="서울 서남권";
            else if(has("seocho","gangnam","songpa","gangdong","서초","강남","송파","강동"))k="서울 동남권";
          }
          if(!k)k="그 외 지역";
          if(!gm[k])gm[k]=new Set();if(v)gm[k].add(v);
          if(k==="그 외 지역"){const raw=[String(x.region||"")||"(region 없음)",String(x.city||"")||"(city 없음)",String(x.regionCode||"")||"(code 없음)"].join(" / ");if(!unknownGeo[raw])unknownGeo[raw]=new Set();if(v)unknownGeo[raw].add(v)}
        }}
      
      const daily=dates.map(date=>({date,count:dailySets[date]?.size||0})),rankSets=o=>Object.entries(o).map(([name,set])=>({name,count:set.size})).sort((a,b)=>b.count-a.count);
      let registrations=0,reservations=0;const start=analyticsStart.getTime(),finish=now.getTime();try{const o=await env.IMAGES.get("system/members.json"),x=o?JSON.parse(await o.text()):[];registrations=x.filter(v=>{const t=new Date(v.joinedAt||v.createdAt||0).getTime();return t>=start&&t<=finish}).length}catch{}try{const o=await env.IMAGES.get("system/reservations.json"),x=o?JSON.parse(await o.text()):[];reservations=x.filter(v=>{const t=new Date(v.createdAt||0).getTime();return t>=start&&t<=finish&&v.status!=="cancelled"}).length}catch{}
      return Response.json({ok:true,source:"site",summary:{visitors:visitorSet.size,requests:filtered.length,pageviews:filtered.length,registrations,reservations},daily,sources:rankSets(rv).slice(0,10),regions:rankSets(gm),cities:rankSets(gm),unknownGeo:rankSets(unknownGeo).slice(0,30),countries:[]});
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

    if (url.pathname === "/api/logbook" && request.method === "GET") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{const key="system/logbooks/"+encodeURIComponent(String(member.memberNo||member.provider+"-"+member.id))+".json",o=await env.IMAGES.get(key);return Response.json({ok:true,logs:o?JSON.parse(await o.text()):[]},{headers:{"Cache-Control":"no-store"}})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/logbook" && request.method === "POST") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      if(request.headers.get("Origin")!==url.origin)return Response.json({ok:false,error:"잘못된 요청입니다."},{status:403});
      try{const d=await request.json(),key="system/logbooks/"+encodeURIComponent(String(member.memberNo||member.provider+"-"+member.id))+".json",o=await env.IMAGES.get(key),logs=o?JSON.parse(await o.text()):[],allowed=["logDate","logPlace","logBottomTime","logScubaSurface","logGas","logO2","logStartPressure","logEndPressure","logTank","logTankSize","logNDL","logSafetyStop","logEntryType","logDiveStyle","logWaterType","logTemp","logAirTemp","logVisibility","logWaves","logCurrent","logWeather","logCondition","logWeight","logSuit","logFins","logMask","logComputer","logGear","logFD_STA","logFD_DYN","logFD_DNF","logFD_CWT","logFD_CNF"],row={id:crypto.randomUUID(),createdAt:new Date().toISOString()};allowed.forEach(k=>row[k]=String(d[k]??"").slice(0,300));logs.unshift(row);await env.IMAGES.put(key,JSON.stringify(logs),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true,log:row})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/logbook" && request.method === "DELETE") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      if(request.headers.get("Origin")!==url.origin)return Response.json({ok:false,error:"잘못된 요청입니다."},{status:403});
      try{const id=String(url.searchParams.get("id")||""),key="system/logbooks/"+encodeURIComponent(String(member.memberNo||member.provider+"-"+member.id))+".json",o=await env.IMAGES.get(key),logs=o?JSON.parse(await o.text()):[];await env.IMAGES.put(key,JSON.stringify(logs.filter(x=>String(x.id)!==id)),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
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

    if(url.pathname==="/api/admin/member-delete"&&request.method==="POST"){
      const denied=await requireAdmin();if(denied)return denied;
      try{const d=await request.json(),memberNo=String(d.memberNo||"");if(!memberNo)return Response.json({ok:false,error:"회원번호가 필요합니다."},{status:400});
        const key="system/members.json",o=await env.IMAGES.get(key),members=o?JSON.parse(await o.text()):[],target=members.find(x=>x.memberNo===memberNo);
        if(!target)return Response.json({ok:false,error:"회원을 찾을 수 없습니다."},{status:404});
        await env.IMAGES.put("system/deleted-members/"+crypto.randomUUID()+".json",JSON.stringify({member:target,deletedAt:new Date().toISOString()}),{httpMetadata:{contentType:"application/json"}});
        await env.IMAGES.put(key,JSON.stringify(members.filter(x=>x.memberNo!==memberNo)),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true});
      }catch(e){return Response.json({ok:false,error:e?.message||"회원 삭제에 실패했습니다."},{status:500})}
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

    function npayCredentials(){
      return {
        clientId:String(env.NPAY_CLIENT_ID||env["Client Id"]||""),
        clientSecret:String(env.NPAY_CLIENT_SECRET||env["Client Secret"]||""),
        chainId:String(env.NPAY_CHAIN_ID||env["Chain Id"]||"")
      };
    }
    async function npayUserKey(memberNo){
      const b=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(memberNo||""))));
      return Array.from(b,x=>x.toString(16).padStart(2,"0")).join("").slice(0,44);
    }
    async function completeNpayPayment(row,detail,rows){
      if(row.status==="completed")return row;
      const mk="system/members.json";let members=[];const mo=await env.IMAGES.get(mk);if(mo)members=JSON.parse(await mo.text());
      const mi=members.findIndex(x=>x.memberNo===row.memberNo);if(mi<0)throw new Error("결제 회원을 찾을 수 없습니다.");
      const reward=Math.max(0,Number(row.rewardPoint)||0),products=await readA3Products(),productIndex=Number.isInteger(row.productIndex)?row.productIndex:products.findIndex(x=>String(x.title||"")===String(row.product||"")),purchaseMileage=row.purchaseMileagePoint!=null?Math.max(0,Number(row.purchaseMileagePoint)||0):(productIndex===0?Math.max(0,Number(row.amount)||0):0),credited=reward+purchaseMileage;
      members[mi].point=Number(members[mi].point||0)+credited;members[mi].balanceUpdatedAt=new Date().toISOString();
      row.status="completed";row.productIndex=productIndex;row.purchaseMileagePoint=purchaseMileage;row.completedAt=new Date().toISOString();row.npayPaymentId=String(detail.paymentId||"");row.npayPayHistId=String(detail.payHistId||"");row.npayDetail={paymentId:row.npayPaymentId,payHistId:row.npayPayHistId,primaryPayMeans:detail.primaryPayMeans||"",totalPayAmount:Number(detail.totalPayAmount)||0};
      await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});
      try{await writePayments(rows)}catch(e){members[mi].point=Math.max(0,Number(members[mi].point||0)-credited);await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});throw e}
      return row;
    }
    if(url.pathname==="/api/npay/config"&&request.method==="GET"){
      const c=npayCredentials();if(!c.clientId||!c.chainId)return Response.json({ok:false,error:"Npay 샌드박스 인증정보가 설정되지 않았습니다."},{status:503});
      return Response.json({ok:true,mode:"development",clientId:c.clientId,chainId:c.chainId},{headers:{"Cache-Control":"no-store"}});
    }
    if(url.pathname==="/api/npay/prepare"&&request.method==="POST"){
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{
        const c=npayCredentials();if(!c.clientId||!c.clientSecret||!c.chainId)return Response.json({ok:false,error:"Npay 샌드박스 인증정보가 완전하지 않습니다."},{status:503});
        const d=await request.json(),quantity=Math.max(1,Math.min(10,Math.floor(Number(d.quantity)||1))),products=await readA3Products(),productIndex=products.findIndex(x=>x.published!==false&&String(x.title||"")===String(d.product||"")),product=products[productIndex];
        if(!product)return Response.json({ok:false,error:"상품을 찾을 수 없습니다."},{status:404});
        const unitAmount=Number(String(product.price||"").replace(/[^0-9]/g,""))||0,amount=unitAmount*quantity;if(amount<10)return Response.json({ok:false,error:"결제금액을 확인해 주세요."},{status:400});
        const rewardRate=Math.max(0,Number(product.npay)||0),rewardPoint=Math.round(amount*rewardRate/100),purchaseMileagePoint=productIndex===0?amount:0,rows=await readPayments(),id=crypto.randomUUID(),merchantUserKey=await npayUserKey(member.memberNo);
        const row={id,memberNo:member.memberNo,name:member.name||"회원",phone:member.phone||"",product:String(product.title),productIndex,quantity,unitAmount,amount,payerName:member.name||"",method:"npay",rewardRate,rewardPoint,purchaseMileagePoint,status:"awaiting_auth",createdAt:new Date().toISOString()};rows.unshift(row);await writePayments(rows);
        return Response.json({ok:true,payment:{id,product:row.product,quantity,amount},reserve:{merchantUserKey,merchantPayKey:id,productName:row.product,productCount:quantity,totalPayAmount:amount,taxScopeAmount:amount,taxExScopeAmount:0,returnUrl:"https://submarine.asia/api/npay/return?orderId="+encodeURIComponent(id),productItems:[{categoryType:"ETC",categoryId:"ETC",uid:"submarine-"+id.replaceAll("-","").slice(0,20),name:row.product,payReferrer:"ETC",count:quantity}]}});
      }catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if(url.pathname==="/api/npay/return"&&request.method==="GET"){
      const orderId=String(url.searchParams.get("orderId")||""),resultCode=String(url.searchParams.get("resultCode")||""),paymentId=String(url.searchParams.get("paymentId")||""),resultMessage=String(url.searchParams.get("resultMessage")||"");
      const back=(status,msg)=>new Response(null,{status:302,headers:{Location:"https://submarine.asia/?npayResult="+encodeURIComponent(status)+(msg?"&npayMessage="+encodeURIComponent(msg):"")}});
      try{
        const rows=await readPayments(),row=rows.find(x=>x.id===orderId&&x.method==="npay");if(!row)return back("fail","결제 주문을 찾을 수 없습니다.");
        if(row.status==="completed")return back("success","");
        if(resultCode!=="Success"||!paymentId){row.status="auth_failed";row.npayError=resultMessage||resultCode||"결제 인증 실패";await writePayments(rows);return back("fail",row.npayError)}
        const c=npayCredentials();if(!c.clientId||!c.clientSecret||!c.chainId)throw new Error("Npay 인증정보가 없습니다.");
        const body=new URLSearchParams({paymentId}),r=await fetch("https://dev-pay.paygate.naver.com/naverpay-partner/naverpay/payments/v2.2/apply/payment",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded","X-Naver-Client-Id":c.clientId,"X-Naver-Client-Secret":c.clientSecret,"X-NaverPay-Chain-Id":c.chainId,"X-NaverPay-Idempotency-Key":orderId},body});
        const j=await r.json();if(!r.ok||j.code!=="Success"||!j.body?.detail){row.status="approval_failed";row.npayError=j.message||j.code||("HTTP "+r.status);await writePayments(rows);return back("fail",row.npayError)}
        const detail=j.body.detail;if(String(detail.merchantPayKey||"")!==orderId||Number(detail.totalPayAmount)!==Number(row.amount)){row.status="review";row.npayError="결제 검증값 불일치";row.npayPaymentId=paymentId;await writePayments(rows);return back("fail","결제 확인이 필요합니다. 관리자에게 문의해 주세요.")}
        await completeNpayPayment(row,detail,rows);return back("success","");
      }catch(e){return back("fail",e?.message||"결제 승인 처리 중 오류가 발생했습니다.")}
    }

    // Standards-based payload-free Web Push. Service worker displays generic payment notice.
    // Configure VAPID_PRIVATE_KEY as base64url PKCS#8 P-256 key, VAPID_PUBLIC_KEY
    // as base64url uncompressed public point, and VAPID_SUBJECT as mailto: address.
    const kPushBase64url=bytes=>{let binary="";for(const b of bytes)binary+=String.fromCharCode(b);return btoa(binary).split("+").join("-").split("/").join("_").replace(/=+$/,"")};
    const kPushDecode=str=>Uint8Array.from(atob(String(str).replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(String(str).length/4)*4,"=")),c=>c.charCodeAt(0));
    async function sendKPushNotifications(){
      const pub=String(env.VAPID_PUBLIC_KEY||"").trim(),priv=String(env.VAPID_PRIVATE_KEY||"").trim(),subject=String(env.VAPID_SUBJECT||"").trim();
      if(!pub||!priv||!subject)return;
      const key="system/admin-k-push-subscriptions.json",o=await env.IMAGES.get(key);
      if(!o)return;
      const subscriptions=JSON.parse(await o.text());
      if(!Array.isArray(subscriptions)||!subscriptions.length)return;
      const signingKey=await crypto.subtle.importKey("pkcs8",kPushDecode(priv),{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
      const encoder=new TextEncoder(),header=kPushBase64url(encoder.encode(JSON.stringify({typ:"JWT",alg:"ES256"})));
      const exp=Math.floor(Date.now()/1000)+3600;
      const tokens=new Map();
      const results=await Promise.allSettled(subscriptions.map(async sub=>{
        const endpoint=String(sub.endpoint||""),url=new URL(endpoint);
        if(url.protocol!=="https:")throw Error("invalid push endpoint");
        const aud=url.origin;
        let token=tokens.get(aud);
        if(!token){
          const payload=kPushBase64url(encoder.encode(JSON.stringify({aud,exp,sub:subject})));
          const signingInput=header+"."+payload;
          const signature=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},signingKey,encoder.encode(signingInput)));
          token=signingInput+"."+kPushBase64url(signature);tokens.set(aud,token);
        }
        const response=await fetch(endpoint,{method:"POST",headers:{"Authorization":"vapid t="+token+", k="+pub,"TTL":"60","Urgency":"high","Content-Length":"0"}});
        return {endpoint,status:response.status,ok:response.ok,expired:response.status===404||response.status===410};
      }));
      const expired=new Set(results.filter(x=>x.status==="fulfilled"&&x.value.expired).map(x=>x.value.endpoint));
      if(expired.size){
        // Avoid overwriting registrations made while notifications were being sent.
        const current=await env.IMAGES.get(key),rows=current?JSON.parse(await current.text()):[];
        await env.IMAGES.put(key,JSON.stringify(rows.filter(x=>!expired.has(x.endpoint))),{httpMetadata:{contentType:"application/json"}});
      }
      for(const result of results)if(result.status==="rejected")console.error("K-room push failed",String(result.reason));
    }
    async function readPayments(){try{const o=await env.IMAGES.get("system/payments.json");return o?JSON.parse(await o.text()):[]}catch{return []}}
    async function writePayments(rows){await env.IMAGES.put("system/payments.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    if (url.pathname === "/api/payments" && request.method === "POST") {const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});try{const d=await request.json(),amount=Math.max(0,Number(d.amount)||0);if(!d.product||!amount)return Response.json({ok:false,error:"상품과 금액을 확인해 주세요."},{status:400});const quantity=Math.max(1,Math.floor(Number(d.quantity)||1)),unitAmount=Math.max(0,Number(d.unitAmount)||0),products=await readA3Products(),productIndex=products.findIndex(x=>String(x.title||"")===String(d.product||"")),product=products[productIndex],rewardRate=Math.max(0,Number(product?.rate)||0),rewardPoint=Math.round(amount*rewardRate/100),purchaseMileagePoint=productIndex===0?amount:0,rows=await readPayments(),row={id:crypto.randomUUID(),memberNo:member.memberNo,name:member.name||"회원",phone:member.phone||"",product:String(d.product),productIndex,quantity,unitAmount,amount,payerName:String(d.payerName||member.name||"").trim(),method:"bank",rewardRate,rewardPoint,purchaseMileagePoint,status:"pending",createdAt:new Date().toISOString()};rows.unshift(row);await writePayments(rows);if(ctx&&typeof ctx.waitUntil==="function")ctx.waitUntil(sendKPushNotifications().catch(e=>console.error("K-room push delivery failed",String(e))));return Response.json({ok:true,payment:row})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    // K-room push registration: each administrator phone registers independently.
    // VAPID_PUBLIC_KEY is a public browser key; private signing key must remain server-side.
    if (url.pathname === "/api/admin/k-push/public-key" && request.method === "GET") {
      const denied=await requireAdmin();if(denied)return denied;
      const publicKey=String(env.VAPID_PUBLIC_KEY||"").trim();
      return Response.json({ok:!!publicKey,publicKey,error:publicKey?undefined:"웹 푸시 서버 키가 아직 설정되지 않았습니다."},{status:publicKey?200:503,headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/api/admin/k-push/subscriptions" && request.method === "POST") {
      const denied=await requireAdmin();if(denied)return denied;
      try {
        const d=await request.json(),sub=d.subscription||{},endpoint=String(sub.endpoint||"");
        if(!endpoint.startsWith("https://")||endpoint.length>2048||!sub.keys||!String(sub.keys.p256dh||"")||!String(sub.keys.auth||""))
          return Response.json({ok:false,error:"올바른 푸시 구독 정보가 아닙니다."},{status:400});
        const key="system/admin-k-push-subscriptions.json",o=await env.IMAGES.get(key),rows=o?JSON.parse(await o.text()):[];
        const now=new Date().toISOString(),entry={endpoint,keys:{p256dh:String(sub.keys.p256dh),auth:String(sub.keys.auth)},createdAt:now,updatedAt:now};
        const i=rows.findIndex(x=>x.endpoint===endpoint);
        if(i>=0)rows[i]={...rows[i],...entry,createdAt:rows[i].createdAt||now};else rows.push(entry);
        await env.IMAGES.put(key,JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true,registered:true});
      }catch(e){return Response.json({ok:false,error:e?.message||"등록 실패"},{status:500})}
    }
    if (url.pathname === "/api/admin/k-push/test" && request.method === "POST") {
      const denied=await requireAdmin();if(denied)return denied;
      if(!env.VAPID_PUBLIC_KEY||!env.VAPID_PRIVATE_KEY||!env.VAPID_SUBJECT)
        return Response.json({ok:false,error:"서버 푸시 인증키 설정이 필요합니다."},{status:503});
      try {
        const key="system/admin-k-push-subscriptions.json",o=await env.IMAGES.get(key),rows=o?JSON.parse(await o.text()):[];
        if(!rows.length)return Response.json({ok:false,error:"등록된 관리자 휴대폰이 없습니다."},{status:409});
        await sendKPushNotifications();
        return Response.json({ok:true,attempted:rows.length,note:"발송 시도 완료. 실제 수신은 휴대폰에서 확인하세요."});
      }catch(e){return Response.json({ok:false,error:"테스트 알림 발송 실패"},{status:500})}
    }
    if (url.pathname === "/api/admin/k-push/subscriptions" && request.method === "DELETE") {
      const denied=await requireAdmin();if(denied)return denied;
      try {
        const d=await request.json(),endpoint=String(d.endpoint||"");
        const key="system/admin-k-push-subscriptions.json",o=await env.IMAGES.get(key),rows=o?JSON.parse(await o.text()):[];
        await env.IMAGES.put(key,JSON.stringify(rows.filter(x=>x.endpoint!==endpoint)),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true});
      }catch(e){return Response.json({ok:false,error:e?.message||"해제 실패"},{status:500})}
    }
    if (url.pathname === "/api/admin/payments" && request.method === "GET") {const denied=await requireAdmin();if(denied)return denied;return Response.json({ok:true,payments:await readPayments()})}
    if (url.pathname === "/api/admin/payments/complete" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readPayments(),i=rows.findIndex(x=>x.id===d.id);if(i<0)return Response.json({ok:false,error:"결제내역을 찾을 수 없습니다."},{status:404});if(rows[i].status==="completed")return Response.json({ok:true,payment:rows[i]});const products=await readA3Products(),productIndex=Number.isInteger(rows[i].productIndex)?rows[i].productIndex:products.findIndex(x=>String(x.title||"")===String(rows[i].product||"")),product=products[productIndex],rate=rows[i].rewardRate!=null?Math.max(0,Number(rows[i].rewardRate)||0):Math.max(0,Number(product?.rate)||0),reward=rows[i].rewardPoint!=null?Math.max(0,Number(rows[i].rewardPoint)||0):Math.round(Number(rows[i].amount||0)*rate/100),purchaseMileage=rows[i].purchaseMileagePoint!=null?Math.max(0,Number(rows[i].purchaseMileagePoint)||0):(productIndex===0?Math.max(0,Number(rows[i].amount)||0):0),credited=reward+purchaseMileage,mk="system/members.json";let members=[];const mo=await env.IMAGES.get(mk);if(mo)members=JSON.parse(await mo.text());const mi=members.findIndex(x=>x.memberNo===rows[i].memberNo);if(mi<0)return Response.json({ok:false,error:"결제 회원을 찾을 수 없습니다."},{status:404});members[mi].point=Number(members[mi].point||0)+credited;members[mi].balanceUpdatedAt=new Date().toISOString();rows[i].status="completed";rows[i].productIndex=productIndex;rows[i].rewardRate=rate;rows[i].rewardPoint=reward;rows[i].purchaseMileagePoint=purchaseMileage;rows[i].completedAt=new Date().toISOString();await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});try{await writePayments(rows)}catch(e){members[mi].point=Math.max(0,Number(members[mi].point||0)-credited);await env.IMAGES.put(mk,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});throw e}return Response.json({ok:true,payment:rows[i],rewardPoint:reward,purchaseMileagePoint:purchaseMileage,creditedPoint:credited,memberPoint:members[mi].point})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin/payments/delete" && request.method === "POST") {const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readPayments(),i=rows.findIndex(x=>x.id===d.id);if(i<0)return Response.json({ok:false,error:"결제내역을 찾을 수 없습니다."},{status:404});rows.splice(i,1);await writePayments(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if (url.pathname === "/api/admin/member-balance-adjust" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try{const d=await request.json(),memberNo=String(d.memberNo||""),cashDelta=Number(d.cashDelta)||0,pointDelta=Number(d.pointDelta)||0,key="system/members.json";let members=[];const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text());const i=members.findIndex(x=>x.memberNo===memberNo);if(i<0)return Response.json({ok:false,error:"회원을 찾을 수 없습니다."},{status:404});const nc=Number(members[i].cash||0)+cashDelta,np=Number(members[i].point||0)+pointDelta;if(nc<0||np<0)return Response.json({ok:false,error:"잔액이 부족합니다."},{status:400});members[i].cash=nc;members[i].point=np;members[i].balanceUpdatedAt=new Date().toISOString();await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true,member:members[i]})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/admin/member-balance" && request.method === "POST") {
      const denied=await requireAdmin(); if(denied)return denied;
      try{const d=await request.json(),memberNo=String(d.memberNo||""),cash=Number(d.cash??0),point=Number(d.point??0),key="system/members.json";let members=[];const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text());const i=members.findIndex(x=>x.memberNo===memberNo);if(i<0)return Response.json({ok:false,error:"회원을 찾을 수 없습니다."},{status:404});if(!Number.isSafeInteger(cash)||!Number.isSafeInteger(point)||(!cash&&!point))return Response.json({ok:false,error:"변경 금액은 0이 아닌 정수로 입력하세요."},{status:400});const nextCash=Number(members[i].cash||0)+cash,nextPoint=Number(members[i].point||0)+point;if(!Number.isSafeInteger(nextCash)||!Number.isSafeInteger(nextPoint)||nextCash<0||nextPoint<0)return Response.json({ok:false,error:"잔액이 부족하거나 변경 금액이 올바르지 않습니다."},{status:400});members[i].cash=nextCash;members[i].point=nextPoint;members[i].balanceUpdatedAt=new Date().toISOString();await env.IMAGES.put(key,JSON.stringify(members),{httpMetadata:{contentType:"application/json"}});return Response.json({ok:true,member:members[i]})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/member/withdraw" && request.method === "POST") {
      try {
        const member=await sessionMember();
        if(!member) return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
        const key="system/members.json"; let members=[];
        try{const o=await env.IMAGES.get(key);if(o)members=JSON.parse(await o.text())}catch{}
        const normalizePhone=v=>String(v||"").replace(/[^0-9]/g,"");
        const target=members.find(x=>(member.memberNo&&x.memberNo===member.memberNo)||((x.provider===member.provider||(x.providers||[]).includes(member.provider))&&x.id===member.id)||(member.phone&&normalizePhone(x.phone)===normalizePhone(member.phone)));
        if(!target)return Response.json({ok:false,error:"탈퇴할 회원 정보를 찾을 수 없습니다. 다시 로그인해 주세요."},{status:404});
        members=members.filter(x=>x!==target);
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
        const cookie=request.headers.get("Cookie")||"", raw=(cookie.match(/(?:^|;\s*)submarine_session=([^;]+)/)||[])[1];
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
    if (url.pathname === "/api/admin/instructor-agreements" && request.method === "GET") {
      const denied=await requireAdmin();if(denied)return denied;
      const listed=await env.IMAGES.list({prefix:"system/instructor-agreements/"});
      const rows=[];for(const item of listed.objects){const o=await env.IMAGES.get(item.key);if(!o)continue;try{const x=JSON.parse(await o.text());delete x.signature;rows.push(x)}catch{}}
      rows.sort((a,b)=>String(b.submittedAt).localeCompare(String(a.submittedAt)));
      return Response.json({ok:true,agreements:rows});
    }
    if (url.pathname.startsWith("/api/admin/instructor-agreements/") && request.method === "GET") {
      const denied=await requireAdmin();if(denied)return denied;
      const tail=url.pathname.slice("/api/admin/instructor-agreements/".length);
      const [id,kind,indexText]=tail.split("/");
      if(!/^[0-9a-f-]{36}$/.test(id))return Response.json({ok:false,error:"잘못된 접수번호"},{status:400});
      const o=await env.IMAGES.get("system/instructor-agreements/"+id+".json");
      if(!o)return Response.json({ok:false,error:"약정서 없음"},{status:404});
      const row=JSON.parse(await o.text());
      if(kind==="file"){const n=Number(indexText),file=row.attachments?.[n];if(!Number.isInteger(n)||!file)return Response.json({ok:false,error:"첨부파일 없음"},{status:404});const f=await env.IMAGES.get(file.key);if(!f)return Response.json({ok:false,error:"파일 없음"},{status:404});return new Response(f.body,{headers:{"Content-Type":file.type,"Content-Disposition":"attachment; filename*=UTF-8''"+encodeURIComponent(file.name),"Cache-Control":"no-store"}})}
      return Response.json({ok:true,agreement:row});
    }
    if(url.pathname==="/api/admin/sm-instructor-agreements"&&request.method==="GET"){
      const denied=await requireAdmin();if(denied)return denied;
      const listed=await env.IMAGES.list({prefix:"system/sm-instructor-agreements/"}),rows=[];
      for(const item of listed.objects){const o=await env.IMAGES.get(item.key);if(!o)continue;try{const x=JSON.parse(await o.text());delete x.signature;rows.push(x)}catch{}}
      rows.sort((a,b)=>String(b.submittedAt).localeCompare(String(a.submittedAt)));
      return Response.json({ok:true,agreements:rows});
    }
    if(url.pathname.startsWith("/api/admin/sm-instructor-agreements/")&&request.method==="GET"){
      const denied=await requireAdmin();if(denied)return denied;
      const id=url.pathname.split("/").pop();if(!/^[0-9a-f-]{36}$/.test(id))return Response.json({ok:false,error:"잘못된 접수번호"},{status:400});
      const o=await env.IMAGES.get("system/sm-instructor-agreements/"+id+".json");if(!o)return Response.json({ok:false,error:"약정서 없음"},{status:404});
      return Response.json({ok:true,agreement:JSON.parse(await o.text())});
    }
    if(url.pathname==="/api/sm-instructor-agreement"&&request.method==="POST"){
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{
        const o=await env.IMAGES.get("system/instructors.json"),rows=o?JSON.parse(await o.text()):[];
        if(!member.memberNo||!rows.some(x=>String(x.memberNo||"").trim()===String(member.memberNo).trim()))return Response.json({ok:false,error:"F방에 등록된 강사회원만 제출할 수 있습니다."},{status:403});
        const d=await request.json();const signature=String(d.signature||"");
        if(d.agreed!==true||!signature.startsWith("data:image/png;base64,")||signature.length>500000)return Response.json({ok:false,error:"약정 동의 및 서명을 확인해 주세요."},{status:400});
        const id=crypto.randomUUID(),record={id,memberId:member.id,memberNo:member.memberNo,name:member.name||"",version:"sm-instructor-2026-10-10",clauses:d.clauses,agreed:true,signature,submittedAt:new Date().toISOString()};
        if(!Array.isArray(record.clauses)||record.clauses.length!==10)return Response.json({ok:false,error:"약정서 내용이 올바르지 않습니다."},{status:400});
        await env.IMAGES.put("system/sm-instructor-agreements/"+id+".json",JSON.stringify(record),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true,id});
      }catch(e){return Response.json({ok:false,error:"약정서 저장에 실패했습니다."},{status:500})}
    }
    if (url.pathname === "/api/sm-instructor-applications" && request.method === "POST") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{const d=await request.json(),id=String(d.agreementId||"");
        if(!/^[0-9a-f-]{36}$/.test(id))return Response.json({ok:false,error:"강사 이용 약정서를 먼저 제출해 주세요."},{status:400});
        const o=await env.IMAGES.get("system/instructor-agreements/"+id+".json");if(!o)return Response.json({ok:false,error:"강사 약정서 접수 내역이 없습니다."},{status:404});
        const agreement=JSON.parse(await o.text());if(String(agreement.memberId)!==String(member.id))return Response.json({ok:false,error:"본인의 약정서만 사용할 수 있습니다."},{status:403});
        const fields=["experience","strengths","motivation"];if(fields.some(k=>!String(d[k]||"").trim()||String(d[k]).length>3000))return Response.json({ok:false,error:"자기소개 항목을 모두 작성해 주세요(각 3000자 이내). "},{status:400});
        const row={id:crypto.randomUUID(),agreementId:id,memberId:member.id,memberNo:member.memberNo||"",name:agreement.name,experience:String(d.experience).trim(),strengths:String(d.strengths).trim(),motivation:String(d.motivation).trim(),status:"pending",submittedAt:new Date().toISOString()};
        await env.IMAGES.put("system/sm-instructor-applications/"+row.id+".json",JSON.stringify(row),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true,id:row.id});
      }catch(e){return Response.json({ok:false,error:"신청 저장에 실패했습니다."},{status:500})}
    }
    if (url.pathname === "/api/instructor-agreement" && request.method === "POST") {
      try {
        const member=await sessionMember();
        if(!member)return Response.json({ok:false,error:"로그인 후 제출할 수 있습니다."},{status:401});
        const form=await request.formData();
        const get=k=>String(form.get(k)||"").trim();
        const name=get("name"),phone=get("phone"),address=get("address"),organization=get("organization"),instructorNo=get("instructorNo"),birthDate=get("birthDate"),signature=get("signature");
        if(!name||!phone||!address||!/^[0-9]{6}-[1-4]$/.test(get("identity7"))||!signature.startsWith("data:image/png;base64,"))return Response.json({ok:false,error:"필수 입력사항과 서명을 확인해 주세요."},{status:400});
        if(signature.length>500000)return Response.json({ok:false,error:"서명 이미지가 너무 큽니다."},{status:413});
        const insurance=form.get("insurance");if(!insurance||typeof insurance==="string"||!insurance.size)return Response.json({ok:false,error:"책임보험 가입증명서를 첨부해 주세요."},{status:400});const files=[...form.getAll("attachments"),insurance];if(!files.some(f=>f&&typeof f!=="string"&&f.size))return Response.json({ok:false,error:"강사 자격증 및 책임보험 가입증명서를 첨부해 주세요."},{status:400});if(files.length>5)return Response.json({ok:false,error:"첨부파일은 최대 5개입니다."},{status:400});
        const id=crypto.randomUUID(),attachments=[];
        for(const file of files){
          if(!file||typeof file==="string"||!file.size)continue;
          if(file.size>5*1024*1024)return Response.json({ok:false,error:"첨부파일은 개당 5MB 이하로 등록해 주세요."},{status:413});
          if(!["image/jpeg","image/png"].includes(file.type))return Response.json({ok:false,error:"첨부파일은 JPG, PNG만 가능합니다."},{status:415});
          const ext={"image/jpeg":"jpg","image/png":"png"}[file.type];
          const key="instructor-agreements/"+id+"/"+crypto.randomUUID()+"."+ext;
          await env.IMAGES.put(key,await file.arrayBuffer(),{httpMetadata:{contentType:file.type}});
          attachments.push({name:String(file.name||"").slice(0,150),key,type:file.type,size:file.size});
        }
        const row={id,name:name.slice(0,100),phone:phone.slice(0,50),address:address.slice(0,300),birthDate:birthDate.slice(0,20),identity7:get("identity7").slice(0,8),organization:organization.slice(0,150),instructorNo:instructorNo.slice(0,100),attachments,signature,agreementVersion:"2026-10-10",memberNo:member.memberNo||"",memberId:member.id||"",submittedAt:new Date().toISOString()};
        await env.IMAGES.put("system/instructor-agreements/"+id+".json",JSON.stringify(row),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true,id});
      }catch(e){return Response.json({ok:false,error:"약정서 저장에 실패했습니다."},{status:500})}
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
    if (url.pathname === "/api/instructor-waivers" && request.method === "GET") {
      const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
      try{
        const io=await env.IMAGES.get("system/instructors.json"),instructors=io?JSON.parse(await io.text()):[],no=String(member.memberNo||""),inst=instructors.find(x=>String(x.memberNo||"")===no);
        if(!inst)return Response.json({ok:true,isInstructor:false,waivers:[]});
        const name=String(inst.name||"").trim(),rows=await readWaivers();
        const waivers=rows.filter(x=>x.waiverCode==="D-2"&&((x.instructorMemberNo&&String(x.instructorMemberNo)===no)||(!x.instructorMemberNo&&name&&String(x.instructorName||"").trim()===name))).sort((a,b)=>String(b.lessonDate||"").localeCompare(String(a.lessonDate||"")));
        return Response.json({ok:true,isInstructor:true,waivers});
      }catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
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

    // License uploads are needed before signup as well as by signed-in members.
    // Keep the generic image-upload endpoint admin-only.
    if (url.pathname === "/api/member/license-image" && request.method === "POST") {
      try {
        const form=await request.formData(),file=form.get("file");
        if(!file||typeof file==="string")return Response.json({ok:false,error:"이미지 파일이 없습니다."},{status:400});
        if(file.size>3145728)return Response.json({ok:false,error:"파일당 최대 3MB까지 업로드할 수 있습니다."},{status:413});
        const extMap={"image/jpeg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"};
        if(!Object.prototype.hasOwnProperty.call(extMap,file.type))return Response.json({ok:false,error:"JPG, PNG, WEBP, GIF 이미지만 업로드할 수 있습니다."},{status:415});
        const key="member-licenses/"+new Date().toISOString().slice(0,10)+"/"+crypto.randomUUID()+"."+extMap[file.type];
        await env.IMAGES.put(key,file.stream(),{httpMetadata:{contentType:file.type}});
        return Response.json({ok:true,url:"https://pub-8216b63561af42ecb148b7864ed54e6b.r2.dev/"+key});
      }catch(e){return Response.json({ok:false,error:"자격증 이미지 업로드 실패: "+(e?.message||String(e))},{status:500})}
    }

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
        if(!valid)return Response.json({ok:false,error:"관리자 ID 또는 비밀번호가 서버에 등록된 정보와 일치하지 않습니다. (로그인 인증 401)"},{status:401});
        const token=crypto.randomUUID()+crypto.randomUUID().replaceAll("-",""),expiresAt=Date.now()+12*60*60*1000;
        await env.IMAGES.put("system/admin-sessions/"+token+".json",JSON.stringify({expiresAt}),{httpMetadata:{contentType:"application/json"}});
        return Response.json({ok:true},{headers:{"Set-Cookie":"submarine_admin="+token+"; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200"}});
      } catch { return Response.json({ok:false},{status:400}); }
    }
    async function readIndependentPosts(){let rows=[];try{const o=await env.IMAGES.get("system/independent-posts.json");if(o)rows=JSON.parse(await o.text())}catch{}return Array.isArray(rows)?rows:[]}
    async function writeIndependentPosts(rows){await env.IMAGES.put("system/independent-posts.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    async function readTourPosts(){let rows=[];try{const o=await env.IMAGES.get("system/tour-posts.json");if(o)rows=JSON.parse(await o.text())}catch{}return Array.isArray(rows)?rows:[]}
    async function writeTourPosts(rows){await env.IMAGES.put("system/tour-posts.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    async function readCommunityReports(){let rows=[];try{const o=await env.IMAGES.get("system/community-reports.json");if(o)rows=JSON.parse(await o.text())}catch{}return Array.isArray(rows)?rows:[]}
    async function writeCommunityReports(rows){await env.IMAGES.put("system/community-reports.json",JSON.stringify(rows.slice(0,2000)),{httpMetadata:{contentType:"application/json"}})}
    async function readCommunityBlocks(){let rows={};try{const o=await env.IMAGES.get("system/community-blocks.json");if(o)rows=JSON.parse(await o.text())}catch{}return rows&&typeof rows==="object"&&!Array.isArray(rows)?rows:{}}
    async function writeCommunityBlocks(rows){await env.IMAGES.put("system/community-blocks.json",JSON.stringify(rows),{httpMetadata:{contentType:"application/json"}})}
    function communityMemberKey(m){return String(m?.memberNo||m?.id||"")}
    function communityTextAllowed(...values){const t=values.map(v=>String(v||"").toLowerCase().replace(/\s+/g,"")).join(" ");const banned=["포르노","야동","강간","성폭행","살인예고","테러예고","마약판매","필로폰판매","대마판매","porn","rape","terrorattack","methforsale"];return !banned.some(x=>t.includes(x))}
    async function communityViewer(){const member=await sessionMember(),key=communityMemberKey(member),all=await readCommunityBlocks();return {member,key,blocked:new Set(Array.isArray(all[key])?all[key].map(String):[])}}
    function publicIndependentPost(p,key,blocked){const own=!!key&&String(p.authorKey||"")===key,joined=!!key&&(p.participants||[]).some(x=>String(x.key||"")===key),q={...p,viewerOwn:own,viewerJoined:joined};delete q.authorKey;q.participants=own?(p.participants||[]).filter(x=>!blocked.has(String(x.key||""))).map(x=>({name:x.name||"회원"})):[];q.comments=(p.comments||[]).filter(x=>!blocked.has(String(x.authorKey||""))).map(x=>({id:x.id,name:x.name||"회원",text:x.text||"",createdAt:x.createdAt,mine:!!key&&String(x.authorKey||"")===key}));q.secretComments=(own||joined)?(p.secretComments||[]).filter(x=>!blocked.has(String(x.authorKey||""))).map(x=>({id:x.id,name:x.name||"회원",text:x.text||"",createdAt:x.createdAt,mine:!!key&&String(x.authorKey||"")===key})):[];return q}
    function publicTourPost(p,key,blocked){const own=!!key&&String(p.authorKey||"")===key,q={...p,viewerOwn:own};delete q.authorKey;const all=Array.isArray(p.comments)?p.comments:[];q.comments=all.filter(x=>!blocked.has(String(x.authorKey||""))).map(x=>{const mine=!!key&&String(x.authorKey||"")===key,visible=!x.secret||mine||own;return {id:x.id,parentId:x.parentId||"",text:visible?(x.text||""):"",secret:!!x.secret,secretVisible:visible,author:x.author||"회원",createdAt:x.createdAt,mine}});return q}
    async function communityTarget(board,postId,commentId=""){const rows=board==="independent"?await readIndependentPosts():board==="tour"?await readTourPosts():[];const post=rows.find(x=>String(x.id)===String(postId));if(!post)return null;if(!commentId)return {post,targetKey:String(post.authorKey||""),targetName:post.author||"회원",contentType:"post",contentText:(post.title||"")+" "+(post.body||"")};const pools=board==="independent"?[...(post.comments||[]),...(post.secretComments||[])]:[...(post.comments||[])];const comment=pools.find(x=>String(x.id)===String(commentId));if(!comment)return null;return {post,comment,targetKey:String(comment.authorKey||""),targetName:comment.author||comment.name||"회원",contentType:"comment",contentText:comment.text||""}}
    async function resolveCommunityReportsForPost(board,postId){const rows=await readCommunityReports();let changed=false;for(const r of rows)if(r.board===board&&String(r.postId)===String(postId)&&r.status==="open"){r.status="resolved";r.resolvedAt=new Date().toISOString();changed=true}if(changed)await writeCommunityReports(rows)}
    async function appendAdminBoardLog(entry){const key="system/admin-board-log.json";let rows=[];try{const o=await env.IMAGES.get(key);if(o)rows=JSON.parse(await o.text())}catch{}rows.unshift({...entry,at:new Date().toISOString()});await env.IMAGES.put(key,JSON.stringify(rows.slice(0,500)),{httpMetadata:{contentType:"application/json"}})}

    if(url.pathname==="/api/community/report"&&request.method==="POST"){try{const m=await sessionMember();if(!m)return Response.json({ok:false,error:"로그인 후 신고할 수 있습니다."},{status:401});const d=await request.json(),board=d.board==="independent"?"independent":d.board==="tour"?"tour":"",reason=String(d.reason||"").trim().slice(0,500),reporterKey=communityMemberKey(m);if(!board||!d.postId||reason.length<2)return Response.json({ok:false,error:"신고 사유를 입력해 주세요."},{status:400});const target=await communityTarget(board,d.postId,d.commentId||"");if(!target)return Response.json({ok:false,error:"신고 대상을 찾을 수 없습니다."},{status:404});if(!target.targetKey||target.targetKey===reporterKey)return Response.json({ok:false,error:"본인 콘텐츠는 신고할 수 없습니다."},{status:400});const rows=await readCommunityReports();if(rows.some(x=>x.status==="open"&&x.board===board&&String(x.postId)===String(d.postId)&&String(x.commentId||"")===String(d.commentId||"")&&x.reporterKey===reporterKey))return Response.json({ok:true,duplicate:true});rows.unshift({id:crypto.randomUUID(),status:"open",board,postId:String(d.postId),commentId:String(d.commentId||""),contentType:target.contentType,targetKey:target.targetKey,targetName:target.targetName,contentText:String(target.contentText||"").slice(0,1000),reporterKey,reporterName:m.name||"회원",reason,createdAt:new Date().toISOString()});await writeCommunityReports(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/community/block"&&request.method==="POST"){try{const m=await sessionMember();if(!m)return Response.json({ok:false,error:"로그인 후 차단할 수 있습니다."},{status:401});const d=await request.json(),board=d.board==="independent"?"independent":d.board==="tour"?"tour":"",key=communityMemberKey(m);if(!board||!d.postId)return Response.json({ok:false,error:"차단 대상을 확인해 주세요."},{status:400});const target=await communityTarget(board,d.postId,d.commentId||"");if(!target)return Response.json({ok:false,error:"차단 대상을 찾을 수 없습니다."},{status:404});if(!target.targetKey||target.targetKey===key)return Response.json({ok:false,error:"본인은 차단할 수 없습니다."},{status:400});const all=await readCommunityBlocks(),set=new Set(Array.isArray(all[key])?all[key].map(String):[]);set.add(target.targetKey);all[key]=[...set].slice(0,500);await writeCommunityBlocks(all);return Response.json({ok:true,targetName:target.targetName})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/community/blocks"&&request.method==="DELETE"){try{const m=await sessionMember();if(!m)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});const d=await request.json(),key=communityMemberKey(m),all=await readCommunityBlocks();all[key]=(Array.isArray(all[key])?all[key]:[]).filter(x=>String(x)!==String(d.targetKey||""));await writeCommunityBlocks(all);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if(url.pathname==="/api/independent"&&request.method==="GET"){const v=await communityViewer(),rows=(await readIndependentPosts()).filter(p=>!v.blocked.has(String(p.authorKey||""))).map(p=>publicIndependentPost(p,v.key,v.blocked));return Response.json({ok:true,posts:rows})}
    if(url.pathname==="/api/independent"&&request.method==="POST"){try{const m=await sessionMember();if(!m)return Response.json({ok:false,error:"로그인 후 모집글을 작성할 수 있습니다."},{status:401});const d=await request.json(),pool=String(d.pool||"").trim().slice(0,50),title=String(d.title||"").trim().slice(0,40),body=String(d.body||"").slice(0,1000);if(!pool||!d.date||!d.time||!title)return Response.json({ok:false,error:"풀장 · 날짜 · 시간 · 제목을 입력해 주세요."},{status:400});if(!communityTextAllowed(title,body))return Response.json({ok:false,error:"커뮤니티 운영정책상 등록할 수 없는 표현이 포함되어 있습니다."},{status:400});const rows=await readIndependentPosts(),p={id:crypto.randomUUID(),createdAt:new Date().toISOString(),pool,poolType:d.poolType==="general"?"general":"deep",region:String(d.region||"").slice(0,40),depth:String(d.depth||"").slice(0,20),date:String(d.date),time:String(d.time),title,body,current:1,max:Math.max(2,Math.min(20,Number(d.max)||4)),status:"open",author:m.name||"회원",authorKey:communityMemberKey(m),participants:[],comments:[],secretComments:[]};rows.unshift(p);await writeIndependentPosts(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/independent/action"&&request.method==="POST"){try{const m=await sessionMember();if(!m)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});const d=await request.json(),rows=await readIndependentPosts(),p=rows.find(x=>String(x.id)===String(d.postId)),key=communityMemberKey(m);if(!p)return Response.json({ok:false,error:"모집글을 찾을 수 없습니다."},{status:404});p.participants=Array.isArray(p.participants)?p.participants:[];p.comments=Array.isArray(p.comments)?p.comments:[];p.secretComments=Array.isArray(p.secretComments)?p.secretComments:[];if(d.action==="join"){if(!p.participants.some(x=>String(x.key)===key)&&p.status==="open"&&Number(p.current)<Number(p.max)){p.participants.push({key,name:m.name||"회원"});p.current=Number(p.current||1)+1;if(p.current>=p.max)p.status="full"}}else if(d.action==="cancelJoin"){p.participants=p.participants.filter(x=>String(x.key)!==key);p.current=Math.max(1,1+p.participants.length);if(p.status==="full"&&p.current<p.max)p.status="open"}else if(d.action==="close"){if(String(p.authorKey)!==key)return Response.json({ok:false,error:"작성자만 모집을 취소할 수 있습니다."},{status:403});p.status="closed"}else if(d.action==="comment"){const text=String(d.text||"").trim().slice(0,300);if(text&&!communityTextAllowed(text))return Response.json({ok:false,error:"커뮤니티 운영정책상 등록할 수 없는 표현이 포함되어 있습니다."},{status:400});if(text)p.comments.push({id:crypto.randomUUID(),authorKey:key,name:m.name||"회원",text,createdAt:new Date().toISOString()})}else if(d.action==="secret"){const text=String(d.text||"").trim().slice(0,300),joined=p.participants.some(x=>String(x.key)===key);if(String(p.authorKey)!==key&&!joined)return Response.json({ok:false,error:"참가자와 모집자만 이용할 수 있습니다."},{status:403});if(text&&!communityTextAllowed(text))return Response.json({ok:false,error:"커뮤니티 운영정책상 등록할 수 없는 표현이 포함되어 있습니다."},{status:400});if(text)p.secretComments.push({id:crypto.randomUUID(),authorKey:key,name:m.name||"회원",text,createdAt:new Date().toISOString()})}else if(d.action==="deleteComment"){const i=p.comments.findIndex(x=>String(x.id)===String(d.commentId)&&String(x.authorKey)===key);if(i>=0)p.comments.splice(i,1)}await writeIndependentPosts(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if(url.pathname==="/api/admin/community"&&request.method==="GET"){const denied=await requireAdmin();if(denied)return denied;let logs=[];try{const o=await env.IMAGES.get("system/admin-board-log.json");if(o)logs=JSON.parse(await o.text())}catch{}return Response.json({ok:true,independent:await readIndependentPosts(),tours:await readTourPosts(),reports:await readCommunityReports(),logs:Array.isArray(logs)?logs:[]})}
    if(url.pathname==="/api/admin/community/report"&&request.method==="POST"){const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readCommunityReports(),r=rows.find(x=>String(x.id)===String(d.id));if(!r)return Response.json({ok:false,error:"신고내역을 찾을 수 없습니다."},{status:404});r.status=d.status==="dismissed"?"dismissed":"resolved";r.resolvedAt=new Date().toISOString();await writeCommunityReports(rows);await appendAdminBoardLog({board:r.board,action:"report-"+r.status,postId:r.postId,title:r.contentText,author:r.targetName});return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/admin/community/independent"&&request.method==="POST"){const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readIndependentPosts(),p=rows.find(x=>String(x.id)===String(d.postId));if(!p)return Response.json({ok:false,error:"게시글을 찾을 수 없습니다."},{status:404});if(d.action==="close"){p.status="closed";await writeIndependentPosts(rows);await appendAdminBoardLog({board:"independent",action:"close",postId:p.id,title:p.title,author:p.author,authorKey:p.authorKey});return Response.json({ok:true})}if(d.action==="deleteComment"){p.comments=Array.isArray(p.comments)?p.comments:[];const i=p.comments.findIndex(x=>String(x.id)===String(d.commentId));if(i<0)return Response.json({ok:false,error:"댓글을 찾을 수 없습니다."},{status:404});const removed=p.comments.splice(i,1)[0];await writeIndependentPosts(rows);await appendAdminBoardLog({board:"independent",action:"deleteComment",postId:p.id,title:p.title,author:removed.name,commentText:removed.text});return Response.json({ok:true})}if(d.action==="delete"){await appendAdminBoardLog({board:"independent",action:"delete",postId:p.id,title:p.title,author:p.author,authorKey:p.authorKey,body:p.body});await writeIndependentPosts(rows.filter(x=>String(x.id)!==String(p.id)));await resolveCommunityReportsForPost("independent",p.id);return Response.json({ok:true})}return Response.json({ok:false,error:"지원하지 않는 작업입니다."},{status:400})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/admin/community/tour"&&request.method==="POST"){const denied=await requireAdmin();if(denied)return denied;try{const d=await request.json(),rows=await readTourPosts(),p=rows.find(x=>String(x.id)===String(d.postId));if(!p)return Response.json({ok:false,error:"게시글을 찾을 수 없습니다."},{status:404});if(d.action==="close"){p.status="마감";await writeTourPosts(rows);await appendAdminBoardLog({board:"tour",action:"close",postId:p.id,title:p.title,author:p.author,authorKey:p.authorKey});return Response.json({ok:true})}if(d.action==="deleteComment"){p.comments=Array.isArray(p.comments)?p.comments:[];const i=p.comments.findIndex(x=>String(x.id)===String(d.commentId));if(i<0)return Response.json({ok:false,error:"댓글을 찾을 수 없습니다."},{status:404});const removed=p.comments[i],childIds=new Set([String(removed.id)]);let changed=true;while(changed){changed=false;for(const x of p.comments)if(childIds.has(String(x.parentId))&&!childIds.has(String(x.id))){childIds.add(String(x.id));changed=true}}p.comments=p.comments.filter(x=>!childIds.has(String(x.id)));await writeTourPosts(rows);await appendAdminBoardLog({board:"tour",action:"deleteComment",postId:p.id,title:p.title,author:removed.author,commentText:removed.text});return Response.json({ok:true})}if(d.action==="delete"){await appendAdminBoardLog({board:"tour",action:"delete",postId:p.id,title:p.title,author:p.author,authorKey:p.authorKey,body:p.body,images:p.images});await writeTourPosts(rows.filter(x=>String(x.id)!==String(p.id)));await resolveCommunityReportsForPost("tour",p.id);return Response.json({ok:true})}return Response.json({ok:false,error:"지원하지 않는 작업입니다."},{status:400})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}

    if(url.pathname==="/api/tours"&&request.method==="GET"){const v=await communityViewer(),rows=(await readTourPosts()).filter(p=>!v.blocked.has(String(p.authorKey||""))).map(p=>publicTourPost(p,v.key,v.blocked));return Response.json({ok:true,posts:rows})}
    if(url.pathname==="/api/tours"&&request.method==="POST"){try{const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인 후 모집글을 작성할 수 있습니다."},{status:401});const d=await request.json(),title=String(d.title||"").trim().slice(0,120),place=String(d.place||"").trim().slice(0,80),body=String(d.body||"").trim().slice(0,30000),type=d.type==="overseas"?"overseas":"domestic",capacity=Math.max(1,Math.min(100,Number(d.capacity)||1)),images=Array.isArray(d.images)?d.images.map(String).filter(x=>/^https:\/\//.test(x)).slice(0,3):[];if(!title||!place||!d.startDate||!d.endDate)return Response.json({ok:false,error:"제목, 여행지, 일정을 입력해 주세요."},{status:400});if(!communityTextAllowed(title,body))return Response.json({ok:false,error:"커뮤니티 운영정책상 등록할 수 없는 표현이 포함되어 있습니다."},{status:400});const rows=await readTourPosts(),post={id:crypto.randomUUID(),type,title,place,startDate:String(d.startDate),endDate:String(d.endDate),capacity,joined:0,status:"모집중",divingType:String(d.divingType||"").slice(0,60),level:String(d.level||"").slice(0,80),body,images,author:member.name||"회원",authorKey:communityMemberKey(member),createdAt:new Date().toISOString(),comments:[]};rows.unshift(post);await writeTourPosts(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/tours/edit"&&request.method==="POST"){try{const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});const d=await request.json(),rows=await readTourPosts(),p=rows.find(x=>String(x.id)===String(d.id)),key=communityMemberKey(member),title=String(d.title||"").trim().slice(0,120),body=String(d.body||"").slice(0,30000);if(!p)return Response.json({ok:false,error:"모집글을 찾을 수 없습니다."},{status:404});if(String(p.authorKey)!==key)return Response.json({ok:false,error:"작성자만 수정할 수 있습니다."},{status:403});if(!communityTextAllowed(title,body))return Response.json({ok:false,error:"커뮤니티 운영정책상 등록할 수 없는 표현이 포함되어 있습니다."},{status:400});p.title=title;p.place=String(d.place||"").trim().slice(0,80);p.startDate=String(d.startDate||"");p.endDate=String(d.endDate||"");p.capacity=Math.max(1,Math.min(100,Number(d.capacity)||1));p.divingType=String(d.divingType||"").slice(0,60);p.level=String(d.level||"").slice(0,80);p.body=body;if(Array.isArray(d.images))p.images=d.images.map(String).filter(x=>/^https:\/\//.test(x)).slice(0,3);p.updatedAt=new Date().toISOString();await writeTourPosts(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/tours/delete"&&request.method==="POST"){try{const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});const d=await request.json(),rows=await readTourPosts(),i=rows.findIndex(x=>String(x.id)===String(d.id)),key=communityMemberKey(member);if(i<0)return Response.json({ok:false,error:"모집글을 찾을 수 없습니다."},{status:404});if(String(rows[i].authorKey)!==key)return Response.json({ok:false,error:"작성자만 삭제할 수 있습니다."},{status:403});const id=rows[i].id;rows.splice(i,1);await writeTourPosts(rows);await resolveCommunityReportsForPost("tour",id);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/tours/comment"&&request.method==="POST"){try{const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인 후 댓글을 작성할 수 있습니다."},{status:401});const d=await request.json(),text=String(d.text||"").trim().slice(0,1000);if(!text)return Response.json({ok:false,error:"댓글을 입력해 주세요."},{status:400});if(!communityTextAllowed(text))return Response.json({ok:false,error:"커뮤니티 운영정책상 등록할 수 없는 표현이 포함되어 있습니다."},{status:400});const rows=await readTourPosts(),p=rows.find(x=>String(x.id)===String(d.postId));if(!p)return Response.json({ok:false,error:"모집글을 찾을 수 없습니다."},{status:404});p.comments=Array.isArray(p.comments)?p.comments:[];const parentId=String(d.parentId||"");if(parentId&&!p.comments.some(x=>String(x.id)===parentId))return Response.json({ok:false,error:"답글 대상 댓글을 찾을 수 없습니다."},{status:404});p.comments.push({id:crypto.randomUUID(),parentId,text,secret:!!d.secret,author:member.name||"회원",authorKey:communityMemberKey(member),createdAt:new Date().toISOString()});await writeTourPosts(rows);return Response.json({ok:true})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if(url.pathname==="/api/tours/image"&&request.method==="POST"){try{const member=await sessionMember();if(!member)return Response.json({ok:false,error:"로그인 후 이미지를 올릴 수 있습니다."},{status:401});const form=await request.formData(),file=form.get("file");if(!file||typeof file==="string")return Response.json({ok:false,error:"이미지 파일이 없습니다."},{status:400});if(file.size>5242880)return Response.json({ok:false,error:"파일당 최대 5MB입니다."},{status:413});if(!file.type||!file.type.startsWith("image/"))return Response.json({ok:false,error:"이미지 파일만 가능합니다."},{status:415});const ext=({"image/jpeg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif"})[file.type]||"img",key="uploads/tours/"+new Date().toISOString().slice(0,10)+"/"+crypto.randomUUID()+"."+ext;await env.IMAGES.put(key,file.stream(),{httpMetadata:{contentType:file.type}});return Response.json({ok:true,url:"https://pub-8216b63561af42ecb148b7864ed54e6b.r2.dev/"+key})}catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}}
    if (url.pathname === "/api/admin-session" && request.method === "GET") {
      return Response.json({ok:await adminSessionValid()},{status:await adminSessionValid()?200:401});
    }
    if (url.pathname === "/api/admin-logout" && request.method === "POST") {
      const cookie=request.headers.get("Cookie")||"",token=(cookie.match(/(?:^|;\s*)submarine_admin=([^;]+)/)||[])[1];if(token)try{await env.IMAGES.delete("system/admin-sessions/"+token+".json")}catch{}
      return Response.json({ok:true},{headers:{"Set-Cookie":"submarine_admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"}});
    }

    // Public, server-rendered education pages: existing R2 book text, no duplicate content store.
    if (request.method === "GET" && (url.pathname.startsWith("/academy/") || url.pathname === "/sitemap.xml")) {
      const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
      const escapeXml = escapeHtml;
      let posts = [];
      try {
        const obj = await env.IMAGES.get("system/education-posts.json");
        if (obj) posts = JSON.parse(await obj.text()).filter(p => p && p.published !== false && String(p.title || "").trim() && String(p.title || "").trim() !== "한 줄, 상위 카테고리");
      } catch {}
      if (url.pathname === "/sitemap.xml") {
        const paths = ["/", "/freediving.html", ...posts.filter(p => /^[a-zA-Z0-9_-]{1,120}$/.test(String(p.id || ""))).map(p => "/academy/" + encodeURIComponent(String(p.id)))];
        const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + paths.map(p => "  <url><loc>https://submarine.asia" + escapeXml(p) + "</loc></url>").join("\n") + "\n</urlset>";
        return new Response(xml, {headers: {"Content-Type":"application/xml; charset=utf-8","Cache-Control":"public, max-age=1800"}});
      }
      const id = decodeURIComponent(url.pathname.slice("/academy/".length));
      const post = posts.find(p => String(p.id) === id);
      if (!post || !/^[a-zA-Z0-9_-]{1,120}$/.test(id)) return new Response("교육자료를 찾을 수 없습니다.", {status:404,headers:{"Content-Type":"text/plain; charset=utf-8"}});
      const title = escapeHtml(post.title), category = escapeHtml(post.category || "교육자료"), canonical = "https://submarine.asia/academy/" + encodeURIComponent(id);
      const description = escapeHtml(String(post.bodyHtml || "").replace(/<[^>]*>/g," ").replace(/&nbsp;/g," ").replace(/\s+/g," ").trim().slice(0,155) || String(post.title));
      const body = String(post.bodyHtml || "").replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi,"").replace(/\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi,"").replace(/javascript\s*:/gi,"");
      const html = '<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + title + ' | 서브마린 교육자료실</title><meta name="description" content="' + description + '"><meta name="robots" content="index,follow"><link rel="canonical" href="' + canonical + '"><style>body{margin:0;background:#f7fafc;color:#20313d;font:16px/1.85 system-ui,-apple-system,sans-serif}header,main,footer{max-width:860px;margin:auto;padding:20px}main{background:#fff;padding:28px;border-radius:14px}h1{line-height:1.4;color:#155b88}h2,h3{color:#1769aa}img{max-width:100%;height:auto}a{color:#1769aa}.cta{display:inline-block;margin:16px 10px 16px 0;padding:10px 18px;background:#1769aa;color:white;border-radius:8px;text-decoration:none}@media(max-width:600px){main{padding:18px;border-radius:0}}</style></head><body><header><a href="/">서브마린 다이빙풀</a> · <a href="/?library=freediving">교육자료실</a></header><main><small>' + category + '</small><h1>' + title + '</h1>' + (post.image ? '<img src="' + escapeHtml(post.image) + '" alt="' + title + '">' : '') + '<article>' + body + '</article><a class="cta" href="/?library=freediving">교육자료 더 보기</a><a class="cta" href="/?view=schedule">다이빙풀 예약 안내</a></main><footer>서브마린 다이빙풀 · 경기도 부천시 경인로 459</footer></body></html>';
      return new Response(html, {headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"public, max-age=300","X-Content-Type-Options":"nosniff"}});
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
