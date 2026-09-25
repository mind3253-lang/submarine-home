export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    async function saveMember(member) {
      const key = "system/members.json";
      let members = [];
      try { const o = await env.IMAGES.get(key); if (o) members = JSON.parse(await o.text()); } catch {}
      const now = new Date().toISOString();
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
        const member={provider:"kakao",id:String(profile.id),name:p.nickname||"카카오 회원",email:account.email||"",phone:account.phone_number||""};
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

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      try {
        const cookie=request.headers.get("Cookie")||"", raw=(cookie.match(/(?:^|;\\s*)submarine_session=([^;]+)/)||[])[1];
        if(!raw) return Response.json({ok:false},{status:401});
        const [payload,sig]=raw.split(".");
        const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.NAVER_CLIENT_SECRET),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
        const pad=sig.replaceAll("-","+").replaceAll("_","/") + "=".repeat((4-sig.length%4)%4);
        const bytes=Uint8Array.from(atob(pad),c=>c.charCodeAt(0));
        const valid=await crypto.subtle.verify("HMAC",key,bytes,new TextEncoder().encode(payload));
        if(!valid) return Response.json({ok:false},{status:401});
        const pp=payload.replaceAll("-","+").replaceAll("_","/") + "=".repeat((4-payload.length%4)%4);
        const member=JSON.parse(decodeURIComponent(escape(atob(pp))));
        return Response.json({ok:true,member});
      } catch { return Response.json({ok:false},{status:401}); }
    }

    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      return Response.json({ok:true},{headers:{"Set-Cookie":"submarine_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}});
    }

    if (url.pathname === "/api/admin/members" && request.method === "GET") {
      try {
        const o = await env.IMAGES.get("system/members.json");
        const members = o ? JSON.parse(await o.text()) : [];
        return Response.json({ok:true,members});
      } catch(e) {
        return Response.json({ok:false,error:e?.message||String(e)},{status:500});
      }
    }

    if (url.pathname === "/api/member/withdraw" && request.method === "POST") {
      try {
        const cookie=request.headers.get("Cookie")||"", raw=(cookie.match(/(?:^|;\s*)submarine_session=([^;]+)/)||[])[1];
        if(!raw) return Response.json({ok:false,error:"로그인이 필요합니다."},{status:401});
        const [payload]=raw.split(".");
        const pp=payload.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-payload.length%4)%4);
        const member=JSON.parse(decodeURIComponent(escape(atob(pp))));
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
      const cutoff = Date.now() - 365 * 24 * 60 * 60 * 1000;
      const kept = rows.filter(x => x.hold === true || new Date(x.submittedAt || 0).getTime() >= cutoff);
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
        if(!["D-1","D-2"].includes(data.waiverCode)||!data.lessonDate||!data.lessonTime||!data.signatureData) return Response.json({ok:false,error:"약정서 제출정보가 부족합니다."},{status:400});
        const rows=await readWaivers(), now=new Date().toISOString();
        const row={id:crypto.randomUUID(),waiverCode:data.waiverCode,lessonDate:data.lessonDate,lessonTime:data.lessonTime,educationLevel:data.waiverCode==="D-2"?String(data.educationLevel||""):"",memberName:member.name||"회원",provider:member.provider||"",memberId:member.id||"",agreementHtml:String(data.agreementHtml||"").slice(0,200000),signatureData:String(data.signatureData||"").slice(0,500000),submittedAt:now,hold:false};
        rows.push(row); await writeWaivers(rows);
        return Response.json({ok:true,id:row.id});
      } catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/admin/waivers" && request.method === "GET") {
      try { return Response.json({ok:true,waivers:await readWaivers()}); }
      catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }
    if (url.pathname === "/api/admin/waivers/hold" && request.method === "POST") {
      try {
        const data=await request.json(), rows=await readWaivers(), x=rows.find(v=>v.id===data.id);
        if(!x) return Response.json({ok:false,error:"약정서를 찾을 수 없습니다."},{status:404});
        x.hold=!!data.hold; x.holdUpdatedAt=new Date().toISOString(); await writeWaivers(rows);
        return Response.json({ok:true,hold:x.hold});
      } catch(e){return Response.json({ok:false,error:e?.message||String(e)},{status:500})}
    }

    if (url.pathname === "/api/upload-image" && request.method === "POST") {
      try {
        const form = await request.formData();
        const file = form.get("file");
        if (!file || typeof file === "string") {
          return Response.json({ ok: false, error: "이미지 파일이 없습니다." }, { status: 400 });
        }
        if (file.size > 2621440) {
          return Response.json({ ok: false, error: "파일당 최대 2.5MB까지 업로드할 수 있습니다." }, { status: 413 });
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

    if (url.pathname === "/api/admin-login" && request.method === "POST") {
      try {
        const data = await request.json();
        const configured = env.ADMIN_PASSWORD;
        if (!configured) {
          return Response.json({ ok: false, reason: "PASSWORD_NOT_CONFIGURED" }, { status: 503 });
        }
        const valid = data.id === "submarine" && String(data.password) === String(configured);
        return Response.json({ ok: valid }, { status: valid ? 200 : 401 });
      } catch {
        return Response.json({ ok: false, reason: "BAD_REQUEST" }, { status: 400 });
      }
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