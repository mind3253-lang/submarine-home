#!/usr/bin/env python3
import os, json, time, hashlib, urllib.request, urllib.parse, urllib.error
import jwt

BASE="https://api.appstoreconnect.apple.com"
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG=json.load(open(os.path.join(ROOT,"appstore","metadata.json"),encoding="utf-8"))
STATUS=[]

def log(msg):
    print(msg, flush=True); STATUS.append(msg)

def token():
    now=int(time.time())
    payload={"iss":os.environ["ASC_ISSUER_ID"],"iat":now,"exp":now+1100,"aud":"appstoreconnect-v1"}
    return jwt.encode(payload,os.environ["ASC_PRIVATE_KEY"],algorithm="ES256",headers={"kid":os.environ["ASC_KEY_ID"],"typ":"JWT"})

def asc(method,path,body=None,ok=(200,201,204)):
    data=None if body is None else json.dumps(body,ensure_ascii=False).encode()
    req=urllib.request.Request(BASE+path,data=data,method=method,headers={
        "Authorization":"Bearer "+token(),
        "Content-Type":"application/json",
        "Accept":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=45) as r:
            raw=r.read().decode()
            if r.status not in ok: raise RuntimeError(f"{method} {path}: HTTP {r.status} {raw}")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw=e.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path}: HTTP {e.code} {raw[:3000]}")

def webpost(path,body):
    data=json.dumps(body,ensure_ascii=False).encode()
    req=urllib.request.Request("https://submarine.asia"+path,data=data,method="POST",
        headers={"Content-Type":"application/json","Origin":"https://submarine.asia"})
    try:
        with urllib.request.urlopen(req,timeout=30) as r: return r.status,json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw=e.read().decode(errors="replace")
        try: j=json.loads(raw)
        except: j={"raw":raw}
        return e.code,j

def ensure_review_account():
    digest=hashlib.sha256(os.environ["ASC_PRIVATE_KEY"].encode()).hexdigest()[:14]
    pwd="Review-"+digest+"!A7"
    body={"name":CFG["reviewAccountName"],"phone":CFG["reviewAccountPhone"],"password":pwd,"licenses":[],"licenseConfirmed":True}
    code,j=webpost("/api/auth/local/register",body)
    if code in (200,201):
        log("review_account=created")
    elif code==409:
        code2,j2=webpost("/api/auth/local/login",{"phone":CFG["reviewAccountPhone"],"password":pwd})
        if code2!=200 or not j2.get("ok"): raise RuntimeError("Existing review account password does not match generated credential")
        log("review_account=verified")
    else:
        raise RuntimeError(f"review account create failed: {code} {j}")
    return pwd

def first_data(resp):
    d=resp.get("data",[])
    return d[0] if isinstance(d,list) and d else None

def upsert_version_localization(version_id, locale):
    q=urllib.parse.urlencode({"filter[locale]":locale})
    r=asc("GET",f"/v1/appStoreVersions/{version_id}/appStoreVersionLocalizations?{q}")
    attrs={"description":CFG["description"],"keywords":CFG["keywords"],"marketingUrl":CFG["marketingUrl"],"promotionalText":CFG["promotionalText"],"supportUrl":CFG["supportUrl"]}
    x=first_data(r)
    if x:
        asc("PATCH",f"/v1/appStoreVersionLocalizations/{x['id']}",{"data":{"type":"appStoreVersionLocalizations","id":x["id"],"attributes":attrs}})
        log(f"version_localization=updated:{locale}")
    else:
        body={"data":{"type":"appStoreVersionLocalizations","attributes":{"locale":locale,**attrs},"relationships":{"appStoreVersion":{"data":{"type":"appStoreVersions","id":version_id}}}}}
        asc("POST","/v1/appStoreVersionLocalizations",body)
        log(f"version_localization=created:{locale}")

def upsert_appinfo_localization(app_id, locale):
    infos=asc("GET",f"/v1/apps/{app_id}/appInfos?limit=50").get("data",[])
    if not infos: raise RuntimeError("No appInfos resource")
    info_id=infos[0]["id"]
    q=urllib.parse.urlencode({"filter[locale]":locale})
    r=asc("GET",f"/v1/appInfos/{info_id}/appInfoLocalizations?{q}")
    attrs={"subtitle":CFG["subtitle"],"privacyPolicyUrl":CFG["privacyPolicyUrl"]}
    x=first_data(r)
    if x:
        asc("PATCH",f"/v1/appInfoLocalizations/{x['id']}",{"data":{"type":"appInfoLocalizations","id":x["id"],"attributes":attrs}})
        log(f"appinfo_localization=updated:{locale}")
    else:
        body={"data":{"type":"appInfoLocalizations","attributes":{"locale":locale,**attrs},"relationships":{"appInfo":{"data":{"type":"appInfos","id":info_id}}}}}
        asc("POST","/v1/appInfoLocalizations",body)
        log(f"appinfo_localization=created:{locale}")

def attach_latest_build(app_id, version_id):
    for attempt in range(18):
        q=urllib.parse.urlencode({"filter[app]":app_id,"sort":"-uploadedDate","limit":"20","fields[builds]":"version,uploadedDate,processingState,minOsVersion"})
        builds=asc("GET","/v1/builds?"+q).get("data",[])
        valid=[b for b in builds if b.get("attributes",{}).get("processingState")=="VALID"]
        if valid:
            b=valid[0]
            asc("PATCH",f"/v1/appStoreVersions/{version_id}/relationships/build",{"data":{"type":"builds","id":b["id"]}},ok=(200,204))
            log(f"build_attached={b['id']} version={b.get('attributes',{}).get('version')} minOS={b.get('attributes',{}).get('minOsVersion')}")
            return b["id"]
        if attempt<17:
            log(f"build_wait={attempt+1}/18")
            time.sleep(20)
    raise RuntimeError("No VALID build available after polling")

def upsert_review_detail(version_id,password):
    try:
        r=asc("GET",f"/v1/appStoreVersions/{version_id}/appStoreReviewDetail")
        x=r.get("data")
    except RuntimeError as e:
        if "HTTP 404" in str(e): x=None
        else: raise
    attrs={**CFG["review"],"demoAccountRequired":True,"demoAccountName":CFG["reviewAccountPhone"],"demoAccountPassword":password}
    if x:
        asc("PATCH",f"/v1/appStoreReviewDetails/{x['id']}",{"data":{"type":"appStoreReviewDetails","id":x["id"],"attributes":attrs}})
        log("review_detail=updated")
    else:
        body={"data":{"type":"appStoreReviewDetails","attributes":attrs,"relationships":{"appStoreVersion":{"data":{"type":"appStoreVersions","id":version_id}}}}}
        asc("POST","/v1/appStoreReviewDetails",body)
        log("review_detail=created")

def main():
    pwd=ensure_review_account()
    q=urllib.parse.urlencode({"filter[bundleId]":CFG["bundleId"],"limit":"10"})
    app=first_data(asc("GET","/v1/apps?"+q))
    if not app: raise RuntimeError("App not found")
    app_id=app["id"]; locale=app.get("attributes",{}).get("primaryLocale") or "ko"
    log(f"app_id={app_id} primary_locale={locale}")
    versions=asc("GET",f"/v1/apps/{app_id}/appStoreVersions?limit=50").get("data",[])
    candidates=[v for v in versions if v.get("attributes",{}).get("platform")=="IOS" and v.get("attributes",{}).get("versionString")==CFG["version"]]
    if not candidates: candidates=[v for v in versions if v.get("attributes",{}).get("platform")=="IOS"]
    if not candidates: raise RuntimeError("No iOS App Store version")
    version=candidates[0]; version_id=version["id"]
    log(f"version_id={version_id} state={version.get('attributes',{}).get('appStoreState')}")
    asc("PATCH",f"/v1/appStoreVersions/{version_id}",{"data":{"type":"appStoreVersions","id":version_id,"attributes":{"copyright":CFG["copyright"]}}})
    log("copyright=updated")
    upsert_appinfo_localization(app_id,locale)
    upsert_version_localization(version_id,locale)
    attach_latest_build(app_id,version_id)
    upsert_review_detail(version_id,pwd)
    log("sync=success")

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        log("sync=failure")
        log("error="+str(e))
        raise
    finally:
        open(os.path.join(ROOT,"appstore-sync-status.txt"),"w",encoding="utf-8").write("\n".join(STATUS)+"\n")
