/* Submarine K-room administrator push service worker. */
self.addEventListener("push",event=>{
 let data={};try{data=event.data?event.data.json():{}}catch{data={}}
 const title="서브마린 · 결제요청";
 const options={body:"새 입금확인 요청이 있습니다. 은행 입금을 확인해 주세요.",tag:"submarine-cash-payment",renotify:true,icon:"/favicon.ico",data:{url:"/admin-k-mobile.html"}};
 event.waitUntil(self.registration.showNotification(title,options));
});
self.addEventListener("notificationclick",event=>{
 event.notification.close();
 event.waitUntil((async()=>{
  const url=new URL("/admin-k-mobile.html",self.location.origin).href;
  const clients=await self.clients.matchAll({type:"window",includeUncontrolled:true});
  const existing=clients.find(c=>c.url.startsWith(self.location.origin)&&c.url.includes("admin-k-mobile.html"));
  if(existing){await existing.focus();return}
  await self.clients.openWindow(url);
 })());
});