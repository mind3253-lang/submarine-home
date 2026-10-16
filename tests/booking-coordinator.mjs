import fs from 'node:fs';import assert from 'node:assert/strict';
const code=fs.readFileSync('worker.js','utf8');const classCode=code.slice(0,code.indexOf('\nexport default {'));
const {BookingCoordinator}=await import('data:text/javascript;base64,'+Buffer.from(classCode).toString('base64'));
const store=new Map();const puts=new Map();const env={IMAGES:{async get(k){return store.has(k)?{async text(){return store.get(k)}}:null},async put(k,v){store.set(k,v);puts.set(k,(puts.get(k)||0)+1)}}};
const member={memberNo:'I01',name:'Instructor',point:200000,cash:0};store.set('system/members.json',JSON.stringify([member]));store.set('system/instructors.json',JSON.stringify([{memberNo:'I01',name:'Instructor'}]));
const coordinator=new BookingCoordinator({},env);
async function send(payload){const response=await coordinator.fetch({async json(){return payload}});return {status:response.status,body:await response.json()}}
const booking={date:'2026-10-19',time:'1타임',type:'강습',people:2,instructorName:'Instructor'};
const p={member:{memberNo:'I01',name:'Instructor'},booking,idempotencyKey:'fixed-booking-key-0001'};
const [first,duplicate]=await Promise.all([send(p),send(p)]);
assert.equal(first.body.ok,true);assert.equal(duplicate.body.ok,true);assert.equal(first.body.reservation.id,duplicate.body.reservation.id);
assert.equal(JSON.parse(store.get('system/reservations.json')).length,1);
const conflicting=await send({...p,booking:{...booking,people:1}});assert.equal(conflicting.status,409);assert.equal(JSON.parse(store.get('system/members.json'))[0].point,120000);
const invalid=await send({...p,idempotencyKey:'invalid-booking-key-0002',booking:{...booking,people:0}});assert.equal(invalid.status,400);
const outsider=await send({member:{memberNo:'OTHER'},booking,idempotencyKey:'another-booking-key-0003'});assert.equal(outsider.status,404);
const missing=await send({member:{memberNo:'I01'},idempotencyKey:'missing-payload-000004'});assert.equal(missing.status,400);
const impossibleDate=await send({member:{memberNo:'I01'},booking:{...booking,date:'2026-02-30'},idempotencyKey:'invalid-date-0000000007'});assert.equal(impossibleDate.status,400);
const wrongType=await send({member:{memberNo:'I01'},booking:{...booking,type:'잘못된구분'},idempotencyKey:'wrong-type-0000000005'});assert.equal(wrongType.status,400);
const adminMalformed=await send({action:'adminAdd'});assert.equal(adminMalformed.status,400);

const admin=await send({action:'adminAdd',booking:{date:'2026-10-19',time:'2타임',type:'강습',people:3,instructorName:'Instructor'}});assert.equal(admin.body.ok,true);assert.equal(admin.body.reservation.ticketDeducted,false);
assert.equal(JSON.parse(store.get('system/members.json'))[0].point,120000);
const cancel=await send({action:'cancelRequest',reservationId:first.body.reservation.id,memberNo:'I01',memberName:'Instructor'});assert.equal(cancel.body.ok,true);
const complete=await send({action:'complete',requestId:JSON.parse(store.get('system/service-requests.json'))[0].id});assert.equal(complete.body.ok,true);
assert.equal(JSON.parse(store.get('system/members.json'))[0].point,200000);
const again=await send({action:'complete',requestId:JSON.parse(store.get('system/service-requests.json'))[0].id});assert.equal(again.body.alreadyCompleted,true);
assert.equal(JSON.parse(store.get('system/members.json'))[0].point,200000);
// Simulate failure while persisting member deduction: the reservation must roll back.
let failMemberWrite=true;
const originalPut=env.IMAGES.put;
env.IMAGES.put=async(k,v)=>{if(k==='system/members.json'&&failMemberWrite){failMemberWrite=false;throw Error('injected member storage failure')}return originalPut(k,v)};
let writeFailed=false;
try{await send({member:{memberNo:'I01'},booking:{...booking,time:'3타임',people:1},idempotencyKey:'storage-failure-0000006'})}catch(e){writeFailed=true}
assert.equal(writeFailed,true);
assert.equal(JSON.parse(store.get('system/reservations.json')).filter(x=>x.idempotencyKey==='storage-failure-0000006').length,0);
assert.equal(JSON.parse(store.get('system/members.json'))[0].point,200000);
console.log('PASS: concurrent idempotency, first booking, quantity validation, instructor authorization, admin no-charge, cancellation and single refund');
