const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function observable(x) { const subs = []; function o(v) { if (arguments.length) { x = v; subs.forEach(fn => fn(x)); return o; } return x; } o.subscribe = fn => subs.push(fn); return o; }
const events = {};
// SnappyMail 2.38.2 exports computed(fn, {pure:true}), not pureComputed.
const ko = { observable, computed(fn, options) { assert.equal(options.pure,true);return fn; } };
const reports=[];
const rl = { pluginSettingsGet: () => ({single_mb:2,total_mb:3,max_count:2}), pluginRemoteRequest(cb,action,data) { if(action==='MailControlUploadProgress') reports.push(data);cb(0,{}); } };
let now=20000;
const header = {children:[], append(child) {this.children.push(child);}};
const attachmentName = {children:[], append(child) {this.children.push(child);}};
const template = {querySelector(selector) {
    if(selector==='.mc-upload-policy') return header.children.find(x=>x.className==='mc-upload-policy');
    if(selector==='.modal-body .b-header') return header;
    if(selector==='.attachmentNameParent') return attachmentName;
    throw new Error('unexpected compose selector: '+selector);
}};
let templateAvailable=false, templateReads=0;
const context = { window: {rl, ko}, ko, document: {getElementById(id) {templateReads++;assert.equal(id,'PopupsCompose');return templateAvailable?{content:template}:null;},createElement(tag) {return {tag,setAttribute(key,value){this[key]=value;}};}}, addEventListener: (n,fn)=>{events[n]=fn;}, setInterval() {}, setTimeout() {}, Date: {now:()=>now} };
vm.runInNewContext(fs.readFileSync(__dirname+'/mail-control-upload/upload.js','utf8'), context);
assert.equal(templateReads,0); // templates need not exist while the plugin loads
const view = {
    viewModelTemplateID: 'PopupsCompose', attachments: observable([]), modalVisible: observable(false),
    sendError: observable(false), sendErrorDesc: observable(''), attachmentsArea() {}, sent:0,
    addAttachment(a,area,jua) { a.cancel=()=>{this.attachments(this.attachments().filter(x=>x!==a));jua?.cancel(a.id);}; this.attachments([...this.attachments(),a]); },
    sendCommand() { this.sent++; }, getAttachmentById(id) { return this.attachments().find(a=>a.id===id); }
};
templateAvailable=true;
events['rl-view-model.create']({detail:view});
assert.equal(header.children.length,1);assert.equal(header.children[0]['data-bind'],'text: mcPolicyText');
assert.equal(attachmentName.children.length,1);
let nativeBuildCalled=false;
const fallbackHeader={children:[],append(node){this.children.push(node);}};
const fallbackView={...view,mcUploadInstalled:false,onBuild(){nativeBuildCalled=true;}};
templateAvailable=false;events['rl-view-model.create']({detail:fallbackView});
fallbackView.onBuild({querySelector(selector){return selector==='.mc-upload-policy'?null:fallbackHeader;}});
assert.equal(nativeBuildCalled,true);assert.equal(fallbackHeader.children.length,1);
fallbackView.mcPolicyText('updated limits');assert.equal(fallbackHeader.children[0].textContent,'updated limits');
function file(id,size) { return {id, size:observable(size), enabled:observable(true), error:observable(''), waiting:observable(true), uploading:observable(false),complete:observable(false),progress:observable(0)}; }
const jua = {events:{},uploaded:[], getEvent(n) {return this.events[n];}, on(n,fn) {this.events[n]=fn;return this;}, uploadTask(id,info){this.uploaded.push(id);this.events.onStart(id);},cancel(){}};
jua.on('onProgress',(id,loaded,total)=>view.getAttachmentById(id).progress(Math.floor(loaded/total*100)))
   .on('onStart',id=>view.getAttachmentById(id).uploading(true))
   .on('onComplete',(id,ok,data)=>{let a=view.getAttachmentById(id);a.uploading(false);a.complete(true);if(!ok)a.error('failed');})
   .on('onSelect',(id,data)=>{view.addAttachment(file(id,data.size),1,jua);return true;});
function select(id,size) {if(jua.getEvent('onSelect')(id,{size})!==false)jua.uploadTask(id,{size});}
select('first',1024);
assert.deepEqual(jua.uploaded,['first']);assert.equal(reports[0].status,'uploading');now+=1001;
jua.getEvent('onProgress')('first',512,1024);
assert.match(view.getAttachmentById('first').mcUploadLabel(),/50%.*512 B.*1.0 KB/);
assert.equal(reports[1].received,512);now+=1001;
jua.getEvent('onProgress')('first',1024,1024);
assert.match(view.getAttachmentById('first').mcUploadLabel(),/服务器处理中/);
assert.equal(reports[2].status,'processing');now+=1001;
jua.getEvent('onComplete')('first',true,{Result:{Attachment:{size:1024}}});
assert.match(view.getAttachmentById('first').mcUploadLabel(),/附件已就绪/);
assert.equal(reports[3].status,'completed');now+=1001;
select('too-big',3*1048576);
assert.deepEqual(jua.uploaded,['first']);
assert.match(view.mcPolicyText(),/单个附件/);
select('second',2*1048576);
select('third',1);
assert.deepEqual(jua.uploaded,['first','second']);
assert.match(view.mcPolicyText(),/数量/);
view.sendCommand();assert.equal(view.sent,1);
view.attachments()[1].size(4*1048576);
view.sendCommand();assert.equal(view.sent,1);assert.equal(view.sendError(),true);
const second=view.getAttachmentById('second');jua.getEvent('onComplete')('second',false,{});
assert.equal(second.mcUploadLabel(),'failed');
console.log('PASS: native upload progress, server processing, failed state, per-file/count/send guards');
