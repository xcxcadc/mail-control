/* Hydrate the already-rendered navigation; never fetch account/menu data. */
(function(){
 'use strict';
 var host=document.getElementById('mail-control-side-nav');
 if(!host||!host.classList.contains('flow-server-sidebar')||self!==top)return;
 var toggle=document.getElementById('mail-control-nav-toggle'),close=document.getElementById('flow-shell-close'),backdrop=document.getElementById('mail-control-nav-backdrop');
 var inertNodes=[],previousFocus=null,media=matchMedia('(max-width:900px)');
 function setOpen(value,restore){
  document.body.classList.toggle('mail-control-nav-open',value);toggle.setAttribute('aria-expanded',String(value));
  if(value){previousFocus=document.activeElement;inertNodes=Array.from(document.body.children).filter(function(n){return n!==host&&n!==toggle&&n!==backdrop&&n.tagName!=='SCRIPT'&&n.tagName!=='STYLE'&&!n.inert});inertNodes.forEach(function(n){n.inert=true});close.focus()}
  else{inertNodes.forEach(function(n){n.inert=false});inertNodes=[];if(restore!==false)(previousFocus&&previousFocus.isConnected?previousFocus:toggle).focus()}
 }
 toggle.addEventListener('click',function(){setOpen(true)});close.addEventListener('click',function(){setOpen(false)});backdrop.addEventListener('click',function(){setOpen(false)});
 document.addEventListener('keydown',function(e){
  if(!document.body.classList.contains('mail-control-nav-open'))return;
  if(e.key==='Escape'){e.preventDefault();setOpen(false);return}
  if(e.key!=='Tab')return;
  var nodes=Array.from(host.querySelectorAll('a[href],button:not([disabled])')).filter(function(n){return n.getClientRects().length});if(!nodes.length)return;
  var first=nodes[0],last=nodes[nodes.length-1];
  if(e.shiftKey&&(document.activeElement===first||!host.contains(document.activeElement))){e.preventDefault();last.focus()}
  else if(!e.shiftKey&&(document.activeElement===last||!host.contains(document.activeElement))){e.preventDefault();first.focus()}
 });
 media.addEventListener('change',function(){if(!media.matches)setOpen(false,false)});
})();
