(function(){
 'use strict';
 function init(){
  if(document.getElementById('navBar')&&document.getElementById('mainUI'))document.body.dataset.flowSurface='rspamd';
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
