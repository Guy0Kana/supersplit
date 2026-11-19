(function(){
'use strict';
var $=function(s,r){return (r||document).querySelector(s)};
var $$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
var toastT;function toast(m){var t=$('#toast');t.textContent=m;t.classList.add('on');clearTimeout(toastT);toastT=setTimeout(function(){t.classList.remove('on')},3600)}

/* ---------- live mode: talks to the Express API when served over http(s), falls back to sample data ---------- */
var LIVE=false,ME=null;
function isAdmin(){return !!(ME&&ME.role==='admin')}
function noop(){}
function api(path,opts){
  opts=opts||{};var o={method:opts.method||'GET',credentials:'same-origin',headers:{}};
  if(opts.body!==undefined){o.headers['Content-Type']='application/json';o.body=JSON.stringify(opts.body)}
  return fetch(path,o).then(function(r){return r.json().catch(function(){return null}).then(function(j){
    if(!r.ok||!j||j.ok===false){var e=new Error((j&&j.error)||'Request failed');e.status=r.status;e.fields=j&&j.fields;throw e}
    return j})});
}
function relTime(iso){var d=(Date.now()-Date.parse(iso))/864e5;if(isNaN(d))return '';if(d<1)return 'Today';if(d<2)return 'Yesterday';return Math.floor(d)+' days ago'}
function ago(iso){var m=(Date.now()-Date.parse(iso))/6e4;if(isNaN(m))return '';if(m<1)return 'just now';if(m<60)return Math.floor(m)+' min ago';if(m<1440)return Math.floor(m/60)+' h ago';return Math.floor(m/1440)+' d ago'}

/* ---------- tabs and routing ---------- */
var TABS=[['overview','Overview'],['feed','Threat Feed'],['quiz','Posture Check'],['privacy','Privacy Hub'],['services','Services'],['admin','Admin']];
var tabsEl=$('#tabs');
TABS.forEach(function(t){var b=document.createElement('button');b.type='button';b.className='tab';b.id='tab-'+t[0];b.setAttribute('role','tab');b.setAttribute('aria-controls','panel-'+t[0]);b.dataset.tab=t[0];b.textContent=t[1];tabsEl.appendChild(b)});
function show(id,opts){
  if(!TABS.some(function(t){return t[0]===id}))id='overview';
  if(id==='admin'&&LIVE&&!isAdmin())id='overview';
  TABS.forEach(function(t){var p=$('#panel-'+t[0]),b=$('#tab-'+t[0]),on=t[0]===id;p.hidden=!on;b.setAttribute('aria-selected',on?'true':'false');b.tabIndex=on?0:-1;if(on&&on!==show.cur){p.style.animation='none';void p.offsetWidth;p.style.animation=''}});
  show.cur=id;
  if(location.hash!=='#'+id){try{history.replaceState(null,'','#'+id)}catch(e){location.hash=id}}
  if(!(opts&&opts.keep))window.scrollTo(0,0);
  if(id==='overview')animateMeter();
  if(id==='admin'&&LIVE)loadAdmin();
}
tabsEl.addEventListener('click',function(e){var b=e.target.closest('.tab');if(b)show(b.dataset.tab)});
tabsEl.addEventListener('keydown',function(e){var i=TABS.findIndex(function(t){return t[0]===show.cur});if(e.key==='ArrowRight'||e.key==='ArrowLeft'){var n=(i+(e.key==='ArrowRight'?1:TABS.length-1))%TABS.length;show(TABS[n][0]);$('#tab-'+TABS[n][0]).focus();e.preventDefault()}});
document.addEventListener('click',function(e){var g=e.target.closest('[data-go]');if(g){e.preventDefault();show(g.dataset.go)}});
window.addEventListener('hashchange',function(){show(location.hash.slice(1))});
$('.brand').addEventListener('click',function(e){e.preventDefault();show('overview')});
function toBooking(){show('services');setTimeout(function(){$('#bookSection').scrollIntoView({behavior:'smooth',block:'start'})},60)}
$('#ctaBook').addEventListener('click',toBooking);$('#svcBook').addEventListener('click',toBooking);

/* ---------- theme ---------- */
var themeBtn=$('#themeBtn'),mq=matchMedia('(prefers-color-scheme: dark)');
function curTheme(){return document.documentElement.getAttribute('data-theme')||(mq.matches?'dark':'light')}
function syncTheme(){var t=curTheme();themeBtn.setAttribute('data-mode',t);themeBtn.setAttribute('aria-label',t==='dark'?'Switch to light theme':'Switch to dark theme')}
themeBtn.addEventListener('click',function(){document.documentElement.setAttribute('data-theme',curTheme()==='dark'?'light':'dark');syncTheme()});
if(mq.addEventListener)mq.addEventListener('change',syncTheme);
syncTheme();

/* ---------- threat meter ---------- */
var SIGNALS=[
 {id:'kev',name:'Known-exploited additions',sub:'CISA KEV · last 7 days',w:.35,x:3,p90:5},
 {id:'crit',name:'Critical CVEs (CVSS 9.0+)',sub:'NVD · last 24 hours',w:.25,x:12,p90:22},
 {id:'epss',name:'High exploit-probability CVEs',sub:'EPSS 0.5 or more · last 7 days',w:.25,x:6,p90:12},
 {id:'news',name:'Breach headlines',sub:'News feeds · last 24 hours',w:.15,x:20,p90:40}];
var BANDS=[['Low',20,'--b1'],['Guarded',40,'--b2'],['Elevated',60,'--b3'],['High',80,'--b4'],['Severe',100,'--b5']];
function score(){return Math.round(100*SIGNALS.reduce(function(a,s){return a+s.w*Math.min(1,s.x/s.p90)},0))}
function bandOf(n){for(var i=0;i<BANDS.length;i++)if(n<=BANDS[i][1])return BANDS[i];return BANDS[4]}
var CX=150,CY=150,R=118;
function pt(a,r){var t=a*Math.PI/180;return [CX+r*Math.cos(t),CY-r*Math.sin(t)]}
function arc(s0,s1){var p0=pt(180-s0*1.8,R),p1=pt(180-s1*1.8,R);return 'M'+p0[0].toFixed(1)+' '+p0[1].toFixed(1)+' A'+R+' '+R+' 0 0 1 '+p1[0].toFixed(1)+' '+p1[1].toFixed(1)}
var arcs=$('#arcs'),prev=0;
BANDS.forEach(function(b,i){var p=document.createElementNS('http://www.w3.org/2000/svg','path');p.setAttribute('d',arc(i*20+1,b[1]-1));p.setAttribute('class','arc');p.style.stroke='var('+b[2]+')';arcs.appendChild(p)});
function renderSignals(){
  var h='';SIGNALS.forEach(function(s){var r=Math.min(1,s.x/s.p90);h+='<div class="sig"><div><div class="nm">'+esc(s.name)+'</div><div class="sb">'+esc(s.sub)+' · weight '+Math.round(s.w*100)+'%</div></div><div class="vl mono">'+s.x+' / '+s.p90+'<div class="sb">+'+Math.round(100*s.w*r)+' pts</div></div><div class="bar"><i style="width:'+(r*100).toFixed(0)+'%"></i></div></div>'});
  $('#sigs').innerHTML=h;
}
function renderSliders(){
  var h='';SIGNALS.forEach(function(s){h+='<div class="slider"><label for="sl-'+s.id+'">'+esc(s.name)+'</label><span class="mono" id="sv-'+s.id+'">'+s.x+'</span><input type="range" id="sl-'+s.id+'" min="0" max="'+Math.round(s.p90*1.6)+'" value="'+s.x+'"></div>'});
  $('#sliders').innerHTML=h;
  SIGNALS.forEach(function(s){$('#sl-'+s.id).addEventListener('input',function(e){s.x=+e.target.value;$('#sv-'+s.id).textContent=s.x;updateMeter(true)})});
}
function updateMeter(instant){
  var n=score(),b=bandOf(n);
  $('#needle').style.transform='rotate('+(-90+n*1.8)+'deg)';
  $('#scoreNum').textContent=n;$('#scoreBand').textContent=b[0];$('#scoreBand').style.color='var('+b[2]+')';
  $('#gauge').setAttribute('aria-label','Threat level '+n+' out of 100, '+b[0]);
  renderSignals();
}
function animateMeter(){var n=score();$('#needle').style.transition='none';$('#needle').style.transform='rotate(-90deg)';void $('#needle').getBoundingClientRect();$('#needle').style.transition='';updateMeter()}
renderSliders();

/* ---------- overview tiles ---------- */
var ICONS={feed:'<path d="M4 5h16M4 12h16M4 19h10"/>',quiz:'<path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/>',privacy:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',services:'<path d="M3 21h18M5 21V8l7-5 7 5v13M9 21v-6h6v6"/>'};
var TILES=[['feed','Threat Feed','Daily CVEs, breaches and patch advisories with severity, vendor and industry filters.'],['quiz','Posture Check','Twenty-five questions on basics, backups and SOC 2 readiness, with a scored report.'],['privacy','Privacy Hub','Open-source tools, private browsers and hardening guides, reviewed and dated.'],['services','Services','Penetration testing and managed monitoring with published scopes and response targets.']];
$('#tiles').innerHTML=TILES.map(function(t){return '<button type="button" class="card tile" data-go="'+t[0]+'"><span class="ico"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+ICONS[t[0]]+'</svg></span><h3>'+t[1]+'</h3><p>'+t[2]+'</p><span class="go">Open →</span></button>'}).join('');

/* ---------- feed ---------- */
var FEED=[
 {id:'SAMPLE-001',type:'CVE',sev:'Critical',cvss:9.8,kev:true,vendor:'Tessera Cloud',product:'Gateway Appliance',ind:'Technology',when:'Today',title:'Authentication bypass in the Tessera Gateway admin interface',sum:'An attacker with network access can reach the admin interface without logging in and create accounts. Exploitation has been reported. Install the vendor fix and limit the admin port to trusted addresses.'},
 {id:'SAMPLE-002',type:'CVE',sev:'Critical',cvss:9.1,kev:true,vendor:'Acme Networks',product:'Edge Router firmware',ind:'Government',when:'Today',title:'Command injection in the Acme edge router management service',sum:'A crafted request to the management service runs commands on the router. Exploitation is known. Update the firmware, and block management access from the internet.'},
 {id:'SAMPLE-003',type:'Breach',sev:'High',cvss:null,kev:false,vendor:'Orbis Payments',product:'Test environment',ind:'Finance',when:'Today',title:'Payment processor reports unauthorised access to a test environment',sum:'The company says an outside party reached a non-production system. It reports no live card data involved so far. Customers should watch for the follow-up notice and rotate any shared test credentials.'},
 {id:'SAMPLE-004',type:'CVE',sev:'High',cvss:8.1,kev:false,vendor:'Halden Health Systems',product:'Patient Portal',ind:'Healthcare',when:'Yesterday',title:'SQL injection in the Halden Patient Portal search',sum:'The search box passes input to the database without proper checks, which could expose records. A patch is available. Apply it and review database access logs for unusual queries.'},
 {id:'SAMPLE-005',type:'Patch',sev:'High',cvss:null,kev:false,vendor:'Halden Health Systems',product:'Patient Portal',ind:'Healthcare',when:'Yesterday',title:'Hotfix released for the Patient Portal vulnerabilities',sum:'The vendor has shipped a hotfix covering the recent portal flaws. Schedule it for this week, and test the login and search pages afterwards.'},
 {id:'SAMPLE-006',type:'CVE',sev:'High',cvss:7.5,kev:false,vendor:'Orbis Payments',product:'Checkout SDK',ind:'Finance',when:'Yesterday',title:'Denial of service in the Orbis Checkout SDK',sum:'A malformed request can make the checkout component stop responding. Update to the fixed SDK version and add basic rate limiting in front of the checkout endpoint.'},
 {id:'SAMPLE-007',type:'Patch',sev:'Medium',cvss:null,kev:false,vendor:'Brightline Software',product:'Office suite',ind:'Technology',when:'2 days ago',title:'Monthly security update fixes twelve flaws',sum:'The monthly release closes twelve issues, none reported as exploited. Include it in the normal patch cycle and check the release notes for any settings changes.'},
 {id:'SAMPLE-008',type:'Breach',sev:'Medium',cvss:null,kev:false,vendor:'Marlow Retail Group',product:'Loyalty database',ind:'Retail',when:'2 days ago',title:'Retail group exposes a loyalty programme database',sum:'A misconfigured storage bucket left names and email addresses reachable. The company has closed access. Members should expect phishing that mentions the programme.'},
 {id:'SAMPLE-009',type:'CVE',sev:'Medium',cvss:5.4,kev:false,vendor:'Brightline Software',product:'Document Editor',ind:'Technology',when:'3 days ago',title:'Cross-site scripting in the Brightline Document Editor comments',sum:'Comment text is not cleaned, so a shared document could run a script in a colleague\'s browser. Update the editor and avoid opening comments from unknown senders until then.'},
 {id:'SAMPLE-010',type:'CVE',sev:'Low',cvss:3.3,kev:false,vendor:'Tessera Cloud',product:'Command-line tool',ind:'Technology',when:'3 days ago',title:'Information disclosure in Tessera CLI log output',sum:'Verbose logs can include a temporary token. Update the tool and clear old log files from shared machines.'}];
var SEVS=['Critical','High','Medium','Low'],sevOn={};
function uniq(k){return Array.from(new Set(FEED.map(function(f){return f[k]}).filter(Boolean))).sort()}
function fillSel(id,label,vals){$(id).innerHTML='<option value="">'+label+'</option>'+vals.map(function(v){return '<option>'+esc(v)+'</option>'}).join('')}
fillSel('#fVendor','All vendors',uniq('vendor'));fillSel('#fIndustry','All industries',uniq('ind'));fillSel('#fType','All types',uniq('type'));
$('#sevChips').innerHTML=SEVS.map(function(s){return '<button type="button" class="chip" aria-pressed="false" data-sev="'+s+'">'+s+'</button>'}).join('');
function metaLine(f){return [f.vendor,f.product].filter(Boolean).map(esc).join(' · ')}
function card(f){
  var ai=f.ai!==false,safe=f.url&&/^https?:\/\//.test(f.url);
  var src=safe?'<a href="'+esc(f.url)+'" target="_blank" rel="noopener noreferrer">Source: '+esc(f.src||'link')+' ↗</a>':'<span>Source: NVD record <span class="mono">'+esc(f.id)+'</span> (sample)</span>';
  return '<article class="card item"><div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center"><span class="pill sev-'+f.sev.toLowerCase()+'">'+f.sev+'</span><span class="pill neutral">'+f.type+'</span>'+(f.kev?'<span class="pill kev">Known exploited</span>':'')+'</div>'
  +'<h3>'+esc(f.title)+'</h3><div class="meta"><span>'+metaLine(f)+'</span><span>'+esc(f.ind)+'</span></div>'
  +'<div class="ai"><b>'+(ai?'AI-generated summary'+(LIVE?'':' · sample'):'From the source')+'</b>'+esc(f.sum)+'</div>'
  +'<div class="item-foot"><span>'+esc(f.when)+'</span>'+(f.cvss?'<span class="mono">CVSS '+f.cvss.toFixed(1)+'</span>':'')+src+'</div></article>';
}
var RANK={Critical:0,High:1,Medium:2,Low:3};
function top3(){return FEED.slice().sort(function(a,b){return (b.kev-a.kev)||(RANK[a.sev]-RANK[b.sev])}).slice(0,3)}
var DIGEST=null;
var EMPTY_FEED='<div class="card empty">No items yet. The first feed update runs shortly after the server starts.</div>';
function renderHome(){
  var t3=top3(),dg=DIGEST&&DIGEST.length?DIGEST:t3;
  $('#homeFeed').innerHTML=t3.length?t3.map(card).join(''):EMPTY_FEED;
  $('#digest').innerHTML='<div><span class="tag">Daily digest</span><div class="note" style="margin-top:6px">'+(LIVE?'Built daily at 07:00 UTC':'Sample · built once a day')+'</div></div><div><h2 style="font-size:20px">'+(dg.length?'Today\'s brief: '+dg.length+' items to act on':'Today\'s brief')+'</h2>'+(dg.length?'<ol>'+dg.map(function(f){return '<li><b>'+esc(f.title)+'</b></li>'}).join('')+'</ol>':'<p class="note" style="margin-top:8px">The brief appears after the first feed update.</p>')+'</div>';
}
renderHome();
function renderFeed(){
  var q=$('#fSearch').value.trim().toLowerCase(),v=$('#fVendor').value,i=$('#fIndustry').value,t=$('#fType').value,k=$('#fKev').checked,any=Object.keys(sevOn).some(function(s){return sevOn[s]});
  var out=FEED.filter(function(f){return (!q||(f.title+f.vendor+f.product+f.ind).toLowerCase().indexOf(q)>-1)&&(!v||f.vendor===v)&&(!i||f.ind===i)&&(!t||f.type===t)&&(!k||f.kev)&&(!any||sevOn[f.sev])});
  $('#feedCount').textContent=out.length+' of '+FEED.length+' items';
  $('#feedList').innerHTML=out.length?out.map(card).join(''):(FEED.length?'<div class="card empty">No items match these filters. Clear a filter to see more.</div>':EMPTY_FEED);
}
['#fSearch','#fVendor','#fIndustry','#fType','#fKev'].forEach(function(s){$(s).addEventListener('input',renderFeed)});
$('#sevChips').addEventListener('click',function(e){var b=e.target.closest('.chip');if(!b)return;var s=b.dataset.sev;sevOn[s]=!sevOn[s];b.setAttribute('aria-pressed',sevOn[s]?'true':'false');renderFeed()});
renderFeed();

/* ---------- quiz ---------- */
var DOMAINS=[
 {id:'acc',name:'Accounts and access',soc:'Security: logical access (CC6)',qs:[
  ['Is multi-factor sign-in turned on for email and admin accounts?','Turn on multi-factor sign-in for email and every admin account first.',3],
  ['Does everyone use a password manager for work logins?','Roll out a password manager and retire reused passwords.',2],
  ['Do leavers lose access within one working day?','Write a leaver checklist and revoke accounts the day someone departs.',3],
  ['Are admin rights limited to the people who need them?','List admin accounts and remove rights nobody needs.',2],
  ['Are shared accounts avoided or tracked?','Replace shared logins with named accounts, or record who holds each one.',1]]},
 {id:'dev',name:'Devices and patching',soc:'Security: system operations (CC7)',qs:[
  ['Are laptops and phones encrypted?','Enable built-in disk encryption on every laptop and phone.',2],
  ['Are critical patches applied within 14 days?','Set a 14-day target for critical patches and track it monthly.',3],
  ['Do you keep a list of company devices and software?','Start a simple inventory sheet of devices and key software.',2],
  ['Is endpoint protection running on every computer?','Install and centrally monitor endpoint protection on all computers.',2],
  ['Are automatic updates and screen locks switched on?','Enforce automatic updates and a short screen-lock timeout.',1]]},
 {id:'bak',name:'Backups and recovery',soc:'Availability (A1)',qs:[
  ['Is your critical data backed up automatically?','Automate backups of the data you could not afford to lose.',3],
  ['Is a copy kept offsite or offline?','Keep one backup copy offsite or offline.',3],
  ['Have you restored from a backup in the last year?','Test a restore this quarter and write down how long it took.',2],
  ['Is there a written target for how fast you must recover?','Agree a recovery time target for each critical system.',1],
  ['Are backups protected if an account is compromised?','Use separate credentials and delete protection for backups.',2]]},
 {id:'ppl',name:'Email and people',soc:'Security: control environment and communication (CC1, CC2)',qs:[
  ['Has everyone had phishing awareness training?','Run a short phishing session for all staff each year.',2],
  ['Are SPF, DKIM and DMARC set up for your domain?','Publish SPF, DKIM and DMARC records for your email domain.',2],
  ['Is there an easy way to report a suspicious email?','Add a report button or a single address for suspicious emails.',1],
  ['Does everyone know who to tell if something goes wrong?','Name an incident contact and share it with the whole team.',2],
  ['Do new starters get security basics on day one?','Add a short security briefing to onboarding.',1]]},
 {id:'gov',name:'Governance and SOC 2 readiness',soc:'Security: risk assessment and vendor risk (CC3, CC9)',qs:[
  ['Is there a written security policy approved by leadership?','Write a short security policy and have leadership approve it.',2],
  ['Do you keep a risk register and review it yearly?','Start a risk register with your top ten risks and review it yearly.',2],
  ['Are suppliers with access to your data reviewed first?','Review security basics for any supplier that handles your data.',2],
  ['Do you have a written incident response plan?','Write a one-page incident plan: who, what, and who to call.',3],
  ['Are access and security logs kept and reviewed?','Keep logs for at least 90 days and review them on a schedule.',2]]}];
var ANS=['Yes','Partly','No','Not sure'],VAL={y:2,p:1,n:0,u:0},CODE={y:'Yes',p:'Partly',n:'No',u:'Not sure'};
var quiz={step:0,a:{},done:false,saved:false};
var qr=$('#quizRoot');
function qBand(p){return p<40?['Foundational','--b5']:p<70?['Developing','--b3']:p<90?['Solid','--b2']:['Audit-ready','--b1']}
function renderQuiz(){
  if(quiz.done)return renderResults();
  var d=DOMAINS[quiz.step],h='<div class="stepper">'+DOMAINS.map(function(x,i){return '<div class="step" data-s="'+(i<quiz.step?'done':i===quiz.step?'now':'')+'">'+esc(x.name)+'</div>'}).join('')+'</div>';
  h+='<h2 style="font-size:24px;margin-bottom:4px">'+esc(d.name)+'</h2><p class="note" style="margin-bottom:16px">Area '+(quiz.step+1)+' of 5 · supports '+esc(d.soc)+'</p><div class="grid" style="gap:12px">';
  d.qs.forEach(function(q,i){var key=d.id+i,cur=quiz.a[key];
    h+='<fieldset class="card q" style="margin:0;border:1px solid var(--line)"><legend class="sr">'+esc(q[0])+'</legend><p class="t">'+esc(q[0])+'</p><div class="opts">';
    ['y','p','n','u'].forEach(function(c,j){h+='<label class="opt"><input type="radio" name="'+key+'" value="'+c+'"'+(cur===c?' checked':'')+'><span>'+ANS[j]+'</span></label>'});
    h+='</div></fieldset>'});
  var n=d.qs.filter(function(q,i){return quiz.a[d.id+i]}).length;
  h+='</div><div class="quiz-nav"><button class="btn btn-quiet" type="button" id="qBack"'+(quiz.step?'':' disabled')+'>Back</button><span class="note" id="qCount">'+n+' of 5 answered</span><button class="btn btn-accent" type="button" id="qNext"'+(n<5?' disabled':'')+'>'+(quiz.step===4?'See my results':'Next area')+'</button></div>';
  qr.innerHTML=h;
}
qr.addEventListener('change',function(e){
  var r=e.target;if(r.type!=='radio')return;quiz.a[r.name]=r.value;
  var d=DOMAINS[quiz.step],n=d.qs.filter(function(q,i){return quiz.a[d.id+i]}).length;
  $('#qCount').textContent=n+' of 5 answered';$('#qNext').disabled=n<5;
});
qr.addEventListener('click',function(e){
  var t=e.target.closest('button');if(!t)return;
  if(t.id==='qNext'){if(quiz.step===4)quiz.done=true;else quiz.step++;renderQuiz();window.scrollTo(0,0)}
  if(t.id==='qBack'){quiz.step--;renderQuiz();window.scrollTo(0,0)}
  if(t.id==='qRestart'){quiz={step:0,a:{},done:false,saved:false};renderQuiz();window.scrollTo(0,0)}
  if(t.id==='qSave'){if(!signedIn){openAuth('in','Sign in to save this result.');return}if(LIVE){api('/api/quiz/results',{method:'POST',body:{answers:quiz.a}}).then(function(){quiz.saved=true;toast('Result saved to your account.');renderQuiz()}).catch(function(e){toast(e.message)});return}quiz.saved=true;toast('Saved to your account (preview).');renderQuiz()}
  if(t.id==='qBook'){var s=$('#bSvc');s.value='Security posture review';$('#bMsg').value='My posture check score was '+calc().overall+'% ('+qBand(calc().overall)[0]+').';toBooking()}
});
function calc(){
  var tot=0,doms=DOMAINS.map(function(d){var s=0;d.qs.forEach(function(q,i){s+=VAL[quiz.a[d.id+i]||'n']});tot+=s;return {d:d,pct:Math.round(s/10*100)}});
  var gaps=[];DOMAINS.forEach(function(d,di){d.qs.forEach(function(q,i){var a=quiz.a[d.id+i]||'n',v=VAL[a];if(v<2)gaps.push({q:q,a:a,d:d,di:di,sc:(2-v)*q[2]})})});
  gaps.sort(function(a,b){return b.sc-a.sc||a.di-b.di});
  return {overall:Math.round(tot/50*100),doms:doms,fixes:gaps.slice(0,5)};
}
function renderResults(){
  var c=calc(),b=qBand(c.overall),C=2*Math.PI*60,off=C*(1-c.overall/100);
  var h='<div class="card result-top"><svg class="ring" viewBox="0 0 150 150" role="img" aria-label="Overall score '+c.overall+' percent"><circle cx="75" cy="75" r="60" fill="none" stroke="var(--surface-2)" stroke-width="14"/><circle cx="75" cy="75" r="60" fill="none" stroke="var('+b[1]+')" stroke-width="14" stroke-linecap="round" stroke-dasharray="'+C.toFixed(1)+'" stroke-dashoffset="'+off.toFixed(1)+'" transform="rotate(-90 75 75)"/><text x="75" y="82" text-anchor="middle" font-size="34" font-weight="800" font-family="Manrope,sans-serif" fill="var(--ink)">'+c.overall+'%</text></svg>'
   +'<div><span class="tag">Overall result</span><h2 style="font-size:30px;margin:8px 0">'+b[0]+'</h2><p style="color:var(--ink-2)">'+(c.overall<40?'The essentials are not yet in place. The five fixes below give the biggest gain.':c.overall<70?'You have some basics. Closing the gaps below will move you quickly.':c.overall<90?'Most controls are in place. A few gaps remain.':'Your basics are strong. A formal readiness review is a sensible next step.')+'</p>'
   +'<div class="cta-row" style="margin-top:16px"><button class="btn btn-accent btn-sm" id="qBook" type="button">Talk it through</button><button class="btn btn-quiet btn-sm" id="qSave" type="button"'+(quiz.saved?' disabled':'')+'>'+(quiz.saved?'Saved':'Save result')+'</button><button class="btn btn-quiet btn-sm" id="qRestart" type="button">Start again</button></div></div></div>';
  h+='<h3 style="margin:32px 0 8px;font-size:20px">By area</h3>';
  c.doms.forEach(function(x){var bb=qBand(x.pct);h+='<div class="dom"><div class="nm"><b>'+esc(x.d.name)+'</b><div class="note">'+esc(x.d.soc)+'</div></div><div class="tr"><i style="width:'+x.pct+'%;background:var('+bb[1]+')"></i></div><div class="mono">'+x.pct+'%</div></div>'});
  h+='<h3 style="margin:32px 0 12px;font-size:20px">Your top fixes</h3>';
  if(!c.fixes.length)h+='<div class="card fix">No gaps found. Keep reviewing these controls each quarter.</div>';
  else h+='<div class="grid" style="gap:12px">'+c.fixes.map(function(f,i){return '<div class="card fix"><div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><span class="pill neutral">'+esc(f.d.name)+'</span><span class="pill '+(f.a==='n'?'sev-critical':'sev-medium')+'">'+CODE[f.a]+'</span></div><b>'+esc(f.q[1])+'</b><span class="note">Question: '+esc(f.q[0])+'</span></div>'}).join('')+'</div>';
  h+='<p class="note" style="margin-top:24px">This is a self-assessment. It is not an audit or a SOC 2 attestation. '+(LIVE?'Your answers stay in this browser unless you choose Save result.':'Your answers stay in this browser tab in the preview.')+'</p>';
  qr.innerHTML=h;
}
renderQuiz();

/* ---------- privacy directory ---------- */
var DIR=[
 ['Firefox','Browsers','Open-source browser with strong tracking protection and a large add-on ecosystem.','MPL-2.0','Windows, macOS, Linux, Android, iOS','https://www.mozilla.org/firefox/'],
 ['Tor Browser','Browsers','Routes traffic through the Tor network to hide your location from the sites you visit.','Open source','Windows, macOS, Linux, Android','https://www.torproject.org/'],
 ['Brave','Browsers','Chromium-based browser with built-in ad and tracker blocking.','MPL-2.0','Windows, macOS, Linux, Android, iOS','https://brave.com/'],
 ['Bitwarden','Password managers','Password manager with cloud sync and an open-source client.','GPL-3.0 (clients)','Windows, macOS, Linux, Android, iOS, Browser extension','https://bitwarden.com/'],
 ['KeePassXC','Password managers','Offline password manager that keeps your vault in a local file.','GPL','Windows, macOS, Linux','https://keepassxc.org/'],
 ['Signal','Messaging','End-to-end encrypted messaging and calls.','AGPL-3.0','Android, iOS, Windows, macOS, Linux','https://signal.org/'],
 ['Element','Messaging','Encrypted team chat on the open Matrix network.','Apache-2.0','Windows, macOS, Linux, Android, iOS','https://element.io/'],
 ['VeraCrypt','Encryption and backups','Encrypts whole drives or file containers.','Apache-2.0 / TrueCrypt','Windows, macOS, Linux','https://veracrypt.io/'],
 ['Cryptomator','Encryption and backups','Encrypts files before they reach cloud storage.','GPL-3.0','Windows, macOS, Linux, Android, iOS','https://cryptomator.org/'],
 ['restic','Encryption and backups','Fast, encrypted command-line backups to many storage types.','BSD-2-Clause','Windows, macOS, Linux','https://restic.net/'],
 ['WireGuard','Network and tracking protection','Simple, modern VPN protocol built into many systems.','GPL-2.0','Windows, macOS, Linux, Android, iOS','https://www.wireguard.com/'],
 ['uBlock Origin','Network and tracking protection','Content blocker that stops ads and trackers in the browser.','GPL-3.0','Browser extension','https://github.com/gorhill/uBlock']];
var cats,plats,dcat='All';
function buildDirFilters(){
  cats=['All'].concat(Array.from(new Set(DIR.map(function(x){return x[1]}))));
  plats=Array.from(new Set(DIR.reduce(function(a,x){return a.concat(x[4].split(', '))},[]))).sort();
  $('#dPlat').innerHTML='<option value="">All platforms</option>'+plats.map(function(p){return '<option>'+esc(p)+'</option>'}).join('');
  $('#catChips').innerHTML=cats.map(function(c){return '<button type="button" class="chip" data-cat="'+esc(c)+'" aria-pressed="'+(c==='All')+'">'+esc(c)+'</button>'}).join('');
  dcat='All';
}
buildDirFilters();
function renderDir(){
  var q=$('#dSearch').value.trim().toLowerCase(),p=$('#dPlat').value;
  var out=DIR.filter(function(x){return (dcat==='All'||x[1]===dcat)&&(!p||x[4].split(', ').indexOf(p)>-1)&&(!q||(x[0]+x[2]).toLowerCase().indexOf(q)>-1)});
  $('#dirCount').textContent=out.length+' of '+DIR.length+' tools';
  $('#dirGrid').innerHTML=out.length?out.map(function(x){return '<article class="card dir"><div style="display:flex;justify-content:space-between;gap:8px;align-items:start"><h3>'+esc(x[0])+'</h3><span class="pill neutral">'+esc(x[1])+'</span></div><p style="color:var(--ink-2);font-size:14.5px">'+esc(x[2])+'</p><div class="kv"><span>Licence</span><b>'+esc(x[3])+'</b><span>Platforms</span><b>'+esc(x[4])+'</b><span>Reviewed</span><b>'+esc(x[6]||(LIVE?'Awaiting review':'Not yet (sample)'))+'</b></div><a href="'+esc(/^https?:\/\//.test(x[5])?x[5]:'#')+'" target="_blank" rel="noopener noreferrer" style="font:700 14px var(--font-display);margin-top:4px">Official site ↗</a></article>'}).join(''):'<div class="card empty" style="grid-column:1/-1">No tools match. Clear a filter to see more.</div>';
}
$('#catChips').addEventListener('click',function(e){var b=e.target.closest('.chip');if(!b)return;dcat=b.dataset.cat;$$('#catChips .chip').forEach(function(c){c.setAttribute('aria-pressed',c===b?'true':'false')});renderDir()});
$('#dSearch').addEventListener('input',renderDir);$('#dPlat').addEventListener('input',renderDir);renderDir();

/* ---------- services ---------- */
var SVC=[
 ['Web application penetration test',['Agreed URLs and APIs','Tested with and without a login'],['Denial of service','Social engineering','Anything not named in writing'],'A report with findings by severity, evidence, fixes and a retest'],
 ['Vulnerability assessment',['Scans of agreed hosts and cloud accounts','Triaged results'],['Exploiting the findings'],'A prioritised remediation list'],
 ['Managed monitoring',['Log collection and alert triage for agreed systems'],['Hardware and on-site support'],'A weekly summary and incident notes'],
 ['Security posture review',['The posture check results, walked through together'],['Technical testing'],'A written action plan']];
$('#svcGrid').innerHTML=SVC.map(function(s){return '<article class="card svc"><h3 style="font-size:20px">'+esc(s[0])+'</h3><h4>In scope</h4><ul>'+s[1].map(function(x){return '<li>'+esc(x)+'</li>'}).join('')+'</ul><h4>Out of scope</h4><ul>'+s[2].map(function(x){return '<li>'+esc(x)+'</li>'}).join('')+'</ul><h4>You receive</h4><p style="color:var(--ink-2);font-size:14.5px">'+esc(s[3])+'</p></article>'}).join('');
$('#bSvc').innerHTML='<option value="">Choose one</option>'+SVC.map(function(s){return '<option>'+esc(s[0])+'</option>'}).join('');
function setErr(id,msg){var f=$('#'+id);f.classList.toggle('bad',!!msg);var e=$('.err',f);if(e)e.textContent=msg||''}
$('#bookForm').addEventListener('submit',function(e){
  e.preventDefault();var bad=0;
  function chk(id,ok,msg){setErr(id,ok?'':msg);if(!ok)bad++}
  var n=$('#bName').value.trim(),m=$('#bEmail').value.trim();
  chk('f-name',n.length>=2&&n.length<=80,'Enter your name (2 to 80 characters).');
  chk('f-email',/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(m),'Enter a valid work email address.');
  chk('f-size',!!$('#bSize').value,'Choose your organisation size.');
  chk('f-svc',!!$('#bSvc').value,'Choose a service.');
  chk('f-msg',$('#bMsg').value.length<=600,'Keep the message under 600 characters.');
  $('#consentErr').textContent=$('#bConsent').checked?'':'Please agree so we can reply to you.';if(!$('#bConsent').checked)bad++;
  if($('#bWeb').value)return;
  if(bad){var f=$('#bookForm .bad input, #bookForm .bad select, #bookForm .bad textarea');if(f)f.focus();return}
  if(LIVE){
    var bb=$('#bookForm button[type=submit]');bb.disabled=true;
    api('/api/bookings',{method:'POST',body:{name:n,email:m,orgSize:$('#bSize').value,service:$('#bSvc').value,preferredTime:$('#bTime').value,message:$('#bMsg').value,consent:true,website:$('#bWeb').value}})
      .then(function(){$('#bookOkMsg').textContent='Thanks '+n.split(' ')[0]+'. Your request is in. You will get a reply with proposed times.';$('#bookForm').hidden=true;$('#bookOk').hidden=false})
      .catch(function(err){var f=err.fields||{};if(f.name)setErr('f-name',f.name);if(f.email)setErr('f-email',f.email);if(f.orgSize)setErr('f-size',f.orgSize);if(f.service)setErr('f-svc',f.service);if(f.message)setErr('f-msg',f.message);toast(err.message)})
      .then(function(){bb.disabled=false});
    return;
  }
  $('#bookOkMsg').textContent='Thanks '+n.split(' ')[0]+'. In the live site this request is saved for the admin page and you receive a reply with proposed times. The preview sends nothing.';
  $('#bookForm').hidden=true;$('#bookOk').hidden=false;
});

/* ---------- admin / Gemini ---------- */
var gemConfigured=false;
$('#gShow').addEventListener('click',function(){var i=$('#gKey'),s=i.type==='password';i.type=s?'text':'password';this.textContent=s?'Hide':'Show'});
function gemCheck(){
  var k=$('#gKey').value.trim(),mo=$('#gModel').value.trim(),c=+$('#gCap').value,bad=0;
  var keyOk=(gemConfigured&&!k)||(k.length>=20&&!/\s/.test(k));
  setErr('g-key',keyOk?'':'Paste the full key, with no spaces. Keys are at least 20 characters.');if(!keyOk)bad++;
  setErr('g-model',mo?'':'Enter the model name shown in AI Studio.');if(!mo)bad++;
  setErr('g-cap',c>=1&&c<=200?'':'Enter a number from 1 to 200.');if(!(c>=1&&c<=200))bad++;
  return !bad;
}
function setGemStatus(on){var s=$('#gemStatus');s.className='pill '+(on?'ok':'neutral');s.textContent=on?'Key set':'Not connected'}
var JOB_LABEL={ingest:'Feed ingest and summaries',meter:'Threat meter',digest:'Daily digest'};
function renderJobs(s){
  $('#jobsBody').innerHTML=s.jobs.map(function(j){
    var r=j.lastRun,pill=j.running?'<span class="pill neutral">Running</span>':!r?'<span class="pill neutral">Not run yet</span>':r.status==='ok'?'<span class="pill ok">OK · '+esc(ago(r.finished||r.started))+'</span>':r.status==='running'?'<span class="pill neutral">Running</span>':'<span class="pill sev-critical">Error</span>';
    return '<tr><td><b>'+esc(JOB_LABEL[j.name]||j.name)+'</b></td><td class="mono">'+esc(j.schedule)+'</td><td>'+esc(j.description)+(r&&r.message?'<div class="note" style="margin-top:4px">'+esc(r.message)+'</div>':'')+'</td><td>'+pill+'<div style="margin-top:8px"><button class="btn btn-quiet btn-sm" type="button" data-run="'+esc(j.name)+'"'+(j.running?' disabled':'')+'>Run now</button></div></td></tr>';
  }).join('');
  var c=s.counts;$('#adminCounts').textContent=c.users+' users · '+c.items+' feed items ('+c.summarised+' with AI summaries) · '+c.bookings+' consultation requests'+(s.lastIngest?' · last ingest '+ago(s.lastIngest):'');
}
function loadAdmin(){
  api('/api/admin/status').then(function(s){
    gemConfigured=s.gemini.configured;if(s.gemini.model)$('#gModel').value=s.gemini.model;$('#gCap').value=s.gemini.cap;
    setGemStatus(s.gemini.configured);$('#gKey').placeholder=s.gemini.configured?'A key is stored. Paste a new one to replace it.':'Paste your key from Google AI Studio';
    renderJobs(s);
  }).catch(function(e){toast(e.message)});
}
$('#jobsBody').addEventListener('click',function(e){var b=e.target.closest('[data-run]');if(!b||!LIVE)return;b.disabled=true;
  api('/api/admin/jobs/'+b.dataset.run+'/run',{method:'POST',body:{}}).then(function(){toast('Started. Refresh this tab in a moment to see the result.');setTimeout(loadAdmin,2500)}).catch(function(err){toast(err.message);b.disabled=false})});
$('#gemForm').addEventListener('submit',function(e){
  e.preventDefault();if(!gemCheck())return;
  if(LIVE){
    var body={geminiModel:$('#gModel').value.trim(),geminiCap:+$('#gCap').value},k=$('#gKey').value.trim(),nk=$('#nvdKey').value.trim();
    if(k)body.geminiKey=k;if(nk)body.nvdKey=nk;
    api('/api/admin/settings',{method:'POST',body:body}).then(function(){
      $('#gKey').value='';$('#nvdKey').value='';$('#gKey').type='password';$('#gShow').textContent='Show';
      toast('Saved. Keys are stored encrypted and are never shown again.');loadAdmin();
    }).catch(function(err){var f=err.fields||{};setErr('g-key',f.geminiKey||'');setErr('g-model',f.geminiModel||'');setErr('g-cap',f.geminiCap||'');toast(err.message)});
    return;
  }
  $('#gKey').value='';$('#nvdKey').value='';$('#gKey').type='password';$('#gShow').textContent='Show';var s=$('#gemStatus');s.className='pill ok';s.textContent='Key received (preview)';toast('Preview only: the key was checked and cleared, not stored.');
});
$('#gTest').addEventListener('click',function(){
  if(LIVE){api('/api/admin/gemini-test',{method:'POST',body:{}}).then(function(r){toast(r.message)}).catch(function(err){toast(err.message)});return}
  if(!gemCheck())return;toast('The preview cannot call the Gemini API. On the live site the server runs this test.');
});

/* ---------- auth dialog ---------- */
var signedIn=false,mode='in',dlg=$('#authDlg');
function openAuth(m,msg){setMode(m||'in');if(msg)toast(msg);if(dlg.showModal)dlg.showModal();else dlg.setAttribute('open','')}
function setMode(m){mode=m;$('#aIn').setAttribute('aria-selected',m==='in');$('#aUp').setAttribute('aria-selected',m==='up');$('#authTitle').textContent=m==='in'?'Sign in':'Create account';$('#authSubmit').textContent=m==='in'?'Sign in':'Create account';$('#pwHint').hidden=m==='in';$('#aPw').autocomplete=m==='in'?'current-password':'new-password';setErr('a-email','');setErr('a-pw','')}
$('#signInBtn').addEventListener('click',function(){openAuth('in')});
$('#aIn').addEventListener('click',function(){setMode('in')});$('#aUp').addEventListener('click',function(){setMode('up')});
$('#authClose').addEventListener('click',function(){dlg.close()});
$('#aShow').addEventListener('click',function(){var i=$('#aPw'),s=i.type==='password';i.type=s?'text':'password';this.textContent=s?'Hide':'Show'});
$('#authForm').addEventListener('submit',function(e){
  e.preventDefault();var em=$('#aEmail').value.trim(),pw=$('#aPw').value,bad=0;
  var okE=/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(em);setErr('a-email',okE?'':'Enter a valid email address.');if(!okE)bad++;
  var okP=mode==='in'?pw.length>0:(pw.length>=10&&pw.length<=72);setErr('a-pw',okP?'':(mode==='in'?'Enter your password.':'Use 10 to 72 characters.'));if(!okP)bad++;
  if(bad)return;
  if(LIVE){
    var btn=$('#authSubmit');btn.disabled=true;
    api('/api/auth/'+(mode==='in'?'login':'register'),{method:'POST',body:{email:em,password:pw}}).then(function(j){
      ME=j.user;$('#aPw').value='';setUser();dlg.close();toast(mode==='in'?'Signed in.':'Account created.');if(quiz.done)renderQuiz();
    }).catch(function(err){var f=err.fields||{};setErr('a-email',f.email||'');setErr('a-pw',f.password||(f.email?'':err.message))}).then(function(){btn.disabled=false});
    return;
  }
  signedIn=true;$('#aPw').value='';$('#avatar').textContent=em.charAt(0).toUpperCase();$('#userChip').style.display='inline-flex';$('#signInBtn').hidden=true;dlg.close();toast('Signed in to a preview session. Nothing was stored.');
  if(quiz.done)renderQuiz();
});
$('#signOutBtn').addEventListener('click',function(){
  if(LIVE){api('/api/auth/logout',{method:'POST',body:{}}).then(function(){ME=null;setUser();toast('Signed out.')}).catch(function(err){toast(err.message)});return}
  signedIn=false;$('#userChip').style.display='none';$('#signInBtn').hidden=false;toast('Signed out.');
});
dlg.addEventListener('click',function(e){if(e.target===dlg)dlg.close()});

/* ---------- start ---------- */
function setUser(){
  signedIn=!!ME;
  $('#userChip').style.display=ME?'inline-flex':'none';$('#signInBtn').hidden=!!ME;
  if(ME)$('#avatar').textContent=ME.email.charAt(0).toUpperCase();
  var adm=!LIVE||isAdmin();
  $('#tab-admin').hidden=!adm;$$('[data-go="admin"]').forEach(function(b){b.hidden=!adm});
  if(!adm&&show.cur==='admin')show('overview');
}
function mapItem(x){var u=x.source&&x.source.url;return {id:x.id,type:x.type,sev:x.severity,cvss:x.cvss,kev:x.kev,vendor:x.vendor||'',product:x.product||'',ind:x.industry||'General',when:relTime(x.activity),title:x.title,sum:x.summary,ai:x.ai,url:/^https?:\/\//.test(u||'')?u:'',src:(x.source&&x.source.name)||'source'}}
function applyMeter(j){
  SIGNALS=j.signals.map(function(s){return {id:s.id,name:s.name,sub:s.sub,w:s.w,x:s.x,p90:s.p90}});
  renderSliders();animateMeter();
  var t=$('#meterTag');t.textContent=j.calibrating?'Calibrating':'Live';t.title=j.calibrating?'Some baselines are still starting values until enough history has been collected.':'';
}
function applyFeed(j){
  FEED=j.items.map(mapItem);
  fillSel('#fVendor','All vendors',uniq('vendor'));fillSel('#fIndustry','All industries',uniq('ind'));fillSel('#fType','All types',uniq('type'));
  renderHome();renderFeed();
}
function applyDigest(j){DIGEST=j.items.map(mapItem);renderHome()}
function applyDir(j){
  DIR=j.entries.map(function(e){return [e.name,e.category,e.purpose,e.license||'Unspecified',e.platforms,e.url,e.reviewedOn]});
  buildDirFilters();renderDir();
}
function applyLive(){
  $('#adminBanner').hidden=true;
  $('#feedNote').textContent='Summaries are generated by an AI model from public advisory text and may contain mistakes. Check the source before acting.';
  $('#dirNote').textContent="Entries without a review date are waiting for their first review. Check each project's own site for current details.";
  api('/api/meter').then(applyMeter).catch(noop);
  api('/api/feed?limit=100').then(applyFeed).catch(noop);
  api('/api/feed/digest').then(applyDigest).catch(noop);
  api('/api/directory').then(applyDir).catch(noop);
}
function initLive(){
  if(location.protocol.indexOf('http')!==0)return;
  api('/api/me').then(function(j){LIVE=true;ME=j.user;setUser();applyLive()}).catch(noop);
}
show(location.hash.slice(1)||'overview',{keep:true});
initLive();
})();
