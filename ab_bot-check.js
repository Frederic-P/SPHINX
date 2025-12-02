// ab_bot-check.js
// Client-side script (PoW + fingerprint + captcha UI).

(function(){
  //TODO: document that challenge-ui must exists
  //  BUT in case user does not do that, the whole body is used as canvastarget.
  const ui = document.getElementById('challenge-ui') || document.body;
  //helper function (add message for the end user one by one if needed)
  function addMsg(t){
    ui.innerHTML = ('<p>'+t+'</p>') + ui.innerHTML; 
  }

  //helper function: perform an async JSONbody request that does NOT cache!
  async function postJson(path, payload) {
    const r = await fetch(path, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload),
      credentials: 'same-origin',
      cache: 'no-store'
    });
    return r;
  }

  //uses the async JSON helper function
  // asks for a challenge and receives a nonce
  async function getChallenge() {
    const r = await postJson('/ab_challenge.php', {}); // POST, no params
    if (!r.ok) throw new Error('challenge failed');
    return r.json();
  }

  //WebCrypto API: 
  // https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

  //get a hexadecimal string.
  function buf2hex(buffer){
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,'0')).join('');
  }
  //use the modern webcrypto API if it available
  async function sha256Hex(s){
    if (window.crypto && window.crypto.subtle) {
      const enc = new TextEncoder();
      const buf = enc.encode(s);
      const digest = await crypto.subtle.digest('SHA-256', buf);
      return buf2hex(digest);
    } else {
      return fallbackSHA256(s);
    }
  }
  // on older browsers: use the older fallback methods. ==> beware is slow!
  function fallbackSHA256(ascii) {
    function rightRotate(value, amount) { 
      return (value>>>amount) | (value<<(32 - amount)); 
    }
    var mathPow = Math.pow, maxWord = mathPow(2,32);
    var result = '', words = [], asciiBitLength = ascii.length*8, i, j;
    var hash = [], k = [], primeCounter = 0;
    var isComposite = {};
    for (var candidate=2; primeCounter < 64; candidate++){
      if (!isComposite[candidate]){
        for (i = candidate*candidate; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (mathPow(candidate, .5) * maxWord)|0;
        k[primeCounter++] = (mathPow(candidate, 1/3) * maxWord)|0;
      }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (i=0;i<ascii.length;i++){
      j = ascii.charCodeAt(i);
      if (j>>8) return;
      words[i>>2] |= j << ((3 - i)%4)*8;
    }
    words.push((asciiBitLength/maxWord)|0);
    words.push((asciiBitLength)|0);
    var w, oldHash;
    for (j=0;j<words.length;){
      w = words.slice(j, j+=16);
      oldHash = hash.slice(0);
      if (oldHash.length === 0) {
        oldHash = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];
      }
      hash = oldHash.slice(0);
      for (i=0;i<64;i++){
        var w15 = w[i-15], w2 = w[i-2];
        var a = hash[0], e = hash[4];
        var temp1 = hash[7] + (rightRotate(e,6) ^ rightRotate(e,11) ^ rightRotate(e,25)) + ((e & hash[5]) ^ ((~e) & hash[6])) + (k[i]||0) + (w[i] = (i<16) ? w[i] : ((w[i-16] + (rightRotate(w15,7) ^ rightRotate(w15,18) ^ (w15>>>3)) + w[i-7] + (rightRotate(w2,17) ^ rightRotate(w2,19) ^ (w2>>>10)))|0));
        var temp2 = (rightRotate(a,2) ^ rightRotate(a,13) ^ rightRotate(a,22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2)|0].concat(hash);
        hash[4] = (hash[4] + temp1)|0;
      }
      for (i=0;i<8;i++) hash[i] = (hash[i] + oldHash[i])|0;
    }
    for (i=0;i<8;i++){
      for (j=3;j+1;j--){
        var b = (hash[i]>>(j*8)) & 255;
        result += (b < 16 ? '0' : '') + b.toString(16);
      }
    }
    return result;
  }

  // bots don't really have a proper canvas implementation, this should rat them out
  //  added bonus, each system creates a unique hash based on whatever comes out of this. 
  function canvasFingerprint(){
    try{
      const c = document.createElement('canvas');
      c.width = 200; c.height = 50;
      const ctx = c.getContext('2d');
      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#111";
      ctx.fillText("Fingerprint test 12345", 2, 2);
      return c.toDataURL();
    }catch(e){ return ''; }
  }

  //check if the user does something while the POW is going on? This would help them. 
  //  i.e. is the mouse being moved or something?
  let interacted = false;
  ['mousemove','keydown','touchstart'].forEach(ev => window.addEventListener(ev, ()=>interacted=true, {once:true}));

  async function main(){
    try {
      addMsg('Requesting challenge...');
      const ch = await getChallenge();
      const {nonce,difficulty,expires} = await ch;
      //we need to keep track of time (ie. when does the compute starts?)
      const t_request = Math.floor(Date.now() / 1000);
      //try to detect automation tools (selenium, puppeteer). (can this be spoofed??) ==> force as bools anyway
      const webdriver = !!navigator.webdriver;
      const hasCrypto = !!(window.crypto && crypto.subtle);
      const canvasFP = canvasFingerprint();

      addMsg('Computing proof-of-work (may take a moment)...');
      const required = '0'.repeat(difficulty);
      let found = false;
      let suffix = 0;
      const maxIter = 2000000;
      const start = performance.now();
      for (; suffix < maxIter; suffix++) {
        const candidate = nonce + suffix.toString(16);
        const h = await sha256Hex(candidate);
        if (h.substring(0,difficulty) === required) { 
          found = true; 
          suffix = suffix.toString(16); 
          break;
        }
        if ((suffix & 127) === 0) {
          await new Promise(r=>setTimeout(r,0));
        }
        if (performance.now() - start > 9000) {
          break;
        }
      }
      if (!found) { 
        addMsg('POW not found (device too slow).');
        return; 
      }
      addMsg('POW found, submitting for verification...');
      //after test of the client is complete, make a score for the client's browser based on the features you got out from it:
      let score = 0;
      if (!webdriver){
        score += 3;
      }
      if (hasCrypto){
        score += 1;
      }
      if (canvasFP && canvasFP.length > 50){
        score += 2;
      }
      if (interacted){
        score += 2;
      }
      const elapsed = (performance.now() - start)/1000;
      // between 600ms and 15sec = probably real browser
      if (elapsed > 0.6 && elapsed < 15){
        score += 2;
      }
      //Too slow ==> probably a bot
      if (elapsed > 15){
        score -= 1;
      }

      //prepare test results into dict to send to server ==> let the server determine if the request can be trusted or not? 
      const payload = { 
        nonce: nonce, 
        suffix: suffix, 
        score: score, 
        details: { 
          webdriver: webdriver, 
          hasCrypto: hasCrypto, 
          elapsed: elapsed, 
          ts_request: t_request, 
          interacted: interacted } 
        };
      //uses the async JSON helper function
      const vres = await postJson('/ab_verify.php', payload);
      const j = await vres.json();

      if (j.ok === true) {
        addMsg('Access accepted. Redirecting...');
        const originalPath = window.__AB_PROTECT_REQUEST_PATH || '/';
        window.location.href = originalPath;
        return;
      }

      if (j.captcha) {
        addMsg('Captcha required.');
        showCaptchaUI(j.capid);
        return;
      }

      addMsg('Unexpected server response: ' + (j.msg||''));
    } catch (e) {
      console.error(e);
      addMsg('Error during verification. Please reload the page.');
    }
  }

  // show captcha UI and fetch SVG via POST (no URL params)
function showCaptchaUI(capid){
  ui.innerHTML = `
    <div style="max-width:480px;margin:12px auto;text-align:left">
      <p>Please solve the CAPTCHA (8 uppercase letters or digits).</p>
      <div id="captcha-wrap" style="display:flex;gap:12px;align-items:center">
        <img id="captcha-img" alt="captcha" style="height:90px;border:1px solid #ccc;padding:6px;background:#fff;display:block"/>
        <div style="flex:1">
          <input id="captcha-input" placeholder="Enter the 8 characters" style="width:100%;padding:8px;font-size:16px"/>
          <div style="margin-top:8px;display:flex;gap:8px">
            <button id="captcha-submit">Submit</button>
            <button id="captcha-refresh">Refresh</button>
          </div>
          <div id="captcha-feedback" style="margin-top:8px;color:#a00"></div>
        </div>
      </div>
    </div>`;

  const img = document.getElementById('captcha-img');
  const feedback = document.getElementById('captcha-feedback');
  const refreshBtn = document.getElementById('captcha-refresh');

  async function loadSvg() {
    feedback.textContent = 'Loading captcha image...';
    refreshBtn.disabled = true;
    // build form POST
    const form = new FormData();
    form.append('capid', capid);

    try {
      const r = await fetch('/ab_get_captcha.php', {
        method: 'POST',
        body: form,
        credentials: 'same-origin',
        cache: 'no-store'
      });

      if (!r.ok) {
        feedback.textContent = `Failed to load captcha (HTTP ${r.status})`;
        refreshBtn.disabled = false;
        return;
      }

      const blob = await r.blob();

      // optional: verify MIME type (server must send image/svg+xml)
      if (!blob.type || !blob.type.includes('svg')) {
        // still try, but warn
        console.warn('captcha blob type:', blob.type);
      }

      // create object URL and attach to img
      const url = URL.createObjectURL(blob);
      // cleanup previous objectURL if any
      if (img.__ab_obj_url) {
        URL.revokeObjectURL(img.__ab_obj_url);
      }
      img.__ab_obj_url = url;

      // set handlers
      img.onload = () => {
        feedback.textContent = '';
        refreshBtn.disabled = false;
        // revoke after a short delay to ensure rendering is complete (or revoke on unload)
        setTimeout(()=> {
          if (img.__ab_obj_url) {
            URL.revokeObjectURL(img.__ab_obj_url);
            img.__ab_obj_url = null;
          }
        }, 2000);
      };
      img.onerror = (ev) => {
        feedback.textContent = 'Failed to render captcha image';
        console.error('img.onerror', ev);
        // attempt fallback: put SVG text into an inline <div> (debugging)
        r.text().then(txt => {
          console.log('SVG text fallback:', txt.slice(0,300));
        }).catch(()=>{});
        refreshBtn.disabled = false;
      };

      //TODO: set the width of the captcha dynamicallly in case we ever make the characterlength a configurabla parmeter
      img.style.width = '320px';
      img.style.height = (90 + 'px');

      img.src = url;

    } catch (err) {
      console.error(err);
      feedback.textContent = 'Network error while loading captcha';
      refreshBtn.disabled = false;
    }
  }

  loadSvg();
  refreshBtn.addEventListener('click', ()=> loadSvg());

  document.getElementById('captcha-submit').addEventListener('click', async ()=>{
    const val = document.getElementById('captcha-input').value.trim().toUpperCase();
    feedback.textContent = 'Checking...';
    try {
      const rr = await fetch('/ab_verify_captcha.php', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ capid: capid, solution: val, request_path: window.__AB_PROTECT_REQUEST_PATH || window.location.pathname })
      });
      const jj = await rr.json();
      if (jj.ok) {
        // server sets HttpOnly token cookie; redirect to original page
        const originalPath = window.__AB_PROTECT_REQUEST_PATH || '/';
        window.location.href = originalPath;
      } else {
        feedback.textContent = (jj.msg || 'Wrong');
      }
    } catch(e){
      console.error(e);
      feedback.textContent = 'Network error';
    }
  });
}


  // Start
  main();
})();
