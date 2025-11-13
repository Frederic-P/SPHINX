
(async function(){
  // skip if already have the server session cookie (server sets it HttpOnly so JS can't read it)
  // we detect absence indirectly: request challenge and verify flow will set cookie on success.
  try {
    const c = await fetch('/challenge.php', {cache: 'no-store'});
    if (!c.ok) return;
    const {nonce, difficulty, expires} = await c.json();

    // quick abort if expired
    if (Date.now()/1000 > expires) return;

    // helper: hex from buffer
    function buf2hex(buffer){ return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,'0')).join(''); }

    // use subtle.digest to check hashes
    async function sha256Hex(s){
      const enc = new TextEncoder();
      const buf = enc.encode(s);
      const digest = await crypto.subtle.digest('SHA-256', buf);
      return buf2hex(digest);
    }

    // optional browser feature checks to raise bar for bots
    if (navigator.webdriver) {
      // headless automation flagged
      // you can bail out or continue with higher difficulty
      console.warn('webdriver detected');
      // we should probably implement a CAPTCHA system for webdriver based bots. 
    }

    // proof-of-work loop: find suffix string such that sha256(nonce+suffix) has difficulty leading zeros hex
    const required = '0'.repeat(difficulty);

    let suffix = 0;
    const maxIterations = 2000000; // safety cap
    const start = performance.now();
    let found = false;
    for (; suffix < maxIterations; suffix++) {
      const candidate = nonce + suffix.toString(16);
      const h = await sha256Hex(candidate);
      if (h.substring(0,difficulty) === required) {
        found = true;
        suffix = suffix.toString(16);
        break;
      }
      // light cooperative yield every 256 iters so UI/browser doesn't freeze
      if ((suffix & 255) === 0) await new Promise(r => setTimeout(r, 0));
      // give up early if too slow
      if (performance.now() - start > 10000) break; // 10s cap
    }

    if (!found) {
      console.warn('PoW not found');
      return;
    }

    // send proof to server
    await fetch('/verify.php', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({nonce: nonce, suffix: suffix})
    });

    // on success server sets HttpOnly cookie; reload to get content
    window.location.reload();

  } catch (e) {
    console.error('bot-check error', e);
  }
})();

