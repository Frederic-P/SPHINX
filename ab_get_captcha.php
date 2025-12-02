<?php
header('Content-Type: image/svg+xml; charset=utf-8');

/*    Generates the captcha that belongs to the current capid token.
      Upon captcha renewal, the capid is re-used. 
      Inproper ways of trying to get the captcha are blocked with 4XX codes. 
*/

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); 
    header('Allow: POST'); 
    exit;
}
$config = include __DIR__ . '/ab_config.php';

$data = $_POST;
if (!$data || !isset($data['capid'])) {
    http_response_code(400); 
    exit; 
}

$capid = preg_replace('/[^a-f0-9]/','', $data['capid']);
$capdir = $config['storage_dir'] . '/_captchas/';

$capFile = $capdir . $capid;

if (!file_exists($capFile)) {
    http_response_code(404); 
    exit; 
}

$meta = json_decode(file_get_contents($capFile), true);
if ($meta['used'] || time() > $meta['expires']) { 
    http_response_code(410); 
    exit;
}

$txt = $meta['solution'];
//size of image box:
//TODO ==> If the length of the captcha is increased @ ab_verify.php > captchaLength then the width should be expanded
//    SO: move $captchaLength to the config file and express $w as a mutliple of captchaLength. 
$w = 320;
$h = 90;
$bg = '#F7F7F7';

$svg = [];
$svg[] = '<?xml version="1.0" encoding="UTF-8"?>';
$svg[] = "<svg xmlns='http://www.w3.org/2000/svg' width='$w' height='$h' viewBox='0 0 $w $h'>";
$svg[] = "<rect width='100%' height='100%' fill='$bg'/>";
//noise: 
//  random lines: 
for ($i=0; $i<10; $i++ ){
  $x1 = random_int(0,$w); $y1 = random_int(0,$h);
  $x2 = random_int(0,$w); $y2 = random_int(0,$h);
  $stroke = sprintf('#%06x', random_int(0,0xFFFFFF));
  $svg[] = "<line x1='$x1' y1='$y1' x2='$x2' y2='$y2' stroke='$stroke' stroke-width='2' opacity='0.6'/>";
}

$len = strlen($txt);
$startX = 28;
//  display the characters (but with twisted effect)
for ($i=0; $i<$len; $i++ ){
  $ch = htmlspecialchars($txt[$i]);
  $x = $startX + $i * 34 + random_int(-3,3);
  $y = 55 + random_int(-8,8);
  $rot = random_int(-30,30);
  $fontSize = random_int(32,44);
  $fill = sprintf('#%06x', random_int(0,0x333333));
  $svg[] = "<text x='$x' y='$y' transform='rotate($rot $x,$y)' font-family='Verdana,Arial' font-size='$fontSize' fill='$fill'>$ch</text>";
}
//  random dots. 
for ($i=0;$i<40;$i++){
  $cx = random_int(0,$w); $cy = random_int(0,$h);
  $r = random_int(1,3);
  $fill = sprintf('#%06x', random_int(0,0xFFFFFF));
  $svg[] = "<circle cx='$cx' cy='$cy' r='$r' fill='$fill' opacity='0.7'/>";
}

//TODO ==> Digital noise not really worth it, need to find other implementation. 
// digital noise
// $svg[] = "<defs>";
// $svg[] = "<filter id='noise'>";
// $svg[] = "<feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' result='noise'/>";
// $svg[] = "<feColorMatrix in='noise' type='saturate' values='0'/>";
// $svg[] = "<feBlend in='SourceGraphic' in2='noise' mode='multiply' result='blend'/>";
// $svg[] = "</filter>";
// $svg[] = "</defs>";
// $svg[] = "<rect width='100%' height='100%' fill='$bg' opacity='0.2'/>";
// $svg[] = "<rect width='100%' height='100%' fill='white' filter='url(#noise)' opacity='0.2'/>";

$svg[] = "</svg>";
echo implode("\n",$svg);

// delete stale captcha files: 
include_once('ab_gc.php');
gc_cleanup($capdir, $config['captcha_ttl']*1.1);
exit;
?>
