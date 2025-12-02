# SPHINX
**System for Preventing Hijacked & Impersonated Network eXecution**

SPHINX is a PHP based anti-bot tool that can be integrated in any PHP-project. 

## Installation: 
1) Extract all files that cary the `ab_`-prefix and put them in the root directory of your project
2) Configure `ab_config.php` according to the configuration comments
3) You can use an optional whitelist file to automatically approve good bots such as GoogleCrawler. A good list is curated by [AnTheMaker](https://github.com/AnTheMaker/GoodBots), download the `all.ips` file from that repository, put it in your webroot and set the `goodbotfile` key to where the file is located. 

## UI Customization: 
You can provide a customized styling for the POW-/CAPTCHA page. You simple update the file `ab_challenge_document.php`. The minimum requirement for this file's content is this: 
```
<?php 
  $cachebreaker = floor(time() / 7200); //for the JS file so no user ever has a check file older than 2 hrs. 
?>
<!doctype html>
<html lang="en">
  <head>
    <script>window.__AB_PROTECT_REQUEST_PATH = <?php echo json_encode($currentPath); ?>;</script>
    <script src="/ab_bot-check.js?v=<?php echo $cachebreaker; ?>" defer></script>
  </head>

  <body>
    <div id="app">
    <div id="challenge-ui"></div>
    </div>
  </body>
</html>
```

## Version history: 
**V1: Antibot (13/11/2025)**
    proof of concept code

**V2: SPHINX (02/12/2025)**
    - Added CAPTCHA code
    - Added IP whitelisting
    - Added PATH whitelisting
    - Added central configuration file
    - Added pragmatic garbage collecting
    - Renamed project



## TODOS: 
1) make garbage collecting a configurable parameter so end users can use CRON
2) Add the option to include different kind of CAPTCHA challenge. 
3) Add I18N
4) Add digital noise to CAPTCHA challenges
5) Add rate limiting
