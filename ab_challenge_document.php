<?php 
  //. This page is a template, enduser can make a custom template that fits in with their ui. 
    // ==> WHen making your own HTML challenge page, you should always have the link to the JS file included as well as the PHP path
          // the page should have the ID 'challenge-ui' to make the captcha work. 
          // basically don't touch anything outside hte body tag. 
  
  //TODO: maybe consider adding I18N? 
  //TODO: further split this file up so templates are fully end-user controlled and required elements are app-given.



  $cachebreaker = floor(time() / 7200); //for the JS file so no user ever has a check file older than 2 hrs. 
?>

<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Security Check</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{
        font-family:Arial,Helvetica,sans-serif;
        display:flex;
        align-items:center;
        justify-content:center;
        height:100vh;
        margin:0;
        background:#f2f4f7
      }
      #app{
        max-width:820px;
        padding:20px;
        text-align:center;
        background:white;
        border-radius:8px;
        box-shadow:0 6px 18px rgba(0,0,0,0.08)
      }
      
    </style>
    <script>window.__AB_PROTECT_REQUEST_PATH = <?php echo json_encode($currentPath); ?>;</script>
    <script src="/ab_bot-check.js?v=<?php echo $cachebreaker; ?>" defer></script>
  </head>

  <body>
    <div id="app">
      <h2>Security Check</h2>
      <p>We will perform a short browser check. If a captcha is required, it will appear below.</p>
    <div id="challenge-ui"></div>
    </div>
  </body>
</html>