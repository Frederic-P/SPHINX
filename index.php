<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    
    
    <?php 
    include_once('ab_protect.php');
    echo 'test';
    echo '<p>go to <a href="p2.php">detail</a></p>';
    
    @var_dump($clientIp);
?>
</body>
</html>