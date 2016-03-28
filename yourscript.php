<!doctype html>
<html>
 <head>
  <title>Process and store</title>
 </head>
<body>
<?php

// Check that user sent some data to begin with. 
if (isset($_REQUEST['yourfield'])) {

    /* Sanitize input. Trust *nothing* sent by the client.
     * When possible use whitelisting, only allow characters that you know
     * are needed. If username must contain only alphanumeric characters,
     * without puntation, then you should not accept anything else.
     * For more details, see: http://stackoverflow.com/a/10094315
     */
    $yourfield=preg_replace('/[^a-zA-Z0-9\ ]/','',$_REQUEST['yourfield']);

    /* Escape your input: use htmlspecialchars to avoid most obvious XSS attacks.
     * Note: Your application may still be vulnerable to XSS if you use $yourfield
     *       in an attribute without proper quoting.
     * For more details, see: http://stackoverflow.com/a/130323
     */
    $yourfield=htmlspecialchars($yourfield);


} else {
    die('User did not send any data to be saved!');
}


// Define MySQL connection and credentials
$pdo_dsn='mysql:dbname=yourdatabase;host=databasehost.example.com';
$pdo_user='yourdatabaseuser';     
$pdo_password='yourdatabaspassword';  

try {
    // Establish connection to database
    $conn = new PDO($pdo_dsn, $pdo_user, $pdo_password);

    // Throw exceptions in case of error.
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Use prepared statements to mitigate SQL injection attacks.
    // See http://stackoverflow.com/questions/60174/how-can-i-prevent-sql-injection-in-php for more details
    $qry=$conn->prepare('INSERT INTO yourtable (yourcolumn) VALUES (:yourvalue)');

    // Execute the prepared statement using user supplied data.
    $qry->execute(Array(":yourvalue" => $yourfield));

} catch (PDOException $e) {
    echo 'Error: ' . $e->getMessage() . " file: " . $e->getFile() . " line: " . $e->getLine();
    exit;
}
?>
<form method="post">

 <!-- Please note that the quotes around next <?php ... ?> block are important
      to avoid XSS issues with poorly escaped user input. For more details:
      http://stackoverflow.com/a/2894530
  -->
 <input type="text" name="yourfield" value="<?php print $yourfield; ?>">
 <input type="submit" name="youraction" value="save">
</form>

</body>
</html>