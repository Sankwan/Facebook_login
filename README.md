<!-- FACEBOOK FAKE LOGIN PAGE
![facebook_login](https://user-images.githubusercontent.com/37655056/196322562-77c1a74b-7c50-4bc6-a22d-1b8840e95554.png)
![facebook_login_phone](https://user-images.githubusercontent.com/37655056/196586834-347752e9-412c-465d-86fe-1e4c7b862021.png) -->

Phishing Lessons for Cyber Security
Facebook Login Page

This is a simple web page with similar characteristics 
as the Facebook page itself.

The page has two fields for the email/phone number and password

On tap of the login button, the credentials of the user are captured on the server
(including a timestamp, the client IP address and an approximate location) and then
the visitor is redirected to the real Facebook login page without knowing that
their information has been logged.

A simple external service (ip-api.com) is used to perform a best‑effort geolocation
lookup. If the server receives a loopback or private address (e.g. during local
testing), the code will instead label the entry `Local network` rather than
querying the external service. You will need the `requests` Python package
installed (`pip install requests`).

All of this data is saved to `credentials.json` for demonstration and can be viewed
through the live dashboard (`/dashboard`).