// /static/js/passkey.js

async function showPasskeyLogin() {
    // Fetch the username from the session (the backend should set the session)
    const response = await fetch('/get_username', { method: 'GET' });
    const result = await response.json();

    if (!response.ok || !result.username) {
        alert("You must be logged in to use passkey login.");
        return;
    }

    const username = result.username; // Use the session-based username

    try {
        // Simulate signing the login request
        const message = "Login request";
        const encodedMessage = new TextEncoder().encode(message);
        const signature = btoa(new Uint8Array(encodedMessage).reduce((data, byte) => data + String.fromCharCode(byte), ""));

        // Send passkey login request
        const loginResponse = await fetch('/passkey_login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, signature }),
        });

        const loginResult = await loginResponse.json();

        if (loginResponse.ok) {
            alert("Login successful! Welcome, " + username + ".");
            window.location.href = '/protected';
        } else {
            alert("Passkey login failed: " + loginResult.error);
        }
    } catch (error) {
        console.error("Error during passkey login:", error);
        alert("An error occurred during passkey login. Please try again.");
    }
}
