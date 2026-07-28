async function deriveKey(password, salt) {
    const encoder = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 200000,
            hash: "SHA-256"
        },
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["decrypt"]
    );
}

function base64ToBytes(base64) {

    const binary = atob(base64);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

document.addEventListener("DOMContentLoaded", () => {

    const container = document.getElementById("protected-post");

    if (!container) return;

    const slug = container.dataset.slug;

    const passwordBox = document.getElementById("password");
    const unlockButton = document.getElementById("unlock");
    const error = document.getElementById("error");

    // Hide the error as soon as the user starts typing
    passwordBox.addEventListener("input", () => {

        error.classList.add("hidden");
        error.textContent = "";

    });

    // Press Enter to unlock
    passwordBox.addEventListener("keydown", (event) => {

        if (event.key === "Enter") {

            event.preventDefault();
            unlockButton.click();

        }

    });

    unlockButton.addEventListener("click", async () => {

        const password = passwordBox.value;

        error.textContent = "";
        error.classList.add("hidden");

        unlockButton.disabled = true;
        unlockButton.textContent = "Unlocking...";

        try {

            const response = await fetch(`/encrypted/${slug}.json`);

            if (!response.ok) {
                throw new Error("Could not load encrypted article.");
            }

            const data = await response.json();

            const key = await deriveKey(
                password,
                base64ToBytes(data.salt)
            );

            const cipher = base64ToBytes(data.ciphertext);
            const tag = base64ToBytes(data.tag);

            const combined = new Uint8Array(cipher.length + tag.length);

            combined.set(cipher);
            combined.set(tag, cipher.length);

            const plaintext = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: base64ToBytes(data.nonce)
                },
                key,
                combined
            );

            const markdown = new TextDecoder().decode(plaintext);

            // Replace the entire lock screen with the article
            container.innerHTML = marked.parse(markdown);

        }
        catch (e) {

            console.error(e);

            error.textContent = "❌ Incorrect password. Please try again.";
            error.classList.remove("hidden");

            unlockButton.disabled = false;
            unlockButton.textContent = "Unlock";

            passwordBox.focus();
            passwordBox.select();

        }

    });

});