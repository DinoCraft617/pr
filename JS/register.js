async function register() {
    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim().toLowerCase();
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    // Validación básica (igual que antes)
    if (!username || !email || !password || !confirmPassword) {
        alert("Por favor complete todos los campos");
        return;
    }

    if (password !== confirmPassword) {
        alert("Las contraseñas no coinciden");
        return;
    }

    try {
        const response = await fetch("https://localhost/registerUser", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({ username, email, password, confirmPassword })
        });

        // Manejo mejorado de la respuesta
        if (!response.ok) {
            const errorData = await response.json().catch(() => null);
            const errorMessage = errorData?.error || `Error HTTP: ${response.status}`;
            throw new Error(errorMessage);
        }

        const data = await response.json();

        if (data.success) {
            alert(data.message || "Registro exitoso");
            window.location.href = "/HTML/login.html";
        } else {
            throw new Error(data.error || "Error en el registro");
        }
    } catch (error) {
        console.error("Error completo:", error);
        alert(`Error al registrar: ${error.message}`);
    }
}

// Mismo event listener
document.getElementById("registerButton").addEventListener("click", async (e) => {
    e.preventDefault();
    await register();
});