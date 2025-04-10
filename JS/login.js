document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const mensajeError = document.getElementById('mensajeError');

    async function handleLogin(event) {
        event.preventDefault();
        
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;

        if (!email || !password) {
            mostrarError('Por favor complete todos los campos');
            return;
        }

        try {
            const response = await fetch('https://localhost/loginUser', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Error en el login');
            }

            if (data.success) {
                mostrarExito('Código enviado. Revisa tu correo.');
                localStorage.setItem('tempToken', data.token);
                
                // Redirigir después de 3 segundos
                setTimeout(() => {
                    window.location.href = 'verify.html';
                }, 3000);
            }
        } catch (error) {
            console.error('Error en login:', error);
            mostrarError(error.message || 'Error de conexión');
        }
    }

    function mostrarError(mensaje) {
        mensajeError.textContent = mensaje;
        mensajeError.style.color = 'red';
        mensajeError.style.display = 'block';
    }

    function mostrarExito(mensaje) {
        mensajeError.textContent = mensaje;
        mensajeError.style.color = 'green';
        mensajeError.style.display = 'block';
    }

    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
});