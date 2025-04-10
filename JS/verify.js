document.addEventListener('DOMContentLoaded', () => {
    const verifyForm = document.getElementById('verifyForm');
    const verifyButton = document.getElementById('verifyButton');
    const mensajeError = document.getElementById('mensajeError');
    const tempToken = localStorage.getItem('tempToken');

    // Verificar si hay token temporal
    if (!tempToken) {
        mostrarError('No se encontró sesión de verificación. Serás redirigido...');
        setTimeout(() => window.location.href = 'login.html', 3000);
        return;
    }

    // Función para verificar el código
    const verificarCodigo = async (e) => {
        if (e) e.preventDefault();
        
        const code = document.getElementById('code').value.trim();
        
        // Validación del código
        if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
            mostrarError('Por favor ingrese un código de 6 dígitos');
            return;
        }

        try {
            const response = await fetch('https://localhost/verifyCode', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${tempToken}`
                },
                body: JSON.stringify({ code })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Error en la verificación');
            }

            // Procesar respuesta exitosa
            if (data.success) {
                // 1. Limpiar el token temporal
                localStorage.removeItem('tempToken');
                
                // 2. Guardar el nuevo token de acceso
                localStorage.setItem('authToken', data.token);
                
                // 3. Guardar datos del usuario
                localStorage.setItem('userData', JSON.stringify(data.user));
                
                // 4. Redirigir a la página principal (sin verificar rol)
                window.location.href = 'catalogo.html';
            }
        } catch (error) {
            console.error('Error en verificación:', error);
            
            if (error.message.includes('Token inválido') || error.message.includes('expirado')) {
                localStorage.removeItem('tempToken');
                mostrarError('La sesión ha expirado. Serás redirigido...');
                setTimeout(() => window.location.href = 'login.html', 3000);
            } else {
                mostrarError(error.message || 'Error al verificar el código');
            }
        }
    };

    // Manejadores de eventos
    verifyForm.addEventListener('submit', verificarCodigo);
    verifyButton.addEventListener('click', verificarCodigo);

    // Función para mostrar mensajes de error
    function mostrarError(mensaje) {
        mensajeError.textContent = mensaje;
        mensajeError.style.display = 'block';
        setTimeout(() => {
            mensajeError.style.display = 'none';
        }, 5000);
    }
});