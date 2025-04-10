document.addEventListener('DOMContentLoaded', async () => {
    // Elementos del DOM
    const mensajeEstado = document.getElementById('mensajeEstado');
    const registroForm = document.getElementById('registroLibroForm');
    
    // Verificar autenticación al cargar la página
    await verificarAutenticacion();
    
    // Función principal para verificar autenticación y permisos
    async function verificarAutenticacion() {
        const token = localStorage.getItem('authToken');
        
        // 1. Verificar si hay token de autenticación
        if (!token) {
            mostrarMensaje('error', 'No estás autenticado. Serás redirigido al login...');
            setTimeout(() => window.location.href = 'login.html', 2000);
            return;
        }
        
        // 2. Verificar permisos de administrador
        try {
            mostrarMensaje('cargando', 'Verificando permisos de administrador...');
            
            const response = await fetch('https://localhost/checkAdminSession', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`Error HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            
            // 3. Verificar si es administrador
            if (data.isAdmin) {
                mostrarMensaje('exito', 'Permisos de administrador verificados');
                registroForm.style.display = 'block';
                configurarFormulario();
            } else {
                throw new Error('No tienes permisos de administrador');
            }
            
        } catch (error) {
            console.error('Error en verificación:', error);
            mostrarMensaje('error', error.message || 'Error al verificar permisos');
            setTimeout(() => window.location.href = 'catalogo.html', 3000);
        }
    }
    
    // Configurar el formulario de registro
    function configurarFormulario() {
        registroForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Validar campos antes de enviar
            if (!validarFormulario()) return;
            
            try {
                mostrarMensaje('cargando', 'Registrando libro...');
                
                const formData = {
                    nombre: document.getElementById('nombre').value.trim(),
                    autor: document.getElementById('autor').value.trim(),
                    genero: document.getElementById('genero').value,
                    descripcion: document.getElementById('descripcion').value.trim(),
                    estado: document.getElementById('estado').value,
                    imagen: document.getElementById('imagen').value.trim()
                };
                
                // Validar URL de imagen
                if (!validarURL(formData.imagen)) {
                    throw new Error('La URL de la imagen no es válida');
                }
                
                const token = localStorage.getItem('authToken');
                const response = await fetch('https://localhost/registrarLibro', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                const result = await response.json();
                
                if (!response.ok) {
                    throw new Error(result.message || 'Error al registrar libro');
                }
                
                mostrarMensaje('exito', 'Libro registrado exitosamente!');
                registroForm.reset();
                
            } catch (error) {
                console.error('Error al registrar:', error);
                mostrarMensaje('error', error.message || 'Error al registrar el libro');
            }
        });
    }
    
    // Función para validar el formulario
    function validarFormulario() {
        const camposRequeridos = ['nombre', 'autor', 'descripcion', 'imagen'];
        let valido = true;
        
        camposRequeridos.forEach(campo => {
            const elemento = document.getElementById(campo);
            if (!elemento.value.trim()) {
                elemento.style.borderColor = 'red';
                valido = false;
            } else {
                elemento.style.borderColor = '';
            }
        });
        
        if (!valido) {
            mostrarMensaje('error', 'Por favor completa todos los campos requeridos');
        }
        
        return valido;
    }
    
    // Función para validar URLs
    function validarURL(url) {
        try {
            new URL(url);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    // Función para mostrar mensajes de estado
    function mostrarMensaje(tipo, mensaje) {
        const tiposMensaje = {
            'cargando': { clase: 'mensaje-cargando', texto: '⏳ ' + mensaje },
            'error': { clase: 'mensaje-error', texto: '❌ ' + mensaje },
            'exito': { clase: 'mensaje-exito', texto: '✅ ' + mensaje }
        };
        
        const mensajeConfig = tiposMensaje[tipo] || tiposMensaje.error;
        mensajeEstado.innerHTML = `
            <div class="${mensajeConfig.clase}">
                <p>${mensajeConfig.texto}</p>
            </div>
        `;
    }
    
    // Resetear estilos al cambiar campos
    document.querySelectorAll('#registroLibroForm input, #registroLibroForm textarea').forEach(input => {
        input.addEventListener('input', () => {
            input.style.borderColor = '';
        });
    });
});