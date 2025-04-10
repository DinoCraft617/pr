// Función para mostrar mensajes de depuración
function debug(message) {
    console.log(`[DEBUG] ${message}`);
}

// Verificar si los elementos del DOM existen
function verifyElements() {
    for (const [key, element] of Object.entries(elements)) {
        if (!element) {
            console.error(`Elemento no encontrado: ${key}`);
            return false;
        }
    }
    return true;
}

// Elementos del DOM con verificación segura (declaración única)
const elements = {
    toggleButton: document.getElementById('toggleCarrusel'),
    carruselContainer: document.getElementById('carruselContainer'),
    carrusel: document.querySelector('.carrusel'),
    prevBtn: document.querySelector('.prev-btn'),
    nextBtn: document.querySelector('.next-btn'),
    settingsButton: document.getElementById('settingsButton'),
    registerBookButton: document.getElementById('registerBookButton'),
    scrollSection: document.getElementById('scrollSection'),
    genreButtons: document.querySelectorAll('.genre-btn'),
    librosContainer: document.getElementById('librosContainer')
};

// Verificar todos los elementos
if (!verifyElements()) {
    console.error('Error: Algunos elementos no se encontraron en la página');
}

// Estado del carrusel
let carruselState = {
    currentIndex: 0,
    interval: null,
    autoRotateDelay: 5000,
    isAutoRotating: false
};

// Función auxiliar para calcular el nuevo índice
function calculateNewIndex(direction, currentIndex, totalItems) {
    if (direction === 'next') {
        return currentIndex < totalItems - 1 ? currentIndex + 1 : 0;
    }
    return currentIndex > 0 ? currentIndex - 1 : totalItems - 1;
}

// Funciones del carrusel
function toggleCarrusel() {
    debug('Botón toggleCarrusel clickeado');
    const isHidden = elements.carruselContainer.style.display === 'none';
    elements.carruselContainer.style.display = isHidden ? 'block' : 'none';
    elements.toggleButton.textContent = isHidden ? 'Ocultar Carrusel' : 'Mostrar Carrusel';
    
    if (isHidden) {
        updateCarrusel();
        startAutoRotation();
    } else {
        stopAutoRotation();
    }
}

function navigateCarrusel(direction) {
    debug(`Navegación del carrusel: ${direction}`);
    const { children } = elements.carrusel;
    carruselState.currentIndex = calculateNewIndex(
        direction,
        carruselState.currentIndex,
        children.length
    );
    
    updateCarrusel();
    resetAutoRotation();
}

function updateCarrusel() {
    elements.carrusel.style.transform = `translateX(${-carruselState.currentIndex * 100}%)`;
}

// Auto-rotación
function startAutoRotation() {
    debug('Iniciando auto-rotación');
    if (!carruselState.interval && elements.carruselContainer.style.display !== 'none') {
        carruselState.interval = setInterval(() => navigateCarrusel('next'), carruselState.autoRotateDelay);
        carruselState.isAutoRotating = true;
    }
}

function stopAutoRotation() {
    debug('Deteniendo auto-rotación');
    if (carruselState.interval) {
        clearInterval(carruselState.interval);
        carruselState.interval = null;
        carruselState.isAutoRotating = false;
    }
}

function resetAutoRotation() {
    stopAutoRotation();
    startAutoRotation();
}

// Efecto de scroll
function handleScroll() {
    const scrollY = window.scrollY;
    if (elements.scrollSection) {
        elements.scrollSection.style.backgroundColor = scrollY > 100 ? '#6b5a46' : '#8b7355';
    }
}

// Redirecciones
function redirectTo(page) {
    debug(`Redirigiendo a: ${page}`);
    window.location.href = page;
}

// Verificación de permisos
async function checkAdminPermissions() {
    try {
        debug('Verificando permisos de admin');
        const userId = localStorage.getItem('userId');
        const authToken = localStorage.getItem('authToken');
        
        if (!userId) {
            debug('No hay userId en localStorage');
            elements.registerBookButton?.classList.add('hidden-button');
            return;
        }

        const response = await fetch(`/verificarAdmin/${userId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        debug(`Resultado de verificación: ${JSON.stringify(result)}`);

        if (result.esAdmin) {
            elements.registerBookButton?.classList.remove('hidden-button');
        } else {
            elements.registerBookButton?.classList.add('hidden-button');
        }
    } catch (error) {
        console.error('Error al verificar permisos:', error);
        elements.registerBookButton?.classList.add('hidden-button');
    }
}

// Función para cargar libros por género
async function cargarLibrosPorGenero(genero) {
    try {
        const url = genero === 'Todos' ? '/obtenerLibros' : `/obtenerLibrosPorGenero?genero=${encodeURIComponent(genero)}`;
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error('Error al cargar libros');
        }
        
        const libros = await response.json();
        mostrarLibros(libros);
    } catch (error) {
        console.error('Error:', error);
        elements.librosContainer.innerHTML = `<p class="error-message">Error al cargar los libros: ${error.message}</p>`;
    }
}

// Función para mostrar los libros en el contenedor
function mostrarLibros(libros) {
    if (libros.length === 0) {
        elements.librosContainer.innerHTML = '<p class="no-books">No se encontraron libros en este género.</p>';
        return;
    }

    elements.librosContainer.innerHTML = libros.map((libro, index) => `
        <div class="libro-card" style="--order: ${index}">
            <img src="${libro.imagen}" alt="${libro.nombre}" class="libro-imagen">
            <div class="libro-info">
                <h3 class="libro-titulo">${libro.nombre}</h3>
                <p class="libro-autor">${libro.autor}</p>
                <span class="libro-genero">${libro.genero}</span>
                <p class="libro-descripcion">${libro.descripcion}</p>
                <p class="libro-estado ${libro.estado === 'No_Disponible' ? 'no-disponible' : ''}">
                    ${libro.estado === 'Disponible' ? 'Disponible' : 'No Disponible'}
                </p>
            </div>
        </div>
    `).join('');
}

// Configurar event listeners
function setupEventListeners() {
    debug('Configurando event listeners');
    
    elements.toggleButton?.addEventListener('click', toggleCarrusel);
    elements.prevBtn?.addEventListener('click', () => navigateCarrusel('prev'));
    elements.nextBtn?.addEventListener('click', () => navigateCarrusel('next'));
    elements.settingsButton?.addEventListener('click', () => redirectTo('settings.html'));
    elements.registerBookButton?.addEventListener('click', () => redirectTo('reglibro.html'));
    
    // Event listeners para botones de género
    elements.genreButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remover clase active de todos los botones
            elements.genreButtons.forEach(b => b.classList.remove('active'));
            // Añadir clase active al botón clickeado
            btn.classList.add('active');
            // Cargar libros del género seleccionado
            cargarLibrosPorGenero(btn.dataset.genero);
        });
    });
    
    window.addEventListener('scroll', handleScroll);
    window.addEventListener('resize', updateCarrusel);
}

// Inicialización
function init() {
    debug('Inicializando aplicación');
    setupEventListeners();
    checkAdminPermissions();
    
    // Iniciar rotación solo si el carrusel está visible
    if (elements.carruselContainer && elements.carruselContainer.style.display !== 'none') {
        startAutoRotation();
    }
    
    // Cargar todos los libros al inicio
    cargarLibrosPorGenero('Todos');
    // Marcar el botón "Todos" como activo
    document.querySelector('.genre-btn[data-genero="Todos"]')?.classList.add('active');
    
    // Verificar permisos periódicamente
    setInterval(checkAdminPermissions, 300000);
}

// Esperar a que el DOM esté completamente cargado
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    setTimeout(init, 0);
}