// Variables para almacenar cambios pendientes
let cambiosPendientes = {};

// Cargar configuración inicial
async function cargarConfiguracion() {
  try {
    const response = await fetch("https://localhost/getUserSettings", {
      method: "GET",
      credentials: "include",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      }
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Error HTTP! estado: ${response.status}`);
    }

    const resultado = await response.json();
    console.log('Respuesta de configuración:', resultado);

    if (resultado.success) {
      document.getElementById("mfaEnabled").checked = resultado.user.mfaEnabled;
      document.getElementById("nombre").value = resultado.user.name;
      return true;
    } else {
      throw new Error(resultado.error || "Error al cargar configuración");
    }
  } catch (error) {
    console.error("Error al cargar configuración:", error);
    alert("Error al cargar configuración: " + error.message);
    return false;
  }
}

// Mostrar modal de verificación
function mostrarModalVerificacion() {
  document.getElementById("verificationModal").style.display = "block";
}

// Ocultar modal de verificación
function ocultarModalVerificacion() {
  document.getElementById("verificationModal").style.display = "none";
  document.getElementById("verificationCode").value = "";
}

// Cerrar modal al hacer clic en la X
document.querySelector(".close").addEventListener("click", ocultarModalVerificacion);

// Manejar el envío del formulario
document.getElementById("saveSettingsButton").addEventListener("click", async () => {
  // Recoger los cambios
  cambiosPendientes = {
    oldPassword: document.getElementById("oldPassword").value,
    newPassword: document.getElementById("newPassword").value,
    mfaEnabled: document.getElementById("mfaEnabled").checked,
    nombre: document.getElementById("nombre").value
  };

  // Verificar si hay cambios que requieran verificación
  if (cambiosPendientes.oldPassword || cambiosPendientes.newPassword || cambiosPendientes.mfaEnabled) {
    try {
      // Solicitar código de verificación
      const response = await fetch("https://localhost/generateVerificationCode", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        }
      });

      const resultado = await response.json();

      if (resultado.success) {
        mostrarModalVerificacion();
      } else {
        alert("Error al solicitar código de verificación: " + (resultado.error || "Error desconocido"));
      }
    } catch (error) {
      console.error("Error al solicitar verificación:", error);
      alert("Error al solicitar código de verificación");
    }
  } else {
    // Guardar cambios que no requieren verificación
    guardarCambios({});
  }
});

// Manejar la verificación del código
document.getElementById("submitVerificationCode").addEventListener("click", async () => {
  const codigo = document.getElementById("verificationCode").value.trim();
  
  if (!codigo) {
    alert("Por favor ingrese el código de verificación");
    return;
  }

  try {
    // Incluir el código en los cambios pendientes
    await guardarCambios({ ...cambiosPendientes, code: codigo });
  } catch (error) {
    console.error("Error al verificar código:", error);
    alert("Error al verificar código: " + error.message);
  }
});

// Función para guardar cambios
async function guardarCambios(cambios) {
  try {
    const response = await fetch("https://localhost/saveSettings", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(cambios)
    });

    const resultado = await response.json();

    if (!response.ok) {
      throw new Error(resultado.error || "Error al guardar cambios");
    }

    if (resultado.success) {
      alert("Cambios guardados exitosamente");
      ocultarModalVerificacion();
      // Limpiar campos de contraseña
      document.getElementById("oldPassword").value = "";
      document.getElementById("newPassword").value = "";
    } else {
      throw new Error(resultado.error || "Error al guardar cambios");
    }
  } catch (error) {
    console.error("Error al guardar cambios:", error);
    alert(error.message || "Error al guardar cambios");
    throw error;
  }
}

// Cargar configuración cuando la página se carga
window.addEventListener("load", async () => {
  await cargarConfiguracion();
});