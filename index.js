const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const https = require('https');
const fs = require('fs');
const CryptoJS = require('crypto-js');

const app = express();

// ======================
// Configuración Constante
// ======================
const ENCRYPTION_KEY = "default-secret-key-32-bytes-1234567890";
const JWT_SECRET = "06177160876567451054943720268410";
const SESSION_SECRET = "secreto-de-sesion-32-caracteres-seguro";
const DB_CONFIG = {
  host: "shinkansen.proxy.rlwy.net:",
  user: "root",
  password: "TYVizHPaZxJPbQPVtjdGKZPtRzLuxAOV",
  database: "pr_dsr",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};
const EMAIL_CONFIG = {
  service: "gmail",
  auth: {
    user: "dinocraft617@gmail.com",
    pass: "avvd ghwt qucl rpfz"
  }
};

// Funciones 
const encryptData = (data) => {
  if (!data) return null;
  try {
    const normalized = data.toString().toLowerCase().trim();
    return CryptoJS.AES.encrypt(
      normalized,
      CryptoJS.enc.Utf8.parse(ENCRYPTION_KEY),
      {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
      }
    ).toString();
  } catch (error) {
    console.error('Error al encriptar:', error);
    throw new Error('Error en el proceso de encriptación');
  }
};

const decryptData = (ciphertext) => {
  if (!ciphertext) return null;
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    if (!decrypted) throw new Error('Resultado de desencriptación vacío');
    return decrypted;
  } catch (error) {
    console.error('Error al desencriptar:', error);
    throw new Error('Error en el proceso de desencriptación');
  }
};

const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();


// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware de autenticación JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Configuración CORS para HTTPS
app.use(cors({
  origin: "https://localhost",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept", "X-Requested-With", "Cookie", "Set-Cookie"]
}));
app.options('*', cors());

// Seguridad con Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "img-src": [
        "'self'", 
        "data:", 
        "https://images.unsplash.com",
        "https://www.libreralia.com",
        "https://www.rae.es",
        "https://latam.casadellibro.com",
        "https://intothebooksheart.com",
        "https://524499105000-my.sharepoint.com"
      ],
      "script-src": ["'self'"],
      "script-src-attr": ["'none'"],
    },
  },
}));

// Configuración de Base de Datos
const pool = mysql.createPool(DB_CONFIG);

// Configuración de Email
const transporter = nodemailer.createTransport(EMAIL_CONFIG);

const sendVerificationCode = async (email, code) => {
  const mailOptions = {
    from: `"Sistema de Verificación" <${EMAIL_CONFIG.auth.user}>`,
    to: email,
    subject: "Tu Código de Verificación",
    text: `Tu código de verificación es: ${code}`,
    html: `<p>Tu código de verificación es: <strong>${code}</strong></p>`
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Correo enviado:', info.messageId);
    return true;
  } catch (error) {
    console.error('Error al enviar correo:', error);
    throw error;
  }
};

// Rutas Estáticas
app.use(express.static(path.join(__dirname, 'public')));
app.use('/CSS', express.static(path.join(__dirname, 'CSS')));
app.use('/JS', express.static(path.join(__dirname, 'JS')));
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use('/HTML', express.static(path.join(__dirname, 'HTML')));

// Rutas de Vistas
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'HTML', 'index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'HTML', 'login.html'));
});

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'HTML', 'register.html'));
});

app.get('/verify.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'HTML', 'verify.html'));
});

app.get('/settings.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'HTML', 'settings.html'));
});

app.get('/reglibro.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'HTML', 'reglibro.html'));
});

app.get('/catalogo.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'HTML', 'catalogo.html'));
});

// Registro de Usuario
app.post('/registerUser', [
  body('username').trim().notEmpty().withMessage('Nombre de usuario requerido'),
  body('email').isEmail().normalizeEmail().withMessage('Email inválido'),
  body('password').isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Las contraseñas no coinciden');
    }
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }

  const { username, email, password } = req.body;

  try {
    // Verificar nombre de usuario primero
    const [userExists] = await pool.query(
      'SELECT id_user FROM usuarios WHERE nombre = ?', 
      [username]
    );

    if (userExists.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'El nombre de usuario ya existe'
      });
    }

    // Verificar email después
    const encryptedEmail = encryptData(email);
    const [emailExists] = await pool.query(
      'SELECT id_user FROM usuarios WHERE correo = ?',
      [encryptedEmail]
    );

    if (emailExists.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'El correo electrónico ya está registrado'
      });
    }

    // Crear usuario
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO usuarios (nombre, correo, contraseña, rol) VALUES (?, ?, ?, ?)',
      [username, encryptedEmail, hashedPassword, 'user']
    );

    res.json({
      success: true,
      message: 'Usuario registrado exitosamente'
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor',
      details: error.message
    });
  }
});

// Inicio de Sesión
app.post('/loginUser', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
      const encryptedEmail = encryptData(email.toLowerCase().trim());
      const [users] = await pool.query(
          'SELECT id_user, nombre, correo, contraseña, rol FROM usuarios WHERE correo = ?', 
          [encryptedEmail]
      );

      if (users.length === 0) {
          return res.status(401).json({
              success: false,
              error: 'Credenciales inválidas'
          });
      }

      const user = users[0];
      const validPassword = await bcrypt.compare(password, user.contraseña);
      if (!validPassword) {
          return res.status(401).json({
              success: false,
              error: 'Credenciales inválidas'
          });
      }

      // Generar código y enviar correo
      const verificationCode = generateVerificationCode();
      
      try {
          await transporter.sendMail({
              from: `"Sistema de Verificación" <${EMAIL_CONFIG.auth.user}>`,
              to: email,
              subject: "Tu Código de Verificación",
              html: `<p>Tu código es: <strong>${verificationCode}</strong></p>`
          });
      } catch (emailError) {
          console.error('Error al enviar correo:', emailError);
          return res.status(500).json({
              success: false,
              error: 'Error al enviar el código'
          });
      }

      // Crear token con código
      const token = jwt.sign(
          {
              userId: user.id_user,
              email: email,
              role: user.rol,
              verificationCode: verificationCode
          },
          JWT_SECRET,
          { expiresIn: '15m' }
      );

      res.json({
          success: true,
          message: 'Código enviado',
          token: token
      });

  } catch (error) {
      console.error('Error en login:', error);
      res.status(500).json({
          success: false,
          error: 'Error interno del servidor'
      });
  }
});


// Verificación de Código
app.post('/verifyCode', [
  body('code').notEmpty().isLength({ min: 6, max: 6 }).isNumeric()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
  }

  const { code } = req.body;
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(401).json({ error: 'Token no proporcionado' });
  }

  try {
      const decoded = jwt.verify(token, JWT_SECRET);
      
      // Verificar que el código coincida
      if (code !== decoded.verificationCode) {
          return res.status(401).json({ 
              success: false,
              error: 'Código de verificación incorrecto' 
          });
      }

      // Crear nuevo token sin el código de verificación
      const accessToken = jwt.sign(
          {
              userId: decoded.userId,
              email: decoded.email,
              role: decoded.role
          },
          JWT_SECRET,
          { expiresIn: '24h' }
      );

      // Obtener datos completos del usuario
      const [user] = await pool.query(
          'SELECT id_user, nombre, rol FROM usuarios WHERE id_user = ?',
          [decoded.userId]
      );

      if (!user.length) {
          return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      // Respuesta exitosa
      res.json({
          success: true,
          message: 'Verificación exitosa',
          token: accessToken,
          user: {
              id: user[0].id_user,
              name: user[0].nombre,
              email: decoded.email,
              role: user[0].rol
          }
      });

  } catch (error) {
      if (error.name === 'JsonWebTokenError') {
          return res.status(401).json({ 
              success: false,
              error: 'Token inválido o expirado' 
          });
      }
      console.error('Error en verifyCode:', error);
      res.status(500).json({ 
          success: false,
          error: 'Error interno del servidor' 
      });
  }
});

// ======================
// Rutas de Administrador
// ======================
app.get('/checkAdminSession', authenticateJWT, (req, res) => {
  res.json({
    isAdmin: req.user.role === 'Adm',
    message: req.user.role === 'Adm' ? 'Usuario es administrador' : 'Usuario no es administrador'
  });
});

// Obtener configuración del usuario
app.get('/getUserSettings', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        success: false,
        error: 'No autorizado. Por favor inicie sesión.'
      });
    }
    const [rows] = await pool.query(
      'SELECT id_user, nombre, correo, rol, mfa_enabled as mfaEnabled FROM usuarios WHERE id_user = ?',
      [req.session.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Usuario no encontrado'
      });
    }

    const user = rows[0];
    const decryptedEmail = decryptData(user.correo);
    
    res.json({
      success: true,
      user: {
        id: user.id_user,
        name: user.nombre,
        email: decryptedEmail,
        role: user.rol,
        mfaEnabled: Boolean(user.mfaEnabled)
      }
    });

  } catch (error) {
    console.error('Error al obtener configuración:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

// Generar código de verificación para cambios
app.post('/generateVerificationCode', async (req, res) => {
  try {
    if (!req.session.userId || !req.session.email) {
      return res.status(401).json({
        success: false,
        error: 'Sesión no válida'
      });
    }

    const verificationCode = generateVerificationCode();
    await sendVerificationCode(req.session.email, verificationCode);
    
    req.session.verificationCode = verificationCode;

    res.json({
      success: true,
      message: 'Código de verificación enviado'
    });

  } catch (error) {
    console.error('Error al generar código:', error);
    res.status(500).json({
      success: false,
      error: 'Error al enviar código de verificación'
    });
  }
});

// Guardar configuración del usuario
app.post('/saveSettings', [
  body('oldPassword').optional(),
  body('newPassword').optional().isLength({ min: 8 }),
  body('mfaEnabled').optional().isBoolean(),
  body('nombre').optional().trim().isLength({ min: 2 }),
  body('code').optional().isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      error: 'Validación fallida',
      details: errors.array() 
    });
  }

  try {
    if (!req.session.userId) {
      return res.status(401).json({
        success: false,
        error: 'No autorizado - ID de usuario no encontrado'
      });
    }

    const { nombre, oldPassword, newPassword, mfaEnabled, code } = req.body;
    const updates = {};
    const necesitaVerificacion = oldPassword || newPassword || mfaEnabled;

    if (necesitaVerificacion) {
      if (!code || code !== req.session.verificationCode) {
        return res.status(401).json({
          success: false,
          error: 'Código de verificación inválido'
        });
      }
    }

    if (newPassword) {
      const [user] = await pool.query(
        'SELECT contraseña FROM usuarios WHERE id_user = ?',
        [req.session.userId]
      );
      
      if (!user.length) {
        return res.status(404).json({
          success: false,
          error: 'Usuario no encontrado'
        });
      }

      const contraseñaValida = await bcrypt.compare(oldPassword, user[0].contraseña);
      if (!contraseñaValida) {
        return res.status(401).json({
          success: false,
          error: 'La contraseña actual es incorrecta'
        });
      }

      updates.contraseña = await bcrypt.hash(newPassword, 10);
    }

    if (nombre) updates.nombre = nombre;
    if (typeof mfaEnabled !== 'undefined') updates.mfa_enabled = mfaEnabled;

    if (Object.keys(updates).length > 0) {
      await pool.query(
        'UPDATE usuarios SET ? WHERE id_user = ?',
        [updates, req.session.userId]
      );
    }

    if (necesitaVerificacion) {
      req.session.verificationCode = null;
    }

    res.json({
      success: true,
      message: 'Configuración actualizada correctamente'
    });

  } catch (error) {
    console.error('Error en saveSettings:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor',
      message: error.message
    });
  }
});

// Obtener información de un usuario específico
app.get('/user/:id', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id_user, nombre, correo, rol FROM usuarios WHERE id_user = ?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Usuario no encontrado'
      });
    }

    const user = {
      ...rows[0],
      correo: decryptData(rows[0].correo)
    };

    res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Error al obtener usuario:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

// Actualizar perfil básico (nombre o email)
app.put('/user/:id', [
  body('nombre').optional().trim(),
  body('email').optional().isEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { nombre, email } = req.body;
  const updates = {};
  if (nombre) updates.nombre = nombre;
  if (email) updates.correo = encryptData(email);

  try {
    if (Object.keys(updates).length > 0) {
      await pool.query(
        'UPDATE usuarios SET ? WHERE id_user = ?',
        [updates, req.params.id]
      );
    }

    res.json({
      success: true,
      message: 'Perfil actualizado exitosamente'
    });
  } catch (error) {
    console.error('Error al actualizar perfil:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

// ======================
// Rutas de API - Autenticación 2FA
// ======================

// Generar secreto 2FA y QR
app.get('/2fa/generate', (req, res) => {
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `Aplicación (${req.query.email || 'usuario'})`
  });

  qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: 'Error al generar QR'
      });
    }

    res.json({
      success: true,
      secret: secret.base32,
      qrCode: data_url
    });
  });
});

// Verificar código 2FA
app.post('/2fa/verify', (req, res) => {
  const { secret, token } = req.body;

  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (verified) {
    res.json({
      success: true,
      message: 'Autenticación exitosa'
    });
  } else {
    res.status(401).json({
      success: false,
      error: 'Código inválido'
    });
  }
});

// Ruta para registrar un nuevo libro (solo admin)
app.post('/registrarLibro', authenticateJWT, [
  body('nombre').trim().notEmpty(),
  body('autor').trim().notEmpty(),
  body('genero').trim().notEmpty(),
  body('descripcion').trim().notEmpty(),
  body('estado').isIn(['Disponible', 'No_Disponible']),
  body('imagen').isURL()
], async (req, res) => {
  if (req.user.role !== 'Adm') {
    return res.status(403).json({
      success: false,
      error: 'Se requieren permisos de administrador'
    });
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { nombre, autor, genero, descripcion, estado, imagen } = req.body;
  
  try {
    const [result] = await pool.query(
      'INSERT INTO libro (nombre, autor, genero, descripcion, estado, imagen) VALUES (?, ?, ?, ?, ?, ?)',
      [nombre, autor, genero, descripcion, estado, imagen]
    );

    res.json({ 
      success: true,
      message: 'Libro registrado exitosamente',
      libroId: result.insertId
    });
  } catch (error) {
    console.error('Error al registrar libro:', error);
    res.status(500).json({
      success: false,
      error: 'Error al registrar el libro'
    });
  }
});

// Middleware para verificar sesión
const verificarSesion = async (req, res, next) => {
  const userId = req.headers['user-id'] || req.params.userId;
  
  if (!userId) {
      return res.status(401).json({ error: 'No autorizado' });
  }

  try {
      const [rows] = await pool.query(
          'SELECT id_user FROM usuarios WHERE id_user = ?',
          [userId]
      );

      if (rows.length === 0) {
          return res.status(401).json({ error: 'Usuario no válido' });
      }

      next();
  } catch (error) {
      console.error('Error al verificar sesión:', error);
      res.status(500).json({ error: 'Error al verificar sesión' });
  }
};

// Ruta para verificar si un usuario es administrador
app.get('/verificarAdmin/:userId', async (req, res) => {
  try {
      const userId = req.params.userId;
      
      // Consulta a la base de datos
      const [rows] = await pool.query(
          'SELECT rol FROM usuarios WHERE id_user = ?',
          [userId]
      );

      if (rows.length === 0) {
          return res.status(404).json({
              esAdmin: false,
              mensaje: 'Usuario no encontrado'
          });
      }

      const esAdmin = rows[0].rol === 'adm';
      
      res.json({
          esAdmin,
          mensaje: esAdmin ? 'Usuario es administrador' : 'Usuario no es administrador'
      });

  } catch (error) {
      console.error('Error al verificar admin:', error);
      res.status(500).json({
          esAdmin: false,
          mensaje: 'Error al verificar permisos'
      });
  }
});

// Ruta para verificar sesión de admin
app.get('/checkAdminSession', async (req, res) => {
  try {
      if (!req.session.userId || !req.session.role) {
          return res.status(401).json({
              isAdmin: false,
              message: 'No hay sesión activa'
          });
      }

      res.json({
          isAdmin: req.session.role === 'adm',
          message: req.session.role === 'adm' ? 'Usuario es administrador' : 'Usuario no es administrador'
      });
  } catch (error) {
      console.error('Error al verificar sesión:', error);
      res.status(500).json({
          isAdmin: false,
          message: 'Error al verificar sesión'
      });
  }
});

// Ruta para obtener todos los libros
app.get('/obtenerLibros', async (req, res) => {
  try {
      const [libros] = await pool.query('SELECT * FROM libro');
      res.json(libros);
  } catch (error) {
      console.error('Error al obtener libros:', error);
      res.status(500).json({ error: 'Error al obtener libros' });
  }
});

// Ruta para obtener libros por género
app.get('/obtenerLibrosPorGenero', async (req, res) => {
  try {
      const genero = req.query.genero;
      const [libros] = await pool.query('SELECT * FROM libro WHERE genero = ?', [genero]);
      res.json(libros);
  } catch (error) {
      console.error('Error al obtener libros por género:', error);
      res.status(500).json({ error: 'Error al obtener libros por género' });
  }
});

app.use((err, req, res, next) => {
  console.error('Error no manejado:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor',
    details: err.message
  });
});

// ======================
// Iniciar Servidor HTTPS
// ======================
const sslOptions = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
  minVersion: 'TLSv1.2'
};

https.createServer(sslOptions, app).listen(443, () => {
  console.log('🚀 Servidor HTTPS corriendo en https://localhost');
  
  pool.getConnection()
    .then(conn => {
      console.log('✅ Conexión a BD establecida');
      conn.release();
    })
    .catch(err => {
      console.error('❌ Error al conectar con la BD:', err.message);
    });
});
