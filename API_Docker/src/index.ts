const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const MONGO_URI = 'mongodb://localhost:27017/crud_example';

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Conectado a MongoDB'))
  .catch((error) => console.error('Error de conexion con MongoDB:', error));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Ruta de registro de usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Verificar si el usuario ya existe
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: 'Ya existe este usuario' });
  }

  // Hash de la contraseña
  const hashedPassword = await bcrypt.hash(password, 10);

  // Crear el nuevo usuario
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  res.status(201).json({ message: 'Usuario creado exitosamente' });
});

// Ruta de autenticación de usuario
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Buscar el usuario en la base de datos
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ message: 'Usuario o contraseña invalida' });
  }

  // Verificar la contraseña
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Usuario o contraseña invalida' });
  }

  // Generar el token de autenticación
  const token = jwt.sign({ userId: user._id }, 'secret-key');
  res.json({ token });
});

// Middleware de autenticación
const authenticate = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, 'secret-key');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Ruta protegida
app.get('/protected', authenticate, (req, res) => {
  res.json({ message: 'Ruta protegida' });
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});
