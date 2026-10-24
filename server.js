// server.js - AYITI FORM BACKEND
// Déployer sur Render.com

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg'); // PostgreSQL client
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// --- CONFIGURATION BASE DE DONNÉES (RENDER) ---
// Sur Render, tu crées une "PostgreSQL Database". 
// Copie sa "Internal Database URL" et colle-la dans les variables d'environnement de Render sous le nom DATABASE_URL.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// --- MIDDLEWARES ---
app.use(cors()); // Autorise tous les domaines (pour simplifier le début)
app.use(express.json());

// --- INITIALISATION DB (Auto-Création des tables si elles n'existent pas) ---
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        whatsapp_number VARCHAR(20),
        full_name VARCHAR(100),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS forms (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        form_title VARCHAR(100) NOT NULL,
        form_fields JSONB NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS submissions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        form_id UUID REFERENCES forms(id) ON DELETE CASCADE,
        data JSONB NOT NULL,
        ip_address INET,
        submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(20) DEFAULT 'NEW'
      );
    `);
    console.log("✅ Base de données initialisée avec succès.");
  } catch (err) {
    console.error("❌ Erreur init DB:", err);
  }
}
initDB();

// --- HELPERS ---
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET || 'secret_temporaire_changer_plus_tard', { expiresIn: '7d' });
};

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(403).json({ error: 'Accès refusé.' });
  
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_temporaire_changer_plus_tard');
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Session expirée.' });
  }
};

// --- ROUTES AUTHENTIFICATION ---

// 1. Inscription Commerçant
app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName, whatsappNumber } = req.body;
  
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis.' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, full_name, whatsapp_number) VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, whatsapp_number',
      [email, hashedPassword, fullName, whatsappNumber]
    );
    
    const token = generateToken(result.rows[0].id);
    res.status(201).json({ user: result.rows[0], token });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Cet email est déjà inscrit.' });
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// 2. Connexion
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Identifiants invalides.' });
    
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: 'Identifiants invalides.' });

    const token = generateToken(user.id);
    delete user.password_hash; 
    
    res.json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// --- ROUTES FORMULAIRES (PROTEGÉES PAR LOGIN) ---

// 3. Créer un formulaire
app.post('/api/forms', verifyToken, async (req, res) => {
  const { title, fields } = req.body; 
  
  try {
    const result = await pool.query(
      'INSERT INTO forms (user_id, form_title, form_fields) VALUES ($1, $2, $3) RETURNING *',
      [req.userId, title, JSON.stringify(fields)]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur création formulaire.' });
  }
});

// 4. Lister mes formulaires
app.get('/api/forms/my', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM forms WHERE user_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur récupération.' });
  }
});

// --- ROUTES PUBLIQUES (POUR LES CLIENTS FINAUX) ---

// 5. Récupérer un formulaire public (sans login)
app.get('/api/forms/public/:formId', async (req, res) => {
  const { formId } = req.params;
  try {
    const result = await pool.query('SELECT form_title, form_fields FROM forms WHERE id = $1 AND is_active = true', [formId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Formulaire introuvable.' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// 6. Recevoir une soumission (Le cœur du business)
app.post('/api/submissions', async (req, res) => {
  const { formId, data } = req.body;
  
  if (!formId || !data) return res.status(400).json({ error: 'Données manquantes.' });

  try {
    // A. Sauvegarder en BDD
    await pool.query(
      'INSERT INTO submissions (form_id, data, ip_address) VALUES ($1, $2, $3)',
      [formId, JSON.stringify(data), req.ip]
    );

    // B. Trouver le propriétaire pour l'alerter
    const ownerInfo = await pool.query(`
      SELECT u.whatsapp_number, f.form_title 
      FROM forms f 
      JOIN users u ON f.user_id = u.id 
      WHERE f.id = $1
    `, [formId]);

    let whatsappLink = null;

    if (ownerInfo.rows.length > 0) {
      const owner = ownerInfo.rows[0];
      
      // Formatage du message WhatsApp
      // On transforme les clés techniques en labels lisibles si possible, sinon on affiche le JSON brut proprement
      let messageBody = `🔔 NOUVELLE DEMANDE: ${owner.form_title}\n\n`;
      for (const [key, value] of Object.entries(data)) {
         messageBody += `- ${key}: ${value}\n`;
      }
      messageBody += `\n⏰ Reçu le: ${new Date().toLocaleString('fr-FR')}`;
      
      // Création du lien wa.me encodé
      const encodedMsg = encodeURIComponent(messageBody);
      // Nettoyage du numéro (enlève +, espaces) pour wa.me
      const cleanPhone = owner.whatsapp_number ? owner.whatsapp_number.replace(/[^0-9]/g, '') : '';
      
      if(cleanPhone) {
        whatsappLink = `https://wa.me/${cleanPhone}?text=${encodedMsg}`;
      }
    }

    res.status(201).json({ 
      success: true, 
      message: "Demande envoyée avec succès.",
      alertReady: !!whatsappLink,
      previewLink: whatsappLink // Pour tester manuellement au début
    });

  } catch (err) {
    console.error("Erreur submission:", err);
    res.status(500).json({ error: 'Échec de l\'enregistrement.' });
  }
});

// 7. Dashboard Admin : Voir les soumissions d'un formulaire
app.get('/api/submissions/form/:formId', verifyToken, async (req, res) => {
  const { formId } = req.params;
  
  try {
    // Vérif propriété
    const check = await pool.query('SELECT user_id FROM forms WHERE id = $1', [formId]);
    if (check.rows[0]?.user_id !== req.userId) {
      return res.status(403).json({ error: 'Non autorisé.' });
    }

    const result = await pool.query(
      'SELECT * FROM submissions WHERE form_id = $1 ORDER BY submitted_at DESC LIMIT 50',
      [formId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur récupération données.' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Ayiti Form Backend démarré sur http://localhost:${PORT}`);
});
