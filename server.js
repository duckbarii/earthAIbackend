const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const Groq = require('groq-sdk');
const simpleGit = require('simple-git');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const textToSpeech = require('@google-cloud/text-to-speech'); // For TTS

const app = express();
const PORT = process.env.PORT || 1100;

// Configuration
const CONFIG = {
    GROQ_API_KEY: process.env.GROQ_API_KEY || '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',
    SUDOAPP_API_KEY: process.env.SUDOAPP_API_KEY || '3fd5e44f6859749864550d7da6697cf1a392b83fb712e734e49d9eba118bb669',
    JWT_SECRET: process.env.JWT_SECRET || '32b635cb52cb2551b7e4019f92a09da8',
    SUDOAPP_API_URL: 'https://sudoapp.dev/api/v1/chat/completions',
    SEAART_API_URL: 'https://seaart-ai.apis-bj-devs.workers.dev',
    // Pre-defined admin credentials
    ADMIN_EMAIL: process.env.ADMIN_EMAIL || 'admin@aifromearth.com',
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin123456',
    ADMIN_USERNAME: process.env.ADMIN_USERNAME || 'neuroadmin'
};

// Initialize Groq client
let groq;
let groqAvailable = false;

try {
    if (CONFIG.GROQ_API_KEY && CONFIG.GROQ_API_KEY.length > 50) {
        groq = new Groq({ apiKey: CONFIG.GROQ_API_KEY });
        groqAvailable = true;
        console.log('✅ Groq client initialized successfully');
    } else {
        console.log('❌ Groq API key is invalid or missing');
    }
} catch (error) {
    console.error('❌ Failed to initialize Groq client:', error.message);
}

// Enhanced CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'https://dnnetwork.rf.gd',
            'http://localhost:3000',
            'http://127.0.0.1:3000',
            'http://localhost:5500',
            'http://127.0.0.1:5500'
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('localhost') || origin.includes('127.0.0.1')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Security headers
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// Database initialization
const db = new sqlite3.Database('./aifromearth.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('✅ Connected to SQLite database.');
        initializeDatabase();
    }
});

async function initializeDatabase() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Enhanced users table with preferences
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                banned BOOLEAN DEFAULT FALSE,
                ban_reason TEXT,
                banned_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME DEFAULT CURRENT_TIMESTAMP,
                tts_voice TEXT DEFAULT 'Arista-PlayAI',
                theme TEXT DEFAULT 'dark',
                language TEXT DEFAULT 'en'
            )`, async (err) => {
                if (err) console.error('❌ Error creating users table:', err);
                else {
                    console.log('✅ Users table ready');
                    // Create default admin user
                    await createAdminUser();
                }
            });

            // Conversations table for chat sessions
            db.run(`CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )`, (err) => {
                if (err) console.error('❌ Error creating conversations table:', err);
                else console.log('✅ Conversations table ready');
            });

            // Messages table for individual messages in conversations
            db.run(`CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                model_used TEXT,
                system_prompt_used TEXT,
                prompt_category TEXT,
                tokens_used INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id)
            )`, (err) => {
                if (err) console.error('❌ Error creating messages table:', err);
                else console.log('✅ Messages table ready');
            });

            // User system prompts table
            db.run(`CREATE TABLE IF NOT EXISTS user_system_prompts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                is_public BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )`, (err) => {
                if (err) console.error('❌ Error creating user_system_prompts table:', err);
                else console.log('✅ User system prompts table ready');
            });

            // Ban history table
            db.run(`CREATE TABLE IF NOT EXISTS ban_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                admin_id INTEGER,
                action TEXT NOT NULL,
                reason TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(admin_id) REFERENCES users(id)
            )`, (err) => {
                if (err) console.error('❌ Error creating ban_history table:', err);
                else console.log('✅ Ban history table ready');
            });

            // User activity logs for security
            db.run(`CREATE TABLE IF NOT EXISTS user_activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )`, (err) => {
                if (err) console.error('❌ Error creating user_activity_logs table:', err);
                else console.log('✅ User activity logs table ready');
                resolve();
            });
        });
    });
}

async function createAdminUser() {
    try {
        const adminExists = await dbGet(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [CONFIG.ADMIN_USERNAME, CONFIG.ADMIN_EMAIL]
        );

        if (!adminExists) {
            const passwordHash = await bcrypt.hash(CONFIG.ADMIN_PASSWORD, 12);
            await dbRun(
                'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [CONFIG.ADMIN_USERNAME, CONFIG.ADMIN_EMAIL, passwordHash, 'admin']
            );
            console.log('✅ Default admin user created');
        } else {
            console.log('✅ Admin user already exists');
        }
    } catch (error) {
        console.error('❌ Error creating admin user:', error);
    }
}

// System Prompts Management
const SYSTEM_PROMPTS_DIR = './system-prompts';
let systemPrompts = {};
let promptCategories = {};

async function initializeSystemPrompts() {
    try {
        if (!fs.existsSync(SYSTEM_PROMPTS_DIR)) {
            console.log('📥 Cloning system prompts repository...');
            await simpleGit().clone(
                'https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools',
                SYSTEM_PROMPTS_DIR,
                ['--depth', '1']
            );
            console.log('✅ System prompts repository cloned successfully.');
        } else {
            console.log('✅ System prompts directory already exists');
            // Update existing repository
            try {
                await simpleGit(SYSTEM_PROMPTS_DIR).pull();
                console.log('✅ System prompts repository updated');
            } catch (pullError) {
                console.log('⚠️ Could not update system prompts repository:', pullError.message);
            }
        }
        loadAllPrompts();
    } catch (error) {
        console.error('❌ Error initializing system prompts:', error.message);
        // Create default prompts if repository fails
        createDefaultSystemPrompts();
    }
}

function createDefaultSystemPrompts() {
    console.log('📝 Creating default system prompts...');
    systemPrompts = {
        'general': {
            content: 'You are a helpful, respectful, and honest assistant. Always answer as helpfully as possible.',
            category: 'general',
            filename: 'general.md'
        },
        'coding': {
            content: 'You are an expert programming assistant. Help users with code, debugging, and technical questions.',
            category: 'coding',
            filename: 'coding.md'
        },
        'writing': {
            content: 'You are a creative writing assistant. Help users with writing, editing, and creative projects.',
            category: 'writing',
            filename: 'writing.md'
        }
    };
    promptCategories = {
        'general': ['general'],
        'coding': ['coding'],
        'writing': ['writing']
    };
}

function loadAllPrompts() {
    try {
        if (!fs.existsSync(SYSTEM_PROMPTS_DIR)) {
            console.log('❌ System prompts directory not found');
            createDefaultSystemPrompts();
            return;
        }

        systemPrompts = {};
        promptCategories = {};

        function scanDirectory(dir, category = '') {
            try {
                const items = fs.readdirSync(dir);
                
                items.forEach(item => {
                    const fullPath = path.join(dir, item);
                    
                    try {
                        const stat = fs.statSync(fullPath);
                        
                        if (stat.isDirectory()) {
                            const newCategory = category ? `${category}/${item}` : item;
                            promptCategories[newCategory] = [];
                            scanDirectory(fullPath, newCategory);
                        } else if (stat.isFile()) {
                            if (item.endsWith('.md') || item.endsWith('.txt') || item.endsWith('.json')) {
                                try {
                                    const content = fs.readFileSync(fullPath, 'utf8');
                                    const relativePath = path.relative(SYSTEM_PROMPTS_DIR, fullPath);
                                    
                                    let promptData = {
                                        content: content,
                                        path: relativePath,
                                        category: category,
                                        filename: item,
                                        fullPath: fullPath
                                    };
                                    
                                    if (item.endsWith('.json')) {
                                        try {
                                            const jsonData = JSON.parse(content);
                                            promptData.json_content = jsonData;
                                        } catch (e) {
                                            console.warn(`⚠️ Could not parse JSON file ${fullPath}:`, e.message);
                                        }
                                    }
                                    
                                    systemPrompts[relativePath] = promptData;
                                    
                                    if (category) {
                                        if (!promptCategories[category]) {
                                            promptCategories[category] = [];
                                        }
                                        promptCategories[category].push(relativePath);
                                    }
                                } catch (fileError) {
                                    console.error(`❌ Error reading file ${fullPath}:`, fileError.message);
                                }
                            }
                        }
                    } catch (statError) {
                        console.error(`❌ Error stating ${fullPath}:`, statError.message);
                    }
                });
            } catch (readdirError) {
                console.error(`❌ Error reading directory ${dir}:`, readdirError.message);
            }
        }

        scanDirectory(SYSTEM_PROMPTS_DIR);
        console.log(`✅ Loaded ${Object.keys(systemPrompts).length} system prompts across ${Object.keys(promptCategories).length} categories`);
    } catch (error) {
        console.error('❌ Error loading system prompts:', error.message);
        createDefaultSystemPrompts();
    }
}

// AI Utility Functions
async function classifyPromptCategory(userPrompt) {
    try {
        const availableCategories = Object.keys(promptCategories);
        if (availableCategories.length === 0) {
            return 'general';
        }

        const promptLower = userPrompt.toLowerCase();
        
        // Enhanced category detection
        const categoryKeywords = {
            'coding': ['code', 'program', 'python', 'javascript', 'java', 'c++', 'html', 'css', 'function', 'algorithm', 'debug', 'error'],
            'writing': ['write', 'essay', 'story', 'article', 'blog', 'email', 'letter', 'creative', 'poem', 'novel'],
            'explanation': ['explain', 'what is', 'how does', 'why', 'meaning', 'define', 'concept'],
            'math': ['math', 'calculate', 'solve', 'equation', 'formula', 'statistics', 'probability'],
            'research': ['research', 'study', 'paper', 'thesis', 'academic', 'scholarly'],
            'business': ['business', 'marketing', 'strategy', 'plan', 'proposal', 'presentation']
        };

        for (const [category, keywords] of Object.entries(categoryKeywords)) {
            if (keywords.some(keyword => promptLower.includes(keyword)) && promptCategories[category]) {
                return category;
            }
        }

        return 'general';
    } catch (error) {
        console.error('❌ Error classifying prompt:', error.message);
        return 'general';
    }
}

async function selectBestSystemPrompt(userPrompt, category, userId = null) {
    try {
        let availablePrompts = promptCategories[category] || [];
        
        // Add user's custom prompts for this category
        if (userId) {
            const userPrompts = await dbAll(
                'SELECT name, content FROM user_system_prompts WHERE user_id = ? AND (category = ? OR category = "general") AND is_active = TRUE',
                [userId, category]
            );
            
            userPrompts.forEach((prompt, index) => {
                const userPromptId = `user_${prompt.name}_${index}`;
                systemPrompts[userPromptId] = {
                    content: prompt.content,
                    category: category,
                    filename: prompt.name,
                    isUserPrompt: true
                };
                availablePrompts.push(userPromptId);
            });
        }

        if (availablePrompts.length === 0) {
            // Fallback to general category
            availablePrompts = promptCategories['general'] || [];
            if (availablePrompts.length === 0) return null;
        }

        // Enhanced prompt selection with semantic matching
        const userPromptLower = userPrompt.toLowerCase();
        let bestMatch = null;
        let bestScore = 0;

        for (const promptPath of availablePrompts) {
            const prompt = systemPrompts[promptPath];
            let score = 0;

            // Score based on filename/keyword matching
            const filenameLower = prompt.filename.toLowerCase();
            
            // Keyword scoring
            const keywords = [
                'code', 'program', 'developer', 'coding',
                'write', 'writer', 'author', 'writing',
                'explain', 'explanation', 'teacher',
                'math', 'calculate', 'mathematics',
                'creative', 'story', 'blog'
            ];

            keywords.forEach(keyword => {
                if (userPromptLower.includes(keyword) && filenameLower.includes(keyword)) {
                    score += 3;
                } else if (userPromptLower.includes(keyword) || filenameLower.includes(keyword)) {
                    score += 1;
                }
            });

            // Prefer user prompts for better personalization
            if (prompt.isUserPrompt) {
                score += 2;
            }

            if (score > bestScore) {
                bestScore = score;
                bestMatch = prompt;
            }
        }

        return bestMatch || systemPrompts[availablePrompts[0]];
    } catch (error) {
        console.error('❌ Error selecting system prompt:', error.message);
        const availablePrompts = promptCategories[category] || promptCategories['general'] || [];
        return availablePrompts.length > 0 ? systemPrompts[availablePrompts[0]] : null;
    }
}

// Database utility functions
function dbRun(query, params = []) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) {
                reject(err);
            } else {
                resolve({ changes: this.changes, lastID: this.lastID });
            }
        });
    });
}

function dbGet(query, params = []) {
    return new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
}

function dbAll(query, params = []) {
    return new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            req.user = { role: 'guest', userId: null, username: 'guest' };
            return next();
        }

        jwt.verify(token, CONFIG.JWT_SECRET, async (err, user) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid or expired token' });
            }

            // Check if user is banned
            try {
                const userRecord = await dbGet(
                    'SELECT banned, ban_reason FROM users WHERE id = ?',
                    [user.userId]
                );

                if (userRecord && userRecord.banned) {
                    return res.status(403).json({ 
                        error: 'Account suspended',
                        details: userRecord.ban_reason || 'Your account has been suspended by administrator',
                        banned: true
                    });
                }
            } catch (dbError) {
                console.error('Error checking user ban status:', dbError);
            }

            req.user = user;
            next();
        });
    } catch (error) {
        console.error('❌ Authentication error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
};

const requireAuth = (req, res, next) => {
    if (req.user.role === 'guest') {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Log user activity
async function logUserActivity(userId, action, ipAddress, userAgent, details = null) {
    try {
        await dbRun(
            'INSERT INTO user_activity_logs (user_id, action, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)',
            [userId, action, ipAddress, userAgent, details]
        );
    } catch (error) {
        console.error('Error logging user activity:', error);
    }
}

// API Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        promptsLoaded: Object.keys(systemPrompts).length,
        categories: Object.keys(promptCategories).length,
        groq_available: groqAvailable,
        sudoapp_available: !!(CONFIG.SUDOAPP_API_KEY && CONFIG.SUDOAPP_API_KEY.length > 10),
        database: 'connected'
    });
});

// Authentication Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('User-Agent');

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const result = await dbRun(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email || null, passwordHash]
        );

        // Log registration activity
        await logUserActivity(result.lastID, 'register', ipAddress, userAgent);

        const token = jwt.sign(
            { 
                userId: result.lastID, 
                username: username, 
                role: 'user' 
            },
            CONFIG.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({ 
            message: 'User registered successfully',
            token,
            user: {
                id: result.lastID,
                username: username,
                email: email,
                role: 'user'
            }
        });
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            if (error.message.includes('username')) {
                return res.status(400).json({ error: 'Username already exists' });
            } else if (error.message.includes('email')) {
                return res.status(400).json({ error: 'Email already exists' });
            }
        }
        console.error('❌ Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('User-Agent');

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = await dbGet(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            [username, username]
        );

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if user is banned
        if (user.banned) {
            return res.status(403).json({ 
                error: 'Account suspended',
                details: user.ban_reason || 'Your account has been suspended by administrator',
                banned: true
            });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        await dbRun(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
            [user.id]
        );

        // Log login activity
        await logUserActivity(user.id, 'login', ipAddress, userAgent);

        const token = jwt.sign(
            { 
                userId: user.id, 
                username: user.username, 
                role: user.role 
            },
            CONFIG.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                tts_voice: user.tts_voice,
                theme: user.theme,
                language: user.language
            }
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Enhanced AI Chat with Conversation Management
app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { prompt, conversation_id, system_prompt_id, custom_system_prompt } = req.body;

        if (!prompt || prompt.trim().length === 0) {
            return res.status(400).json({ error: 'Prompt is required' });
        }

        // Check if user is banned (for authenticated users)
        if (req.user.role !== 'guest') {
            const user = await dbGet(
                'SELECT banned FROM users WHERE id = ?',
                [req.user.userId]
            );
            if (user && user.banned) {
                return res.status(403).json({ 
                    error: 'Account suspended',
                    details: 'Your account has been suspended. Please contact administrator.',
                    banned: true
                });
            }
        }

        let conversationId = conversation_id;
        
        // Create new conversation if no conversation_id provided
        if (!conversationId && req.user.role !== 'guest') {
            const title = prompt.substring(0, 50) + (prompt.length > 50 ? '...' : '');
            const convResult = await dbRun(
                'INSERT INTO conversations (user_id, title) VALUES (?, ?)',
                [req.user.userId, title]
            );
            conversationId = convResult.lastID;
        }

        // Add user message to conversation
        if (conversationId && req.user.role !== 'guest') {
            await dbRun(
                'INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)',
                [conversationId, 'user', prompt]
            );
        }

        let finalSystemPrompt = '';
        let selectedPromptInfo = null;
        let promptCategory = 'general';

        // Smart prompt selection
        if (custom_system_prompt) {
            finalSystemPrompt = custom_system_prompt.substring(0, 2000);
            selectedPromptInfo = { type: 'custom', content: custom_system_prompt };
        } else if (system_prompt_id) {
            if (systemPrompts[system_prompt_id]) {
                finalSystemPrompt = systemPrompts[system_prompt_id].content.substring(0, 2000);
                selectedPromptInfo = { 
                    type: 'repository', 
                    id: system_prompt_id,
                    category: systemPrompts[system_prompt_id].category,
                    filename: systemPrompts[system_prompt_id].filename
                };
                promptCategory = systemPrompts[system_prompt_id].category || 'general';
            }
        } else {
            promptCategory = await classifyPromptCategory(prompt);
            const bestPrompt = await selectBestSystemPrompt(prompt, promptCategory, req.user.userId);
            if (bestPrompt) {
                finalSystemPrompt = bestPrompt.content.substring(0, 2000);
                selectedPromptInfo = { 
                    type: bestPrompt.isUserPrompt ? 'user_custom' : 'auto_selected', 
                    id: bestPrompt.path,
                    category: bestPrompt.category,
                    filename: bestPrompt.filename 
                };
            }
        }

        // Get conversation history for context
        let conversationHistory = [];
        if (conversationId && req.user.role !== 'guest') {
            conversationHistory = await dbAll(
                'SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT 10',
                [conversationId]
            );
            conversationHistory.reverse(); // Oldest first
        }

        // Prepare messages with context
        const messages = [];
        if (finalSystemPrompt) {
            messages.push({ role: 'system', content: finalSystemPrompt });
        }
        
        // Add conversation history (excluding current prompt)
        conversationHistory.forEach(msg => {
            if (msg.role === 'user' && msg.content !== prompt) {
                messages.push({ role: 'user', content: msg.content });
            } else if (msg.role === 'ai') {
                messages.push({ role: 'assistant', content: msg.content });
            }
        });
        
        const userPrompt = prompt.length > 4000 ? prompt.substring(0, 4000) + '...' : prompt;
        messages.push({ role: 'user', content: userPrompt });

        let aiResponse;
        let tokensUsed = 0;
        let usedFallback = false;
        let selectedModel = 'groq';

        console.log(`🚀 Sending request to AI API...`);

        // Try Groq first
        if (groqAvailable) {
            try {
                const completion = await groq.chat.completions.create({
                    messages: messages,
                    model: 'llama-3.1-8b-instant',
                    temperature: 0.7,
                    max_tokens: 2048,
                    stream: false
                });

                aiResponse = completion.choices[0]?.message?.content || 'No response from AI';
                tokensUsed = completion.usage?.total_tokens || 0;
                selectedModel = 'groq';
                console.log(`✅ Groq response received (${tokensUsed} tokens)`);
            } catch (groqError) {
                console.error('❌ Groq API error:', groqError.message);
                
                // Fallback to Sudoapp if Groq fails
                if (CONFIG.SUDOAPP_API_KEY && CONFIG.SUDOAPP_API_KEY.length > 10) {
                    console.log('🔄 Groq failed, falling back to Sudoapp...');
                    usedFallback = true;
                    
                    try {
                        const response = await fetch(CONFIG.SUDOAPP_API_URL, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${CONFIG.SUDOAPP_API_KEY}`
                            },
                            body: JSON.stringify({
                                model: 'gpt-4o',
                                messages: messages,
                                temperature: 0.7,
                                max_tokens: 2048
                            })
                        });

                        if (!response.ok) {
                            const errorText = await response.text();
                            throw new Error(`Sudoapp API error: ${response.status} - ${errorText}`);
                        }

                        const data = await response.json();
                        aiResponse = data.choices[0]?.message?.content || 'No response from AI';
                        tokensUsed = data.usage?.total_tokens || 0;
                        selectedModel = 'sudoapp';
                        console.log(`✅ Sudoapp fallback response received (${tokensUsed} tokens)`);
                    } catch (fallbackError) {
                        throw new Error(`Both Groq and Sudoapp failed: ${fallbackError.message}`);
                    }
                } else {
                    throw groqError;
                }
            }
        } else {
            // Direct to Sudoapp if Groq not available
            try {
                const response = await fetch(CONFIG.SUDOAPP_API_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${CONFIG.SUDOAPP_API_KEY}`
                    },
                    body: JSON.stringify({
                        model: 'gpt-4o',
                        messages: messages,
                        temperature: 0.7,
                        max_tokens: 2048
                    })
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Sudoapp API error: ${response.status} - ${errorText}`);
                }

                const data = await response.json();
                aiResponse = data.choices[0]?.message?.content || 'No response from AI';
                tokensUsed = data.usage?.total_tokens || 0;
                selectedModel = 'sudoapp';
                console.log(`✅ Sudoapp response received (${tokensUsed} tokens)`);
            } catch (sudoappError) {
                throw new Error(`Sudoapp failed: ${sudoappError.message}`);
            }
        }

        // Save AI response to conversation
        if (conversationId && req.user.role !== 'guest') {
            await dbRun(
                `INSERT INTO messages 
                (conversation_id, role, content, model_used, system_prompt_used, prompt_category, tokens_used) 
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    conversationId, 
                    'ai', 
                    aiResponse, 
                    usedFallback ? `${selectedModel}_fallback` : selectedModel,
                    selectedPromptInfo ? JSON.stringify(selectedPromptInfo) : null,
                    promptCategory,
                    tokensUsed
                ]
            );

            // Update conversation timestamp
            await dbRun(
                'UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                [conversationId]
            );
        }

        // Log chat activity
        if (req.user.role !== 'guest') {
            await logUserActivity(
                req.user.userId, 
                'chat_message', 
                req.ip, 
                req.get('User-Agent'),
                `Category: ${promptCategory}, Tokens: ${tokensUsed}`
            );
        }

        res.json({ 
            response: aiResponse,
            model: selectedModel,
            used_fallback: usedFallback,
            system_prompt_used: selectedPromptInfo,
            category: promptCategory,
            tokens_used: tokensUsed,
            conversation_id: conversationId,
            success: true
        });
    } catch (error) {
        console.error('❌ Chat error:', error);
        res.status(500).json({ 
            error: 'Failed to process chat request',
            details: error.message,
            success: false
        });
    }
});

// Text-to-Speech Endpoint
app.post('/api/tts', authenticateToken, async (req, res) => {
    try {
        const { text, voice = 'Arista-PlayAI' } = req.body;

        if (!text || text.trim().length === 0) {
            return res.status(400).json({ error: 'Text is required for TTS' });
        }

        if (!groqAvailable) {
            return res.status(500).json({ error: 'Groq TTS service not available' });
        }

        // Validate voice
        const validVoices = [
            'Arista-PlayAI', 'Atlas-PlayAI', 'Basil-PlayAI', 'Briggs-PlayAI', 
            'Calum-PlayAI', 'Celeste-PlayAI', 'Cheyenne-PlayAI', 'Chip-PlayAI',
            'Cillian-PlayAI', 'Deedee-PlayAI', 'Fritz-PlayAI', 'Gail-PlayAI',
            'Indigo-PlayAI', 'Mamaw-PlayAI', 'Mason-PlayAI', 'Mikail-PlayAI',
            'Mitch-PlayAI', 'Quinn-PlayAI', 'Thunder-PlayAI'
        ];

        const selectedVoice = validVoices.includes(voice) ? voice : 'Arista-PlayAI';

        // Use Groq TTS
        const ttsResponse = await groq.audio.speech.create({
            model: "playai-tts",
            voice: selectedVoice,
            input: text.substring(0, 5000), // Limit text length
            speed: 1.0,
            response_format: "mp3"
        });

        // Convert response to buffer
        const audioBuffer = Buffer.from(await ttsResponse.arrayBuffer());

        res.set({
            'Content-Type': 'audio/mpeg',
            'Content-Length': audioBuffer.length,
            'Content-Disposition': 'inline; filename="tts.mp3"'
        });

        res.send(audioBuffer);

    } catch (error) {
        console.error('❌ TTS error:', error);
        res.status(500).json({ 
            error: 'Failed to generate speech',
            details: error.message
        });
    }
});

// Image Generation Endpoint - Fixed
app.post('/api/generate-image', authenticateToken, async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt || prompt.trim().length === 0) {
            return res.status(400).json({ error: 'Prompt is required' });
        }

        console.log(`🎨 Generating image for prompt: ${prompt}`);
        
        const response = await fetch(CONFIG.SEAART_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                prompt: prompt.substring(0, 500),
                width: 1024,
                height: 1024,
                steps: 20,
                cfg_scale: 7.5
            })
        });

        if (!response.ok) {
            throw new Error(`SeaArt API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        if (!data.images || !Array.isArray(data.images)) {
            throw new Error('Invalid response format from SeaArt API');
        }

        // Log image generation activity
        if (req.user.role !== 'guest') {
            await logUserActivity(
                req.user.userId, 
                'image_generation', 
                req.ip, 
                req.get('User-Agent'),
                `Prompt: ${prompt.substring(0, 100)}`
            );
        }

        res.json({ 
            images: data.images,
            prompt: prompt,
            success: true
        });
    } catch (error) {
        console.error('❌ Image generation error:', error);
        res.status(500).json({ 
            error: 'Failed to generate image',
            details: error.message,
            success: false
        });
    }
});

// Conversation Management
app.get('/api/conversations', authenticateToken, requireAuth, async (req, res) => {
    try {
        const conversations = await dbAll(
            `SELECT id, title, created_at, updated_at 
             FROM conversations 
             WHERE user_id = ? AND is_active = TRUE
             ORDER BY updated_at DESC 
             LIMIT 50`,
            [req.user.userId]
        );

        res.json({ conversations });
    } catch (error) {
        console.error('❌ Conversations fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch conversations' });
    }
});

app.get('/api/conversations/:id/messages', authenticateToken, requireAuth, async (req, res) => {
    try {
        const conversationId = req.params.id;
        
        // Verify conversation belongs to user
        const conversation = await dbGet(
            'SELECT id FROM conversations WHERE id = ? AND user_id = ?',
            [conversationId, req.user.userId]
        );

        if (!conversation) {
            return res.status(404).json({ error: 'Conversation not found' });
        }

        const messages = await dbAll(
            `SELECT role, content, model_used, tokens_used, created_at 
             FROM messages 
             WHERE conversation_id = ? 
             ORDER BY created_at ASC`,
            [conversationId]
        );

        res.json({ messages });
    } catch (error) {
        console.error('❌ Messages fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

app.delete('/api/conversations/:id', authenticateToken, requireAuth, async (req, res) => {
    try {
        const conversationId = req.params.id;
        
        // Verify conversation belongs to user
        const conversation = await dbGet(
            'SELECT id FROM conversations WHERE id = ? AND user_id = ?',
            [conversationId, req.user.userId]
        );

        if (!conversation) {
            return res.status(404).json({ error: 'Conversation not found' });
        }

        await dbRun(
            'UPDATE conversations SET is_active = FALSE WHERE id = ?',
            [conversationId]
        );

        res.json({ message: 'Conversation deleted successfully' });
    } catch (error) {
        console.error('❌ Conversation delete error:', error);
        res.status(500).json({ error: 'Failed to delete conversation' });
    }
});

// System Prompts Management
app.post('/api/system-prompts', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { name, content, category = 'general', is_public = false } = req.body;

        if (!name || !content) {
            return res.status(400).json({ error: 'Name and content are required' });
        }

        const result = await dbRun(
            'INSERT INTO user_system_prompts (user_id, name, content, category, is_public) VALUES (?, ?, ?, ?, ?)',
            [req.user.userId, name, content, category, is_public]
        );

        res.status(201).json({
            message: 'System prompt created successfully',
            prompt: {
                id: result.lastID,
                name,
                content,
                category,
                is_public
            }
        });
    } catch (error) {
        console.error('❌ System prompt creation error:', error);
        res.status(500).json({ error: 'Failed to create system prompt' });
    }
});

app.get('/api/system-prompts', authenticateToken, requireAuth, async (req, res) => {
    try {
        const userPrompts = await dbAll(
            'SELECT id, name, content, category, is_public, created_at FROM user_system_prompts WHERE user_id = ? AND is_active = TRUE ORDER BY created_at DESC',
            [req.user.userId]
        );

        const publicPrompts = await dbAll(
            'SELECT id, name, content, category, created_at FROM user_system_prompts WHERE is_public = TRUE AND is_active = TRUE AND user_id != ? ORDER BY created_at DESC',
            [req.user.userId]
        );

        res.json({
            user_prompts: userPrompts,
            public_prompts: publicPrompts
        });
    } catch (error) {
        console.error('❌ System prompts fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch system prompts' });
    }
});

app.delete('/api/system-prompts/:id', authenticateToken, requireAuth, async (req, res) => {
    try {
        const promptId = req.params.id;
        
        // Verify prompt belongs to user
        const prompt = await dbGet(
            'SELECT id FROM user_system_prompts WHERE id = ? AND user_id = ?',
            [promptId, req.user.userId]
        );

        if (!prompt) {
            return res.status(404).json({ error: 'System prompt not found' });
        }

        await dbRun(
            'UPDATE user_system_prompts SET is_active = FALSE WHERE id = ?',
            [promptId]
        );

        res.json({ message: 'System prompt deleted successfully' });
    } catch (error) {
        console.error('❌ System prompt delete error:', error);
        res.status(500).json({ error: 'Failed to delete system prompt' });
    }
});

// User Profile Management
app.put('/api/user/profile', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { username, email, tts_voice, theme, language } = req.body;

        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        if (email && !/\S+@\S+\.\S+/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const existingUser = await dbGet(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
            [username, email, req.user.userId]
        );

        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        await dbRun(
            'UPDATE users SET username = ?, email = ?, tts_voice = ?, theme = ?, language = ? WHERE id = ?',
            [username, email || null, tts_voice, theme, language, req.user.userId]
        );

        res.json({ 
            message: 'Profile updated successfully',
            user: {
                id: req.user.userId,
                username: username,
                email: email,
                tts_voice: tts_voice,
                theme: theme,
                language: language
            }
        });
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        console.error('❌ Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.get('/api/user/profile', authenticateToken, requireAuth, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT u.id, u.username, u.email, u.role, u.banned, u.ban_reason, u.created_at, u.last_login,
                    u.tts_voice, u.theme, u.language
             FROM users u 
             WHERE u.id = ?`,
            [req.user.userId]
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const stats = await dbGet(
            `SELECT 
                COUNT(DISTINCT c.id) as total_conversations,
                COUNT(m.id) as total_messages,
                SUM(m.tokens_used) as total_tokens,
                COUNT(DISTINCT m.prompt_category) as categories_used
             FROM conversations c
             LEFT JOIN messages m ON c.id = m.conversation_id
             WHERE c.user_id = ? AND c.is_active = TRUE`,
            [req.user.userId]
        );

        res.json({
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                banned: user.banned,
                ban_reason: user.ban_reason,
                created_at: user.created_at,
                last_login: user.last_login,
                tts_voice: user.tts_voice,
                theme: user.theme,
                language: user.language
            },
            stats: stats || { total_conversations: 0, total_messages: 0, total_tokens: 0, categories_used: 0 }
        });
    } catch (error) {
        console.error('❌ Get profile error:', error);
        res.status(500).json({ error: 'Failed to get profile' });
    }
});

// Admin Routes
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await dbAll(
            `SELECT u.id, u.username, u.email, u.role, u.banned, u.ban_reason, u.banned_at, u.created_at, u.last_login,
                    COUNT(DISTINCT c.id) as conversation_count, 
                    COUNT(m.id) as message_count,
                    SUM(m.tokens_used) as total_tokens
             FROM users u
             LEFT JOIN conversations c ON u.id = c.user_id AND c.is_active = TRUE
             LEFT JOIN messages m ON c.id = m.conversation_id
             GROUP BY u.id
             ORDER BY u.created_at DESC`
        );

        res.json({ users });
    } catch (error) {
        console.error('❌ Admin users fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/admin/user/:id/details', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;

        const user = await dbGet(
            `SELECT u.*, 
                    COUNT(DISTINCT c.id) as conversation_count,
                    COUNT(m.id) as message_count,
                    SUM(m.tokens_used) as total_tokens
             FROM users u
             LEFT JOIN conversations c ON u.id = c.user_id AND c.is_active = TRUE
             LEFT JOIN messages m ON c.id = m.conversation_id
             WHERE u.id = ?
             GROUP BY u.id`,
            [userId]
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const conversations = await dbAll(
            `SELECT c.id, c.title, c.created_at, c.updated_at,
                    COUNT(m.id) as message_count,
                    SUM(m.tokens_used) as tokens_used
             FROM conversations c
             LEFT JOIN messages m ON c.id = m.conversation_id
             WHERE c.user_id = ? AND c.is_active = TRUE
             GROUP BY c.id
             ORDER BY c.updated_at DESC
             LIMIT 20`,
            [userId]
        );

        const activityLogs = await dbAll(
            `SELECT action, ip_address, user_agent, details, created_at
             FROM user_activity_logs
             WHERE user_id = ?
             ORDER BY created_at DESC
             LIMIT 50`,
            [userId]
        );

        res.json({
            user,
            conversations,
            activity_logs: activityLogs
        });
    } catch (error) {
        console.error('❌ Admin user details error:', error);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

app.post('/api/admin/users/:id/ban', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const { reason } = req.body;

        if (isNaN(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        if (userId === req.user.userId) {
            return res.status(400).json({ error: 'Cannot ban your own account' });
        }

        const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.banned) {
            return res.status(400).json({ error: 'User is already banned' });
        }

        // Ban the user
        await dbRun(
            'UPDATE users SET banned = TRUE, ban_reason = ?, banned_at = CURRENT_TIMESTAMP WHERE id = ?',
            [reason || 'Violation of terms of service', userId]
        );

        // Record ban history
        await dbRun(
            'INSERT INTO ban_history (user_id, admin_id, action, reason) VALUES (?, ?, ?, ?)',
            [userId, req.user.userId, 'ban', reason]
        );

        // Log admin action
        await logUserActivity(
            req.user.userId, 
            'ban_user', 
            req.ip, 
            req.get('User-Agent'),
            `Banned user: ${user.username}, Reason: ${reason}`
        );

        res.json({ 
            message: 'User banned successfully',
            user: {
                id: userId,
                username: user.username,
                banned: true,
                ban_reason: reason
            }
        });
    } catch (error) {
        console.error('❌ Ban user error:', error);
        res.status(500).json({ error: 'Failed to ban user' });
    }
});

app.post('/api/admin/users/:id/unban', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        if (isNaN(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.banned) {
            return res.status(400).json({ error: 'User is not banned' });
        }

        // Unban the user
        await dbRun(
            'UPDATE users SET banned = FALSE, ban_reason = NULL, banned_at = NULL WHERE id = ?',
            [userId]
        );

        // Record unban history
        await dbRun(
            'INSERT INTO ban_history (user_id, admin_id, action, reason) VALUES (?, ?, ?, ?)',
            [userId, req.user.userId, 'unban', 'Administrative action']
        );

        // Log admin action
        await logUserActivity(
            req.user.userId, 
            'unban_user', 
            req.ip, 
            req.get('User-Agent'),
            `Unbanned user: ${user.username}`
        );

        res.json({ 
            message: 'User unbanned successfully',
            user: {
                id: userId,
                username: user.username,
                banned: false
            }
        });
    } catch (error) {
        console.error('❌ Unban user error:', error);
        res.status(500).json({ error: 'Failed to unban user' });
    }
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalUsers = await dbGet('SELECT COUNT(*) as count FROM users');
        const bannedUsers = await dbGet('SELECT COUNT(*) as count FROM users WHERE banned = TRUE');
        const totalConversations = await dbGet('SELECT COUNT(*) as count FROM conversations WHERE is_active = TRUE');
        const totalMessages = await dbGet('SELECT COUNT(*) as count FROM messages');
        const totalTokens = await dbGet('SELECT SUM(tokens_used) as count FROM messages');
        
        const activeUsers = await dbGet(`
            SELECT COUNT(DISTINCT user_id) as count 
            FROM user_activity_logs 
            WHERE created_at > datetime('now', '-7 days')
        `);

        const popularCategories = await dbAll(`
            SELECT prompt_category, COUNT(*) as usage_count
            FROM messages 
            WHERE prompt_category IS NOT NULL
            GROUP BY prompt_category 
            ORDER BY usage_count DESC 
            LIMIT 10
        `);

        const modelUsage = await dbAll(`
            SELECT model_used, COUNT(*) as usage_count
            FROM messages 
            WHERE model_used IS NOT NULL
            GROUP BY model_used 
            ORDER BY usage_count DESC
        `);

        const recentActivity = await dbAll(`
            SELECT u.username, ual.action, ual.details, ual.created_at
            FROM user_activity_logs ual
            JOIN users u ON ual.user_id = u.id
            ORDER BY ual.created_at DESC
            LIMIT 20
        `);

        res.json({
            totalUsers: totalUsers.count,
            bannedUsers: bannedUsers.count,
            totalConversations: totalConversations.count,
            totalMessages: totalMessages.count,
            totalTokens: totalTokens.count || 0,
            activeUsers: activeUsers.count,
            popularCategories: popularCategories,
            modelUsage: modelUsage,
            recentActivity: recentActivity
        });
    } catch (error) {
        console.error('❌ Admin stats error:', error);
        res.status(500).json({ error: 'Failed to fetch admin stats' });
    }
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: '🤖 aifromearth - Advanced AI Chatting Application Server',
        version: '3.0.0',
        status: 'running',
        features: [
            'Smart Prompt Selection & Custom Prompts',
            'Conversation Management',
            'Text-to-Speech (TTS) Support',
            'Image Generation',
            'User Activity Logging',
            'Admin Security Panel',
            'Multi-AI Provider Fallback'
        ],
        endpoints: {
            auth: ['POST /api/register', 'POST /api/login'],
            user: [
                'GET /api/user/profile',
                'PUT /api/user/profile'
            ],
            chat: [
                'POST /api/chat',
                'GET /api/conversations',
                'GET /api/conversations/:id/messages'
            ],
            ai_services: [
                'POST /api/generate-image',
                'POST /api/tts'
            ],
            system_prompts: [
                'GET /api/system-prompts',
                'POST /api/system-prompts',
                'DELETE /api/system-prompts/:id'
            ],
            admin: [
                'GET /api/admin/users',
                'GET /api/admin/user/:id/details',
                'POST /api/admin/users/:id/ban',
                'POST /api/admin/users/:id/unban',
                'GET /api/admin/stats'
            ],
            health: ['GET /api/health']
        }
    });
});

// Handle undefined routes
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error handler:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// Initialize and start server
async function startServer() {
    try {
        console.log('🚀 Starting Enhanced aifromearth Chat Server...');
        
        await initializeSystemPrompts();
        
        app.listen(PORT, () => {
            console.log('='.repeat(60));
            console.log(`🎯 Server running on port ${PORT}`);
            console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
            console.log(`📝 System prompts loaded: ${Object.keys(systemPrompts).length}`);
            console.log(`📁 Categories available: ${Object.keys(promptCategories).length}`);
            console.log(`🤖 Groq AI: ${groqAvailable ? '✅ ENABLED' : '❌ DISABLED'}`);
            console.log(`🦊 Sudoapp AI: ${CONFIG.SUDOAPP_API_KEY && CONFIG.SUDOAPP_API_KEY.length > 10 ? '✅ ENABLED' : '❌ DISABLED'}`);
            console.log(`🎤 TTS Service: ${groqAvailable ? '✅ ENABLED' : '❌ DISABLED'}`);
            console.log(`🎨 Image Generation: ✅ ENABLED`);
            console.log(`🔒 Admin Security: ✅ ENABLED`);
            console.log(`📊 Activity Logging: ✅ ENABLED`);
            console.log('='.repeat(60));
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down server gracefully...');
    db.close((err) => {
        if (err) {
            console.error('❌ Error closing database:', err.message);
        } else {
            console.log('✅ Database connection closed.');
        }
        process.exit(0);
    });
});

startServer();