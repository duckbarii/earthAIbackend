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

const app = express();
const PORT = process.env.PORT || 1100;

// Configuration - UPDATED with correct SudoApp URL
const CONFIG = {
    GROQ_API_KEY: process.env.GROQ_API_KEY || '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',
    SUDOAPP_API_KEY: process.env.SUDOAPP_API_KEY || '3fd5e44f6859749864550d7da6697cf1a392b83fb712e734e49d9eba118bb669',
    JWT_SECRET: process.env.JWT_SECRET || '32b635cb52cb2551b7e4019f92a09da8',
    SUDOAPP_API_URL: 'https://sudoapp.dev/api/v1/chat/completions', // CORRECTED URL
    SEAART_API_URL: 'https://seaart-ai.apis-bj-devs.workers.dev'
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

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Database initialization
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('✅ Connected to SQLite database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        // Enhanced users table with banned status
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
            last_login DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) console.error('❌ Error creating users table:', err);
            else console.log('✅ Users table ready');
        });

        db.run(`CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            prompt TEXT NOT NULL,
            response TEXT NOT NULL,
            model_used TEXT,
            system_prompt_used TEXT,
            prompt_category TEXT,
            tokens_used INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`, (err) => {
            if (err) console.error('❌ Error creating chat_history table:', err);
            else console.log('✅ Chat history table ready');
        });

        db.run(`CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            default_model TEXT DEFAULT 'groq',
            default_system_prompt TEXT,
            theme TEXT DEFAULT 'dark',
            language TEXT DEFAULT 'en',
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`, (err) => {
            if (err) console.error('❌ Error creating user_preferences table:', err);
            else console.log('✅ User preferences table ready');
        });

        db.run(`CREATE TABLE IF NOT EXISTS custom_system_prompts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT,
            is_public BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`, (err) => {
            if (err) console.error('❌ Error creating custom_system_prompts table:', err);
            else console.log('✅ Custom system prompts table ready');
        });

        // Ban history table
        db.run(`CREATE TABLE IF NOT EXISTS ban_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            admin_id INTEGER,
            action TEXT NOT NULL, -- 'ban' or 'unban'
            reason TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(admin_id) REFERENCES users(id)
        )`, (err) => {
            if (err) console.error('❌ Error creating ban_history table:', err);
            else console.log('✅ Ban history table ready');
        });
    });
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
                SYSTEM_PROMPTS_DIR
            );
            console.log('✅ System prompts repository cloned successfully.');
        } else {
            console.log('✅ System prompts directory already exists');
        }
        loadAllPrompts();
    } catch (error) {
        console.error('❌ Error initializing system prompts:', error.message);
    }
}

function loadAllPrompts() {
    try {
        if (!fs.existsSync(SYSTEM_PROMPTS_DIR)) {
            console.log('❌ System prompts directory not found');
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
    }
}

// AI Utility Functions
async function classifyPromptCategory(userPrompt) {
    try {
        const availableCategories = Object.keys(promptCategories);
        if (availableCategories.length === 0) {
            return 'general';
        }

        // Simple keyword-based classification as fallback
        const promptLower = userPrompt.toLowerCase();
        
        if (promptLower.includes('code') || promptLower.includes('program') || promptLower.includes('python') || promptLower.includes('javascript')) {
            return 'coding' in promptCategories ? 'coding' : 'general';
        }
        if (promptLower.includes('write') || promptLower.includes('essay') || promptLower.includes('story')) {
            return 'writing' in promptCategories ? 'writing' : 'general';
        }
        if (promptLower.includes('explain') || promptLower.includes('what is') || promptLower.includes('how does')) {
            return 'explanation' in promptCategories ? 'explanation' : 'general';
        }
        if (promptLower.includes('math') || promptLower.includes('calculate') || promptLower.includes('solve')) {
            return 'math' in promptCategories ? 'math' : 'general';
        }

        return 'general';
    } catch (error) {
        console.error('❌ Error classifying prompt:', error.message);
        return 'general';
    }
}

async function selectBestSystemPrompt(userPrompt, category) {
    try {
        const availablePrompts = promptCategories[category] || [];
        if (availablePrompts.length === 0) return null;

        // Simple keyword matching
        const userPromptLower = userPrompt.toLowerCase();
        
        for (const promptPath of availablePrompts) {
            const prompt = systemPrompts[promptPath];
            const filenameLower = prompt.filename.toLowerCase();
            
            if (userPromptLower.includes('code') && filenameLower.includes('code')) {
                return prompt;
            }
            if (userPromptLower.includes('write') && filenameLower.includes('writing')) {
                return prompt;
            }
            if (userPromptLower.includes('explain') && filenameLower.includes('explanation')) {
                return prompt;
            }
            if (userPromptLower.includes('math') && filenameLower.includes('math')) {
                return prompt;
            }
        }
        
        return systemPrompts[availablePrompts[0]];
    } catch (error) {
        console.error('❌ Error selecting system prompt:', error.message);
        const availablePrompts = promptCategories[category] || [];
        return availablePrompts.length > 0 ? systemPrompts[availablePrompts[0]] : null;
    }
}

// Authentication Middleware with ban check
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

        await dbRun(
            'INSERT INTO user_preferences (user_id) VALUES (?)',
            [result.lastID]
        );

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
                role: user.role
            }
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Enhanced AI Chat with proper SudoApp integration
app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { prompt, model = 'auto', system_prompt_id, custom_system_prompt } = req.body;

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

        // Auto model selection
        let selectedModel = model;
        if (model === 'auto') {
            selectedModel = groqAvailable ? 'groq' : 'sudoapp';
        }

        // Model availability check
        if (selectedModel === 'groq' && !groqAvailable) {
            console.log('⚠️ Groq not available, switching to Sudoapp');
            selectedModel = 'sudoapp';
        }

        if (selectedModel === 'sudoapp' && (!CONFIG.SUDOAPP_API_KEY || CONFIG.SUDOAPP_API_KEY.length < 10)) {
            if (groqAvailable) {
                console.log('⚠️ Sudoapp not available, switching to Groq');
                selectedModel = 'groq';
            } else {
                return res.status(400).json({ 
                    error: 'No AI service available',
                    details: 'Both Groq and Sudoapp are not configured properly'
                });
            }
        }

        let finalSystemPrompt = '';
        let selectedPromptInfo = null;
        let promptCategory = 'general';

        // Smart prompt selection
        if (custom_system_prompt) {
            finalSystemPrompt = custom_system_prompt.substring(0, 1000);
            selectedPromptInfo = { type: 'custom', content: custom_system_prompt };
        } else if (system_prompt_id) {
            if (systemPrompts[system_prompt_id]) {
                finalSystemPrompt = systemPrompts[system_prompt_id].content.substring(0, 1500);
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
            const bestPrompt = await selectBestSystemPrompt(prompt, promptCategory);
            if (bestPrompt) {
                finalSystemPrompt = bestPrompt.content.substring(0, 1500);
                selectedPromptInfo = { 
                    type: 'auto_selected', 
                    id: bestPrompt.path,
                    category: bestPrompt.category,
                    filename: bestPrompt.filename 
                };
            }
        }

        // Prepare messages
        const messages = [];
        if (finalSystemPrompt) {
            messages.push({ role: 'system', content: finalSystemPrompt });
        }
        
        const userPrompt = prompt.length > 2000 ? prompt.substring(0, 2000) + '...' : prompt;
        messages.push({ role: 'user', content: userPrompt });

        let aiResponse;
        let tokensUsed = 0;
        let usedFallback = false;

        console.log(`🚀 Sending request to ${selectedModel} API...`);

        if (selectedModel === 'groq') {
            try {
                const completion = await groq.chat.completions.create({
                    messages: messages,
                    model: 'llama-3.1-8b-instant',
                    temperature: 0.7,
                    max_tokens: 1024,
                    stream: false
                });

                aiResponse = completion.choices[0]?.message?.content || 'No response from AI';
                tokensUsed = completion.usage?.total_tokens || 0;
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
                                max_tokens: 1024
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
        } else if (selectedModel === 'sudoapp') {
            try {
                const response = await fetch(CONFIG.SUDOAPP_API_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${CONFIG.SUDOAPP_API_KEY}`
                    },
                    body: JSON.stringify({
                        model: 'gpt-4o', // Using gpt-4o as per the example
                        messages: messages,
                        temperature: 0.7,
                        max_tokens: 1024
                    })
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Sudoapp API error: ${response.status} - ${errorText}`);
                }

                const data = await response.json();
                aiResponse = data.choices[0]?.message?.content || 'No response from AI';
                tokensUsed = data.usage?.total_tokens || 0;
                console.log(`✅ Sudoapp response received (${tokensUsed} tokens)`);
            } catch (sudoappError) {
                console.error('❌ Sudoapp API error:', sudoappError);
                
                // Fallback to Groq if Sudoapp fails
                if (groqAvailable) {
                    console.log('🔄 Sudoapp failed, falling back to Groq...');
                    usedFallback = true;
                    
                    try {
                        const completion = await groq.chat.completions.create({
                            messages: messages,
                            model: 'llama-3.1-8b-instant',
                            temperature: 0.7,
                            max_tokens: 1024
                        });

                        aiResponse = completion.choices[0]?.message?.content || 'No response from AI';
                        tokensUsed = completion.usage?.total_tokens || 0;
                        selectedModel = 'groq';
                        console.log(`✅ Groq fallback response received (${tokensUsed} tokens)`);
                    } catch (fallbackError) {
                        throw new Error(`Both Sudoapp and Groq failed: ${fallbackError.message}`);
                    }
                } else {
                    throw sudoappError;
                }
            }
        }

        // Save to chat history for authenticated users
        if (req.user.role !== 'guest') {
            try {
                await dbRun(
                    `INSERT INTO chat_history 
                    (user_id, prompt, response, model_used, system_prompt_used, prompt_category, tokens_used) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [
                        req.user.userId, 
                        prompt, 
                        aiResponse, 
                        usedFallback ? `${selectedModel}_fallback` : selectedModel,
                        selectedPromptInfo ? JSON.stringify(selectedPromptInfo) : null,
                        promptCategory,
                        tokensUsed
                    ]
                );
            } catch (dbError) {
                console.error('❌ Error saving chat history:', dbError);
            }
        }

        res.json({ 
            response: aiResponse,
            model: selectedModel,
            used_fallback: usedFallback,
            system_prompt_used: selectedPromptInfo,
            category: promptCategory,
            tokens_used: tokensUsed,
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

// Image Generation
app.post('/api/generate-image', authenticateToken, async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt || prompt.trim().length === 0) {
            return res.status(400).json({ error: 'Prompt is required' });
        }

        const encodedPrompt = encodeURIComponent(prompt.substring(0, 500));
        const imageUrl = `${CONFIG.SEAART_API_URL}/?Prompt=${encodedPrompt}`;

        console.log(`🎨 Generating image for prompt: ${prompt}`);
        
        const response = await fetch(imageUrl);

        if (!response.ok) {
            throw new Error(`SeaArt API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        if (!data.result || !Array.isArray(data.result)) {
            throw new Error('Invalid response format from SeaArt API');
        }

        res.json({ 
            images: data.result,
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

// User Management Routes
app.put('/api/user/change-password', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current password and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters' });
        }

        const user = await dbGet(
            'SELECT * FROM users WHERE id = ?',
            [req.user.userId]
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 10);

        await dbRun(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            [newPasswordHash, req.user.userId]
        );

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('❌ Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

app.put('/api/user/profile', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { username, email } = req.body;

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
            'UPDATE users SET username = ?, email = ? WHERE id = ?',
            [username, email || null, req.user.userId]
        );

        res.json({ 
            message: 'Profile updated successfully',
            user: {
                id: req.user.userId,
                username: username,
                email: email
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
                    up.default_model, up.default_system_prompt, up.theme, up.language
             FROM users u 
             LEFT JOIN user_preferences up ON u.id = up.user_id
             WHERE u.id = ?`,
            [req.user.userId]
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const stats = await dbGet(
            `SELECT 
                COUNT(*) as total_chats,
                SUM(tokens_used) as total_tokens,
                COUNT(DISTINCT prompt_category) as categories_used
             FROM chat_history 
             WHERE user_id = ?`,
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
                last_login: user.last_login
            },
            preferences: {
                default_model: user.default_model,
                default_system_prompt: user.default_system_prompt,
                theme: user.theme,
                language: user.language
            },
            stats: stats || { total_chats: 0, total_tokens: 0, categories_used: 0 }
        });
    } catch (error) {
        console.error('❌ Get profile error:', error);
        res.status(500).json({ error: 'Failed to get profile' });
    }
});

// Chat History Management
app.get('/api/chat/history', authenticateToken, requireAuth, async (req, res) => {
    try {
        const { page = 1, limit = 50, category, model } = req.query;
        const offset = (page - 1) * limit;

        let whereClause = 'WHERE user_id = ?';
        let params = [req.user.userId];

        if (category) {
            whereClause += ' AND prompt_category = ?';
            params.push(category);
        }

        if (model) {
            whereClause += ' AND model_used = ?';
            params.push(model);
        }

        const history = await dbAll(
            `SELECT id, prompt, response, model_used, system_prompt_used, prompt_category, tokens_used, timestamp 
             FROM chat_history 
             ${whereClause}
             ORDER BY timestamp DESC 
             LIMIT ? OFFSET ?`,
            [...params, parseInt(limit), offset]
        );

        const total = await dbGet(
            `SELECT COUNT(*) as count FROM chat_history ${whereClause}`,
            params
        );

        const parsedHistory = history.map(item => ({
            ...item,
            system_prompt_used: item.system_prompt_used ? JSON.parse(item.system_prompt_used) : null
        }));

        res.json({
            history: parsedHistory,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: total.count,
                totalPages: Math.ceil(total.count / limit)
            }
        });
    } catch (error) {
        console.error('❌ Chat history error:', error);
        res.status(500).json({ error: 'Failed to fetch chat history' });
    }
});

// System Prompts Management
app.get('/api/system-prompts', authenticateToken, (req, res) => {
    try {
        const categories = Object.keys(promptCategories).map(category => ({
            name: category,
            prompt_count: promptCategories[category].length,
            prompts: promptCategories[category].map(promptPath => ({
                id: promptPath,
                filename: systemPrompts[promptPath].filename,
                category: systemPrompts[promptPath].category,
                preview: systemPrompts[promptPath].content.substring(0, 150) + '...',
                full_path: promptPath
            }))
        }));

        res.json({
            total_prompts: Object.keys(systemPrompts).length,
            total_categories: categories.length,
            categories: categories
        });
    } catch (error) {
        console.error('❌ System prompts fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch system prompts' });
    }
});

// Admin Routes with Ban/Unban Features
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await dbAll(
            `SELECT u.id, u.username, u.email, u.role, u.banned, u.ban_reason, u.banned_at, u.created_at, u.last_login,
                    COUNT(ch.id) as chat_count, 
                    SUM(ch.tokens_used) as total_tokens
             FROM users u
             LEFT JOIN chat_history ch ON u.id = ch.user_id
             GROUP BY u.id
             ORDER BY u.created_at DESC`
        );

        res.json({ users });
    } catch (error) {
        console.error('❌ Admin users fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Ban user
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

// Unban user
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

// Get ban history
app.get('/api/admin/ban-history', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const history = await dbAll(`
            SELECT bh.*, u.username as user_username, a.username as admin_username
            FROM ban_history bh
            JOIN users u ON bh.user_id = u.id
            JOIN users a ON bh.admin_id = a.id
            ORDER BY bh.created_at DESC
        `);

        res.json({ history });
    } catch (error) {
        console.error('❌ Ban history fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch ban history' });
    }
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalUsers = await dbGet('SELECT COUNT(*) as count FROM users');
        const bannedUsers = await dbGet('SELECT COUNT(*) as count FROM users WHERE banned = TRUE');
        const totalChats = await dbGet('SELECT COUNT(*) as count FROM chat_history');
        const totalTokens = await dbGet('SELECT SUM(tokens_used) as count FROM chat_history');
        const activeUsers = await dbGet(`
            SELECT COUNT(DISTINCT user_id) as count 
            FROM chat_history 
            WHERE timestamp > datetime('now', '-7 days')
        `);

        const popularCategories = await dbAll(`
            SELECT prompt_category, COUNT(*) as usage_count
            FROM chat_history 
            GROUP BY prompt_category 
            ORDER BY usage_count DESC 
            LIMIT 10
        `);

        const modelUsage = await dbAll(`
            SELECT model_used, COUNT(*) as usage_count
            FROM chat_history 
            GROUP BY model_used 
            ORDER BY usage_count DESC
        `);

        res.json({
            totalUsers: totalUsers.count,
            bannedUsers: bannedUsers.count,
            totalChats: totalChats.count,
            totalTokens: totalTokens.count || 0,
            activeUsers: activeUsers.count,
            popularCategories: popularCategories,
            modelUsage: modelUsage
        });
    } catch (error) {
        console.error('❌ Admin stats error:', error);
        res.status(500).json({ error: 'Failed to fetch admin stats' });
    }
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: '🤖 Advanced AI Chatting Application Server',
        version: '2.2.0',
        status: 'running',
        features: [
            'Smart Prompt Selection',
            'Guest Mode Support',
            'User Ban/Unban System',
            'Dual AI Provider Support',
            'Auto Fallback Between AI Services'
        ],
        endpoints: {
            auth: ['POST /api/register', 'POST /api/login'],
            user: [
                'GET /api/user/profile',
                'PUT /api/user/profile', 
                'PUT /api/user/change-password'
            ],
            chat: [
                'POST /api/chat',
                'POST /api/generate-image',
                'GET /api/chat/history'
            ],
            admin: [
                'GET /api/admin/users',
                'POST /api/admin/users/:id/ban',
                'POST /api/admin/users/:id/unban',
                'GET /api/admin/ban-history',
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
        console.log('🚀 Starting Advanced AI Chat Server...');
        
        await initializeSystemPrompts();
        
        app.listen(PORT, () => {
            console.log('='.repeat(60));
            console.log(`🎯 Server running on port ${PORT}`);
            console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
            console.log(`📝 System prompts loaded: ${Object.keys(systemPrompts).length}`);
            console.log(`📁 Categories available: ${Object.keys(promptCategories).length}`);
            console.log(`🤖 Groq AI: ${groqAvailable ? '✅ ENABLED' : '❌ DISABLED'}`);
            console.log(`🦊 Sudoapp AI: ${CONFIG.SUDOAPP_API_KEY && CONFIG.SUDOAPP_API_KEY.length > 10 ? '✅ ENABLED' : '❌ DISABLED'}`);
            console.log('🔒 User Ban System: ✅ ENABLED');
            console.log('🔄 Auto Fallback: ✅ ENABLED');
            console.log('👥 Guest mode: ✅ ENABLED');
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