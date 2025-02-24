const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
require('dotenv').config();

const app = express();
const port = 3000; // Usando a porta 3000

// Configuração do express-session (SIMPLIFICADA)
app.use(session({
    secret: process.env.SESSION_SECRET, // Use uma chave MUITO forte no seu .env
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,  // SEMPRE true
        secure: false,   // false para localhost (NÃO use true em desenvolvimento local)
        maxAge: 1000 * 60 * 60 * 24 // 1 dia
    }
}));

// Middleware para JSON (com tratamento para requisições sem corpo)
app.use((req, res, next) => {
    if (req.method === 'POST' || req.method === 'PUT') {
        if (req.headers['content-type'] === 'application/json' && req.headers['content-length'] !== '0') {
            express.json()(req, res, next);
        } else {
            next();
        }
    } else {
        next();
    }
});

// Configuração da conexão (igual)
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let connection;

async function connectToDatabase() {
    try {
        connection = await mysql.createPool(dbConfig);
        console.log('Conectado ao banco de dados!');
    } catch (error) {
        console.error('Erro ao conectar ao banco de dados:', error);
        process.exit(1);
    }
}

connectToDatabase();

// Middleware de autenticação (SIMPLIFICADO)
function requireAuth(req, res, next) {
    console.log("REQUIRE AUTH - Session ID:", req.sessionID); // LOG
    console.log("REQUIRE AUTH - User ID:", req.session.userId); // LOG
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Não autenticado.' });
    }
}

// --- Rotas ---

// Cadastro (SIMPLIFICADO - Sem validações extras)
app.post('/api/cadastro', async (req, res) => {
    try {
        const { email, senha, tipo_pessoa, nome_completo, cpf_cnpj, endereco, numero, complemento, bairro, cidade, estado, cep, telefone, telefone_empresa, whatsapp, mostrar_dados_orcamento } = req.body; // Campos mínimos

        if (!email || !senha || !tipo_pessoa || !nome_completo || !cpf_cnpj) {
          return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
        }

        //Verificação se o email já existe
        const [existingUser] = await connection.execute('SELECT id FROM usuarios WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ error: 'E-mail já cadastrado.' }); // 409 = Conflict
        }

         // VERIFICAÇÃO DE CPF/CNPJ DUPLICADO
         const [existingProfile] = await connection.execute('SELECT id FROM perfis WHERE cpf_cnpj = ?', [cpf_cnpj]);
        if (existingProfile.length > 0) {
            return res.status(409).json({ error: 'CPF/CNPJ já cadastrado.' }); // 409 = Conflict
        }

        const hashedPassword = await bcrypt.hash(senha, 10);

        const [userResult] = await connection.execute(
            'INSERT INTO usuarios (email, senha) VALUES (?, ?)',
            [email, hashedPassword]
        );
        const userId = userResult.insertId;

         // Inserir o perfil no banco de dados:
        const [profileResult] = await connection.execute(
            'INSERT INTO perfis (usuario_id, tipo_pessoa, nome_completo, cpf_cnpj,endereco, numero, complemento, bairro, cidade, estado, cep, telefone, telefone_empresa, whatsapp, mostrar_dados_orcamento) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, tipo_pessoa, nome_completo, cpf_cnpj, endereco, numero, complemento, bairro, cidade, estado, cep, telefone, telefone_empresa, whatsapp, mostrar_dados_orcamento]
        );

        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId });

    } catch (error) {
        console.error('Erro no cadastro:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha } = req.body;

        if (!email || !senha) {
            return res.status(400).json({ error: 'Campos obrigatórios faltando.' });
        }

        const [users] = await connection.execute('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas.' });
        }
        const user = users[0];

        const match = await bcrypt.compare(senha, user.senha);
        if (!match) {
            return res.status(401).json({ error: 'Credenciais inválidas.' });
        }


        // ### REMOVIDO TEMPORARIAMENTE O LIMITE DE SESSÕES ###
        req.session.userId = user.id;
        console.log("LOGIN - Session ID:", req.sessionID); // LOG
        console.log("LOGIN - User ID:", req.session.userId); // LOG
        res.json({ message: 'Login realizado com sucesso!' });


    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Logout
app.post('/api/logout', async (req, res) => {
    console.log("LOGOUT - Session ID:", req.sessionID); // LOG
    console.log("LOGOUT - Headers:", req.headers);     // LOG

    if (req.session.userId) {
        // ### REMOVIDO TEMPORARIAMENTE A EXCLUSÃO DA SESSÃO DO BANCO ###
        req.session.destroy(err => {
            if (err) {
                console.error('Erro ao destruir sessão:', err);
                return res.status(500).json({ error: 'Erro ao fazer logout.' });
            }
            res.json({ message: 'Logout realizado com sucesso!' });
        });
    } else {
        res.status(401).json({ error: 'Não autenticado.' });
    }
});


 // Obter Perfil do Usuário Logado
 app.get('/api/perfil', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;

        const [profiles] = await connection.execute(
            'SELECT * FROM perfis WHERE usuario_id = ?', [userId]
        );
        if (profiles.length === 0) {
            return res.status(404).json({ error: 'Perfil não encontrado.' });
        }
        const profile = profiles[0];
        res.json(profile);

    } catch (error) {
        console.error('Erro ao obter perfil:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

//Atualizar Perfil
app.put('/api/perfil', requireAuth, async(req, res) =>{
    try {
        const userId = req.session.userId;
        const { nome_completo, cpf_cnpj, endereco, numero, complemento, bairro, cidade, estado, cep, telefone, telefone_empresa, whatsapp, mostrar_dados_orcamento } = req.body;
         // Validações (coloquei algumas básicas, adicione mais)
        if (!nome_completo) {
          return res.status(400).json({ error: 'O nome completo é obrigatório.' });
        }

        const [result] = await connection.execute(`
            UPDATE perfis
            SET nome_completo = ?, cpf_cnpj = ?, endereco = ?, numero = ?, complemento = ?,
            bairro = ?, cidade = ?, estado = ?, cep = ?, telefone = ?, telefone_empresa = ?,
            whatsapp = ?, mostrar_dados_orcamento = ?
            WHERE usuario_id = ?`,
            [nome_completo, cpf_cnpj, endereco, numero, complemento, bairro, cidade, estado, cep, telefone, telefone_empresa, whatsapp, mostrar_dados_orcamento, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Perfil não encontrado ou dados não alterados.' });
        }

        res.json({ message: 'Perfil atualizado com sucesso!' });

    } catch (error) {
        console.error('Erro ao atualizar perfil:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }

});

// --- Rotas para Orçamentos ---

// Criar Orçamento (requer autenticação)
app.post('/api/orcamentos', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId; // Pega o ID do usuário da sessão

        // Desestruturação completa dos campos do orçamento
        const {
            grau_esferico_od, grau_esferico_oe, grau_cilindrico_od, grau_cilindrico_oe,
            eixo_od, eixo_oe, dnp_od, dnp_oe, adicao, tipo_lente, material_lente,
            tratamento_lente, observacoes, valor_lente, valor_armacao, nome_cliente, cpf_cliente
        } = req.body;

        // Validações (adicione validações para os campos do orçamento, exemplo abaixo)
        if (!grau_esferico_od || !grau_esferico_oe) {
            return res.status(400).json({ error: 'Graus esféricos são obrigatórios.' });
        }
        // ... adicione outras validações ...

        // Inserir o orçamento no banco de dados, associando-o ao usuário logado
        const [result] = await connection.execute(
            'INSERT INTO orcamentos (usuario_id, grau_esferico_od, grau_esferico_oe, grau_cilindrico_od, grau_cilindrico_oe, eixo_od, eixo_oe, dnp_od, dnp_oe, adicao, tipo_lente, material_lente, tratamento_lente, observacoes, valor_lente, valor_armacao, nome_cliente, cpf_cliente) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, grau_esferico_od, grau_esferico_oe, grau_cilindrico_od, grau_cilindrico_oe, eixo_od, eixo_oe, dnp_od, dnp_oe, adicao, tipo_lente, material_lente, tratamento_lente, observacoes, valor_lente, valor_armacao, nome_cliente, cpf_cliente]
        );

        const orcamentoId = result.insertId;

        res.status(201).json({ message: 'Orçamento criado com sucesso!', orcamentoId });

    } catch (error) {
        console.error('Erro ao criar orçamento:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Listar Orçamentos do Usuário Logado (requer autenticação)
app.get('/api/orcamentos', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;

        const [orcamentos] = await connection.execute(
            'SELECT * FROM orcamentos WHERE usuario_id = ?',
            [userId]
        );

        res.json(orcamentos);

    } catch (error) {
        console.error('Erro ao listar orçamentos:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Obter um Orçamento Específico (requer autenticação)
app.get('/api/orcamentos/:id', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const orcamentoId = req.params.id;

        const [orcamentos] = await connection.execute(
            'SELECT * FROM orcamentos WHERE id = ? AND usuario_id = ?',
            [orcamentoId, userId]
        );

        if (orcamentos.length === 0) {
            return res.status(404).json({ error: 'Orçamento não encontrado ou não pertence ao usuário.' });
        }

        res.json(orcamentos[0]);

    } catch (error) {
        console.error('Erro ao obter orçamento:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Atualizar um Orçamento (requer autenticação)
app.put('/api/orcamentos/:id', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const orcamentoId = req.params.id;

        // Desestruturação completa dos campos do orçamento
        const {
            grau_esferico_od, grau_esferico_oe, grau_cilindrico_od, grau_cilindrico_oe,
            eixo_od, eixo_oe, dnp_od, dnp_oe, adicao, tipo_lente, material_lente,
            tratamento_lente, observacoes, valor_lente, valor_armacao, nome_cliente, cpf_cliente
        } = req.body;

        // Validações (mesmas da criação)

        const [result] = await connection.execute(`
            UPDATE orcamentos
            SET grau_esferico_od = ?, grau_esferico_oe = ?, grau_cilindrico_od = ?, grau_cilindrico_oe = ?,
            eixo_od = ?, eixo_oe = ?, dnp_od = ?, dnp_oe = ?, adicao = ?, tipo_lente = ?, material_lente = ?,
            tratamento_lente = ?, observacoes = ?, valor_lente = ?, valor_armacao = ?, nome_cliente = ?, cpf_cliente = ?
            WHERE id = ? AND usuario_id = ?`,
            [grau_esferico_od, grau_esferico_oe, grau_cilindrico_od, grau_cilindrico_oe, eixo_od, eixo_oe, dnp_od, dnp_oe, adicao, tipo_lente, material_lente, tratamento_lente, observacoes, valor_lente, valor_armacao, nome_cliente, cpf_cliente, orcamentoId, userId]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Orçamento não encontrado ou não pertence ao usuário.' });
        }

        res.json({ message: 'Orçamento atualizado com sucesso!' });

    } catch (error) {
        console.error('Erro ao atualizar orçamento:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Excluir um Orçamento (requer autenticação)
app.delete('/api/orcamentos/:id', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const orcamentoId = req.params.id;

        const [result] = await connection.execute(
            'DELETE FROM orcamentos WHERE id = ? AND usuario_id = ?',
            [orcamentoId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Orçamento não encontrado ou não pertence ao usuário.' });
        }

        res.json({ message: 'Orçamento excluído com sucesso!' });

    } catch (error) {
        console.error('Erro ao excluir orçamento:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});
// Inicia o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});