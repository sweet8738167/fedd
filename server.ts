import dotenv from "dotenv";
dotenv.config();

import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { GoogleGenAI } from "@google/genai";
import { createServer as createViteServer } from "vite";
import webpush from "web-push";

interface PushSubscriptionItem {
  userId: string;
  subscription: any;
}

// Interfaces base para o banco de dados interno
interface UserProfile {
  id: string;
  username: string; // único
  fullName: string;
  email: string;
  avatarUrl: string;
  bio: string;
  age: number;
  gender: string;
  location: string;
  interests: string[];
  createdAt: string;
  passwordHash: string;
  passwordSalt: string;
  isBot?: boolean;
  relationshipGoal?: string;
  zodiacSign?: string;
  occupation?: string;
}

interface Message {
  id: string;
  senderId: string;
  recipientId: string;
  content: string;
  timestamp: string;
  read: boolean;
}

interface DBStructure {
  users: UserProfile[];
  messages: Message[];
  pushSubscriptions?: PushSubscriptionItem[];
}

const DB_PATH = path.resolve(process.cwd(), "db.json");

// Inicialização segura do banco de dados em arquivo JSON
function initDB(): DBStructure {
  if (!fs.existsSync(DB_PATH)) {
    const initialData: DBStructure = {
      users: [],
      messages: [],
      pushSubscriptions: [],
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(initialData, null, 2), "utf8");
    return initialData;
  }

  try {
    const raw = fs.readFileSync(DB_PATH, "utf8");
    const parsed = JSON.parse(raw) as DBStructure;
    
    // Purga imediata de qualquer usuário simulador (bots/fakes) do banco de dados
    const originalUserCount = (parsed.users || []).length;
    const originalMessageCount = (parsed.messages || []).length;

    parsed.users = (parsed.users || []).filter(
      (u) => !u.isBot && !u.id.startsWith("user_")
    );

    // Mapeamento dos IDs de usuários reais restantes
    const realUserIds = new Set(parsed.users.map((u) => u.id));

    // Filtragem de mensagens para garantir que os chats permaneçam estritamente privados e apenas entre usuários reais remanescentes
    parsed.messages = (parsed.messages || []).filter(
      (m) => realUserIds.has(m.senderId) && realUserIds.has(m.recipientId)
    );

    // Persiste a limpeza no disco se houver mudança
    if (parsed.users.length !== originalUserCount || parsed.messages.length !== originalMessageCount) {
      fs.writeFileSync(DB_PATH, JSON.stringify(parsed, null, 2), "utf8");
      console.log(`[Database Cleanup] Purga realizada com sucesso. Removidos ${originalUserCount - parsed.users.length} usuários simulados e ${originalMessageCount - parsed.messages.length} mensagens associadas.`);
    }

    if (!parsed.pushSubscriptions) {
      parsed.pushSubscriptions = [];
    }

    return parsed;
  } catch (err) {
    console.error("Erro ao ler banco de dados. Recriando estrutura...", err);
    const initialData: DBStructure = {
      users: [],
      messages: [],
      pushSubscriptions: [],
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(initialData, null, 2), "utf8");
    return initialData;
  }
}

// Carregar o DB na memória para acesso rápido e persistir em disco nas mutações
let db = initDB();
if (!db.pushSubscriptions) {
  db.pushSubscriptions = [];
}

function saveDB() {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
  } catch (err) {
    console.error("Erro ao salvar o banco de dados:", err);
  }
}

// --- CONFIGURAÇÃO DO WEB PUSH PARA NOTIFICAÇÕES ---
let vapidKeys = {
  publicKey: "",
  privateKey: ""
};

const VAPID_KEYS_FILE = path.resolve(process.cwd(), ".vapid.json");
if (fs.existsSync(VAPID_KEYS_FILE)) {
  try {
    vapidKeys = JSON.parse(fs.readFileSync(VAPID_KEYS_FILE, "utf8"));
  } catch (err) {
    console.error("Erro ao ler arquivo .vapid.json, gerando novas chaves de autenticação...", err);
  }
}

if (!vapidKeys.publicKey || !vapidKeys.privateKey) {
  vapidKeys = webpush.generateVAPIDKeys();
  try {
    fs.writeFileSync(VAPID_KEYS_FILE, JSON.stringify(vapidKeys, null, 2), "utf8");
    console.log("[Push Notification] Novas chaves VAPID geradas e salvas com sucesso!");
  } catch (err) {
    console.error("Falha ao salvar as chaves de notificação no disco:", err);
  }
}

webpush.setVapidDetails(
  "mailto:renildorafael059@gmail.com",
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

// Função auxiliar para disparar as notificações web push
async function sendPushNotification(recipientId: string, payload: { title: string; body: string; icon?: string; url?: string }) {
  const subscriptions = db.pushSubscriptions || [];
  const userSubs = subscriptions.filter(sub => sub && sub.userId === recipientId);
  if (userSubs.length === 0) return;

  const payloadString = JSON.stringify(payload);

  const sendPromises = userSubs.map(async (userSub) => {
    try {
      await webpush.sendNotification(userSub.subscription, payloadString);
    } catch (err: any) {
      if (err.statusCode === 410 || err.statusCode === 404) {
        console.log(`[Push Notification] Inscrição expirada detectada. Removendo inscrição do usuário: ${recipientId}`);
        db.pushSubscriptions = (db.pushSubscriptions || []).filter(s => s && s.subscription !== userSub.subscription);
        saveDB();
      } else {
        console.error(`[Push Notification] Erro ao enviar notificação push:`, err.message);
      }
    }
  });

  await Promise.allSettled(sendPromises);
}

// Funções utilitárias de Criptografia seguras sem dependências externas adicionais
function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
}

function generateSalt(): string {
  return crypto.randomBytes(16).toString("hex");
}

function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

// Armazenamento em memória das sessões ativas (Sessões expiram ao reiniciar o app, o que dá total fluidez ao preview)
const activeSessions = new Map<string, { userId: string; username: string }>();

// Inicialização opcional da API Gemini
let aiClient: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  try {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
    console.log("Cliente Gemini configurado com sucesso para respostas dos perfis simulados!");
  } catch (err) {
    console.error("Erro ao configurar cliente Gemini:", err);
  }
} else {
  console.log("GEMINI_API_KEY não configurado. Os perfis usarão respostas automáticas pré-programadas.");
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Middleware logging para acompanhar as chamadas da API de perto
  app.use((req, res, next) => {
    console.log(`[HTTP REQUEST] ${req.method} ${req.url}`);
    next();
  });

  // Middleware para autenticação via Header Authorization Bearer <token>
  function authenticateToken(req: any, res: any, next: () => void) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Token de acesso não fornecido ou inválido." });
    }

    const session = activeSessions.get(token);
    if (!session) {
      return res.status(403).json({ error: "Sessão expirada ou inválida." });
    }

    const user = db.users.find((u) => u.id === session.userId);
    if (!user) {
      return res.status(404).json({ error: "Usuário não encontrado." });
    }

    req.userId = session.userId;
    req.username = session.username;
    req.user = user;
    next();
  }

  // --- ENDPOINTS DE AUTENTICAÇÃO ---

  // Registro de nova conta
  app.post("/api/auth/register", (req, res) => {
    const { username, fullName, email, password, avatarUrl, bio, age, gender, location, interests } = req.body;

    if (!username || !fullName || !email || !password) {
      return res.status(400).json({ error: "Campos obrigatórios ausentes: nome de usuário, nome completo, email e senha." });
    }

    // Regras básicas de validação de nome de usuário (lowercase, sem espaços, min 3 letras)
    const normalizedUsername = username.toLowerCase().trim().replace(/\s+/g, "_");
    if (normalizedUsername.length < 3) {
      return res.status(400).json({ error: "O nome de usuário deve conter no mínimo 3 caracteres." });
    }

    // Validação de e-mail básica
    if (!email.includes("@")) {
      return res.status(400).json({ error: "Formato de e-mail inválido." });
    }

    // Validação de senha
    if (password.length < 6) {
      return res.status(400).json({ error: "A senha deve conter no mínimo 6 caracteres por segurança." });
    }

    // Verifica unicidade
    const usernameExists = db.users.some((u) => u.username.toLowerCase() === normalizedUsername);
    if (usernameExists) {
      return res.status(400).json({ error: "Nome de usuário já cadastrado. Escolha outro." });
    }

    const emailExists = db.users.some((u) => u.email.toLowerCase() === email.toLowerCase());
    if (emailExists) {
      return res.status(400).json({ error: "Este email já está em uso por outra conta." });
    }

    // Criptografa senha
    const salt = generateSalt();
    const hash = hashPassword(password, salt);

    // Salva o novo usuário
    const defaultAvatarUrl = avatarUrl || `https://images.unsplash.com/photo-${gender === "Feminino" ? "1544005313-94ddf0286df2" : "1506794778202-cad84cf45f1d"}?w=400&auto=format&fit=crop&q=80`;

    const newUser: UserProfile = {
      id: crypto.randomUUID(),
      username: normalizedUsername,
      fullName: fullName.trim(),
      email: email.toLowerCase().trim(),
      avatarUrl: defaultAvatarUrl,
      bio: (bio || "Nova conta no Encontro Simples!").trim(),
      age: Number(age) || 18,
      gender: gender || "Prefiro não dizer",
      location: (location || "Não especificado").trim(),
      interests: Array.isArray(interests) ? interests : [],
      createdAt: new Date().toISOString(),
      passwordHash: hash,
      passwordSalt: salt,
      relationshipGoal: req.body.relationshipGoal || "",
      zodiacSign: req.body.zodiacSign || "",
      occupation: req.body.occupation || "",
    };

    db.users.push(newUser);
    saveDB();

    // Cria sessão ativa imediata para facilitar a vida do usuário
    const token = generateToken();
    activeSessions.set(token, { userId: newUser.id, username: newUser.username });

    // Remove campos sensíveis antes de enviar resposta
    const { passwordHash, passwordSalt, ...safeUser } = newUser;

    res.status(201).json({
      message: "Conta criada com sucesso!",
      user: safeUser,
      token,
    });
  });

  // Login
  app.post("/api/auth/login", (req, res) => {
    const { usernameOrEmail, password } = req.body;

    if (!usernameOrEmail || !password) {
      return res.status(400).json({ error: "Por favor, insira o nome de usuário/email e a senha." });
    }

    // Busca usuário pelo username ou email
    const term = usernameOrEmail.toLowerCase().trim();
    const user = db.users.find(
      (u) => !u.isBot && (u.username.toLowerCase() === term || u.email.toLowerCase() === term)
    );

    if (!user) {
      return res.status(401).json({ error: "Credenciais incorretas ou conta inexistente." });
    }

    // Verifica a senha com o Salt do usuário
    const recalculatedHash = hashPassword(password, user.passwordSalt);
    if (recalculatedHash !== user.passwordHash) {
      return res.status(401).json({ error: "Senha incorreta. Verifique suas credenciais." });
    }

    // Gera token de sessão
    const token = generateToken();
    activeSessions.set(token, { userId: user.id, username: user.username });

    const { passwordHash, passwordSalt, ...safeUser } = user;

    res.json({
      message: "Login efetuado com sucesso!",
      user: safeUser,
      token,
    });
  });

  // Logout
  app.post("/api/auth/logout", authenticateToken, (req: any, res) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    
    if (token) {
      activeSessions.delete(token);
    }
    
    res.json({ success: true, message: "Sessão encerrada com sucesso." });
  });

  // Retorna dados do usuário autenticado atual
  app.get("/api/auth/me", authenticateToken, (req: any, res) => {
    const { passwordHash, passwordSalt, ...safeUser } = req.user;
    res.json(safeUser);
  });


  // --- ENDPOINTS DE USUÁRIOS E PERFIL ---

  // Obter todos os usuários (exceto o logado atual), suporta busca por nome de usuário, localização e filtros avançados
  app.get("/api/users", authenticateToken, (req: any, res) => {
    const currentUserId = req.userId;
    const { search, gender, interest, minAge, maxAge, relationshipGoal, zodiacSign, city } = req.query;

    let filtered = db.users.filter((user) => user.id !== currentUserId);

    // Filtro por termo de pesquisa (Username, Nome Completo ou Cidade)
    if (search) {
      const query = String(search).toLowerCase().trim();
      filtered = filtered.filter(
        (u) =>
          u.username.toLowerCase().includes(query) ||
          u.fullName.toLowerCase().includes(query) ||
          u.location.toLowerCase().includes(query) ||
          u.bio.toLowerCase().includes(query)
      );
    }

    // Filtro por gênero
    if (gender && gender !== "Todos") {
      filtered = filtered.filter((u) => u.gender === gender);
    }

    // Filtro por interesses
    if (interest && interest !== "") {
      const qInterest = String(interest).toLowerCase().trim();
      filtered = filtered.filter((u) =>
        u.interests.some((i) => i.toLowerCase().includes(qInterest))
      );
    }

    // Filtro por idade mínima
    if (minAge) {
      const minVal = Number(minAge);
      if (!isNaN(minVal)) {
        filtered = filtered.filter((u) => u.age >= minVal);
      }
    }

    // Filtro por idade máxima
    if (maxAge) {
      const maxVal = Number(maxAge);
      if (!isNaN(maxVal)) {
        filtered = filtered.filter((u) => u.age <= maxVal);
      }
    }

    // Filtro por objetivo de relacionamento
    if (relationshipGoal && relationshipGoal !== "Todos") {
      filtered = filtered.filter((u) => u.relationshipGoal === relationshipGoal);
    }

    // Filtro por signo do zodíaco
    if (zodiacSign && zodiacSign !== "Todos") {
      filtered = filtered.filter((u) => u.zodiacSign === zodiacSign);
    }

    // Filtro por cidade específica
    if (city) {
      const qCity = String(city).toLowerCase().trim();
      filtered = filtered.filter((u) => u.location.toLowerCase().includes(qCity));
    }

    // Remove dados sensíveis
    const safeUsers = filtered.map(({ passwordHash, passwordSalt, email, ...rest }) => rest);

    res.json(safeUsers);
  });

  // Obter perfil detalhado de um usuário pelo ID ou username
  app.get("/api/users/:identifier", authenticateToken, (req: any, res) => {
    const identifier = req.params.identifier;

    // Busca por ID ou Username
    const userProfile = db.users.find(
      (u) => u.id === identifier || u.username.toLowerCase() === identifier.toLowerCase()
    );

    if (!userProfile) {
      return res.status(404).json({ error: "Perfil de usuário não encontrado." });
    }

    const { passwordHash, passwordSalt, ...safeProfile } = userProfile;
    // Permite que outros vejam apenas informações não sensíveis, ou todas se for o próprio usuário
    if (userProfile.id !== req.userId) {
      delete (safeProfile as any).email;
    }

    res.json(safeProfile);
  });

  // Atualizar perfil atual
  app.put("/api/users/profile", authenticateToken, (req: any, res) => {
    const { fullName, bio, age, gender, location, interests, avatarUrl, relationshipGoal, zodiacSign, occupation } = req.body;
    const userIndex = db.users.findIndex((u) => u.id === req.userId);

    if (userIndex === -1) {
      return res.status(404).json({ error: "Usuário desconhecido." });
    }

    const userProfile = db.users[userIndex];

    if (fullName !== undefined) userProfile.fullName = fullName.trim() || userProfile.fullName;
    if (bio !== undefined) userProfile.bio = bio.trim();
    if (age !== undefined) userProfile.age = Number(age) || userProfile.age;
    if (gender !== undefined) userProfile.gender = gender || userProfile.gender;
    if (location !== undefined) userProfile.location = location.trim() || userProfile.location;
    if (interests !== undefined) userProfile.interests = Array.isArray(interests) ? interests : userProfile.interests;
    if (avatarUrl !== undefined) userProfile.avatarUrl = avatarUrl.trim() || userProfile.avatarUrl;
    if (relationshipGoal !== undefined) userProfile.relationshipGoal = relationshipGoal;
    if (zodiacSign !== undefined) userProfile.zodiacSign = zodiacSign;
    if (occupation !== undefined) userProfile.occupation = occupation;

    db.users[userIndex] = userProfile;
    saveDB();

    const { passwordHash, passwordSalt, ...safeProfile } = userProfile;
    res.json({
      message: "Perfil atualizado com sucesso!",
      user: safeProfile,
    });
  });


  // --- ENDPOINTS DO CHAT ---

  // Retorna todas as conversas iniciadas (últimas mensagens com cada pessoa, ideal para o Inbox)
  app.get("/api/chat/conversations", authenticateToken, (req: any, res) => {
    try {
      const currentUserId = req.userId;
      
      // Filtra mensagens em que o usuário atual participa
      const userMessages = (db.messages || []).filter(
        (m) => m && (m.senderId === currentUserId || m.recipientId === currentUserId)
      );

      // Mapeia o outro ID participante de cada mensagem
      const participantIds = new Set<string>();
      userMessages.forEach((m) => {
        if (m) {
          if (m.senderId !== currentUserId) participantIds.add(m.senderId);
          if (m.recipientId !== currentUserId) participantIds.add(m.recipientId);
        }
      });

      const conversations = Array.from(participantIds).map((partnerId) => {
        const partner = (db.users || []).find((u) => u && u.id === partnerId);
        if (!partner) return null;

        // Pegar todas as mensagens entre os dois
        const chatHistory = userMessages.filter(
          (m) =>
            m && ((m.senderId === currentUserId && m.recipientId === partnerId) ||
            (m.senderId === partnerId && m.recipientId === currentUserId))
        );

        // Ordenar por data descending para pegar a última
        chatHistory.sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime());
        const lastMessage = chatHistory[0];

        // Calcular mensagens não lidas recebidas do parceiro
        const unreadCount = chatHistory.filter((m) => m && m.senderId === partnerId && !m.read).length;

        return {
          id: partner.id,
          username: partner.username,
          fullName: partner.fullName,
          avatarUrl: partner.avatarUrl,
          lastMessage: lastMessage ? lastMessage.content : "",
          lastMessageTime: lastMessage ? lastMessage.timestamp : (partner.createdAt || new Date().toISOString()),
          unreadCount,
        };
      }).filter(Boolean);

      // Ordenar conversas pela data da última mensagem (as mais recentes primeiro)
      conversations.sort((a: any, b: any) => {
        const timeA = new Date(a.lastMessageTime || 0).getTime();
        const timeB = new Date(b.lastMessageTime || 0).getTime();
        return timeB - timeA;
      });

      res.json(conversations);
    } catch (err: any) {
      console.error("Erro interno ao carregar conversas:", err);
      res.status(500).json({ error: "Erro interno ao carregar conversas: " + err.message });
    }
  });

  // Obter histórico de mensagens de uma conversa específica com marquagem de lidas
  app.get("/api/chat/messages", authenticateToken, (req: any, res) => {
    try {
      const currentUserId = req.userId;
      const { recipientId } = req.query;

      if (!recipientId) {
        return res.status(400).json({ error: "recipientId é necessário como query param." });
      }

      const chatHistory = (db.messages || []).filter(
        (m) =>
          m && ((m.senderId === currentUserId && m.recipientId === recipientId) ||
          (m.senderId === recipientId && m.recipientId === currentUserId))
      );

      // Ordenar por data ascendente para renderizar na linha do tempo do chat
      chatHistory.sort((a, b) => new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime());

      // Marcar mensagens recebidas como lidas
      let mutated = false;
      (db.messages || []).forEach((m) => {
        if (m && m.senderId === recipientId && m.recipientId === currentUserId && !m.read) {
          m.read = true;
          mutated = true;
        }
      });

      if (mutated) {
        saveDB();
      }

      res.json(chatHistory);
    } catch (err: any) {
      console.error("Erro interno ao carregar mensagens:", err);
      res.status(500).json({ error: "Erro interno ao obter mensagens: " + err.message });
    }
  });

  // Enviar nova mensagem para um usuário
  app.post("/api/chat/messages", authenticateToken, async (req: any, res) => {
    try {
      const currentUserId = req.userId;
      const { recipientId, content } = req.body;

      if (!recipientId || !content || !content.trim()) {
        return res.status(400).json({ error: "ID do destinatário e conteúdo da mensagem são necessários." });
      }

      // Verifica se destinatário existe
      const recipient = (db.users || []).find((u) => u && u.id === recipientId);
      if (!recipient) {
        return res.status(404).json({ error: "Usuário de destino não encontrado no banco de dados." });
      }

      // Cria mensagem
      const newMessage: Message = {
        id: crypto.randomUUID(),
        senderId: currentUserId,
        recipientId,
        content: content.trim(),
        timestamp: new Date().toISOString(),
        read: false,
      };

      db.messages = db.messages || [];
      db.messages.push(newMessage);
      saveDB();

      // Envia notificação push para o destinatário caso não seja um bot
      if (!recipient.isBot) {
        sendPushNotification(recipientId, {
          title: `Nova mensagem de ${req.user.fullName}`,
          body: content.trim(),
          icon: req.user.avatarUrl || '/favicon.ico',
          url: '/'
        }).catch((err) => console.error("Erro ao enviar notificação push:", err));
      }

      res.status(201).json(newMessage);

    // --- LOGICA DE RESPOSTA SIMULADA DE BOT INTEGRADA AO GEMINI ---
    if (recipient.isBot) {
      const botId = recipient.id;
      // Resposta automática de bot em background após 1.2 segundos para simular digitação e envio natural
      setTimeout(async () => {
        try {
          // Busca o histórico recente para dar contexto à conversa do bot no Gemini
          const recentHistory = db.messages.filter(
            (m) =>
              (m.senderId === currentUserId && m.recipientId === botId) ||
              (m.senderId === botId && m.recipientId === currentUserId)
          );
          recentHistory.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
          
          // Mantém as últimas 10 mensagens para não estourar o contexto e manter rápido
          const contextHistory = recentHistory.slice(-10);

          let replyText = "";

          if (aiClient) {
            // Constrói prompts em português detalhando a persona da simulação
            const systemInstruction = `Você é ${recipient.fullName} (@${recipient.username}), participante real de um web app de relacionamentos minimalista chamado "Encontro Simples".
Aqui estão seus dados reais de perfil que você deve adotar:
Nome: ${recipient.fullName}
Idade: ${recipient.age} anos
Localização: ${recipient.location}
Bio: ${recipient.bio}
Interesses: ${recipient.interests.join(", ")}

DIRETRIZES DE COMPORTAMENTO:
- Fale português brasileiro natural, caloroso, descontraído e amigável.
- Responda como se estivesse batendo um papo real em um aplicativo de encontros pelo celular (tipo Tinder ou WhatsApp).
- Dê respostas curtas, fluidas e simples (máximo de 1 a 3 frases curtas). Evite enrolações e textos gigantescos.
- Mostre interesse na pessoa: faça perguntas sobre ela, encontre pontos em comum (compare os interesses se aplicável), puxe assunto, seja carismático e flerte sutilmente se for correspondido.
- NUNCA mencione que você é um robô, IA, IA de suporte, assistente virtual ou modelo de linguagem da Google. Você é a pessoa real do avatar ${recipient.fullName}!
- Escreva como humano: use letras minúsculas casuais, emojis de forma moderada e natural (ex: 😊, haha, rs rs, 😉), e exclamações. Não fique repetindo explicações técnicas.`;

            // Formata a transcrição histórica para o modelo compreender os turnos
            const transcriptionParts = contextHistory.map((m) => {
              const speaker = m.senderId === currentUserId ? "Parceiro de Conversa" : `${recipient.fullName} (Você)`;
              return `${speaker}: ${m.content}`;
            }).join("\n");

            const prompt = `Histórico recente do chat:\n${transcriptionParts}\n\nResponda agora ao parceiro como ${recipient.fullName} continuando a conversa de maneira natural.`;

            try {
              const response = await aiClient.models.generateContent({
                model: "gemini-3.5-flash",
                contents: prompt,
                config: {
                  systemInstruction,
                  temperature: 0.8,
                  topP: 0.9,
                },
              });

              if (response && response.text) {
                replyText = response.text.trim();
              }
            } catch (apiErr) {
              console.error("Erro na API Gemini para automação de chat. Usando fallback tradicional.", apiErr);
            }
          }

          // Fallback robusto se a API Key do Gemini não estiver configurada ou falhar
          if (!replyText) {
            const fallbacks: { [key: string]: string[] } = {
              user_mariana: [
                "Oi! Desculpa a demora, estava tomando meu cafezinho! ☕ O que você curte fazer no fim de semana?",
                "Sim! Eu amo fazer trilhas e ir à praia. Você já conhece o Rio de Janeiro?",
                "Haha que legal! É muito bom trocar essa ideia leve. E sobre música, que tipo de banda você gosta de escutar? 🎧",
                "Que massa! Eu topo super um passeio ao ar livre algum dia. O que me diz?",
                "Olá! 😊 Fiquei muito feliz em ver seu oi! Me conta um pouquinho sobre você.",
              ],
              user_lucas: [
                "Fala rapaz! Beleza? Estava aqui na cozinha inventando uma receita nova... rs rs. E você, curte cozinhar?",
                "São Paulo tem sempre um restaurante bom ou museu novo para ir, né? Qual é o seu rolê preferido na cidade?",
                "Legal demais! Se tiver dicas de viagem ou corrida pode mandar, sempre busco novos desafios! 🏃‍♂️",
                "Com certeza! Um dia a gente combina de comer alguma coisa legal ou fazer um treino de corrida casual.",
                "Opa! Prazer te conhecer! O que te traz por aqui na plataforma de encontros?",
              ],
              user_beatriz: [
                "Oi! Tudo certinho? Estava aqui com meus gatinhos lendo um livro novo 📚🐈. Me conta, você é mais de ler ou ver séries?",
                "Nossa, que legal! Eu adoro ir a feiras de arte aos sábados nos bairros de BH. Onde você mora?",
                "Ficção científica é o melhor gênero do universo, fala sério! Haha 🚀 Você já assistiu Interestelar?",
                "Ah que fofo! Quem sabe em breve a gente não se encontra e toma um sorvete?",
                "Olá! Muito legal seu perfil, curti seu estilo!",
              ],
              user_gabriel: [
                "E aí cara, tudo bom? 🌊 Estava limpando a prancha de surfe pra amanhã cedo. Você curte praia ou é mais do frio?",
                "Nossa, sou viciado em boardgames! Curte jogar coisas tipo Catan, Carcassonne ou até um War? Haha",
                "Sim, totalmente! Gosto de trocar playlists e escutar música nova trabalhando. Que som você tá ouvindo ultimamente?",
                "Com certeza! Vamos marcar de conversar ou fazer algo bacana um dia destes. Bora?",
                "E aí! Prazer conhecer você por aqui. O que curte fazer de bom?",
              ],
            };

            const options = fallbacks[botId] || [
              "Oi! Achei muito legal seu perfil. Vamos nos conhecer melhor? 😊",
              "Que bacana podermos conversar! Como está seu dia?",
              "Gostei do papo! O que você mais procura em alguém?",
            ];
            replyText = options[Math.floor(Math.random() * options.length)];
          }

          // Salva mensagem no histórico do bot respondendo de volta
          const botMessage: Message = {
            id: crypto.randomUUID(),
            senderId: botId,
            recipientId: currentUserId,
            content: replyText,
            timestamp: new Date().toISOString(),
            read: false,
          };

          db.messages.push(botMessage);
          saveDB();
        } catch (botErr) {
          console.error("Erro grave ao processar automação do bot:", botErr);
        }
      }, 1500);
    }
    } catch (err: any) {
      console.error("Erro ao enviar mensagem:", err);
      res.status(500).json({ error: "Erro interno ao enviar mensagem: " + err.message });
    }
  });


  // --- ENDPOINTS PARA NOTIFICAÇÕES PUSH ---

  // Retorna a chave pública do VAPID para registro do Service Worker
  app.get("/api/notifications/vapid-public-key", (req, res) => {
    res.json({ publicKey: vapidKeys.publicKey });
  });

  // Salva ou atualiza a inscrição (subscription) do navegador para o usuário logado
  app.post("/api/notifications/subscribe", authenticateToken, (req: any, res) => {
    try {
      const currentUserId = req.userId;
      const subscription = req.body;

      if (!subscription || !subscription.endpoint) {
        return res.status(400).json({ error: "Assinatura de push inválida." });
      }

      // Evita duplicações limpando subscrições antigas iguais de qualquer usuário
      db.pushSubscriptions = (db.pushSubscriptions || []).filter(
        (sub) => sub && sub.subscription?.endpoint !== subscription.endpoint
      );

      // Salva a nova subscrição relacionada ao userId corrente
      db.pushSubscriptions.push({
        userId: currentUserId,
        subscription,
      });

      saveDB();
      console.log(`[Push Notification] Inscrição de push registrada com sucesso para o usuário ${currentUserId}`);
      res.status(201).json({ status: "success", message: "Inscrição registrada." });
    } catch (err: any) {
      console.error("Erro ao registrar subscrição push:", err);
      res.status(500).json({ error: "Erro interno no servidor: " + err.message });
    }
  });

  // Dispara uma notificação push de teste para o próprio usuário ativo
  app.post("/api/notifications/test-push", authenticateToken, async (req: any, res) => {
    try {
      const currentUserId = req.userId;
      console.log(`[Push Notification] Enviando disparo de teste para o usuário ${currentUserId}`);

      await sendPushNotification(currentUserId, {
        title: "Teste de Notificação Push!",
        body: `Olá ${req.user.fullName}, seu sistema de notificações push está ativo e rodando perfeitamente. Criador por Lil Sweet & Renildo Rafael!`,
        icon: req.user.avatarUrl || 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=100&h=100&fit=crop',
        url: '/'
      });

      res.json({ status: "success", message: "Disparo de teste de notificação enviado para todos os seus navegadores cadastrados." });
    } catch (err: any) {
      console.error("Erro no teste de push:", err);
      res.status(500).json({ error: "Erro ao disparar push de teste: " + err.message });
    }
  });

  // Servir o Service Worker dinamicamente com tipo MIME Javascript correto
  app.get("/sw.js", (req, res) => {
    res.setHeader("Content-Type", "application/javascript; charset=utf-8");
    res.send(`
      self.addEventListener('push', (event) => {
        let data = { title: 'VibeCheck', body: 'Você tem uma nova notificação!' };
        try {
          if (event.data) {
            data = event.data.json();
          }
        } catch (err) {
          if (event.data) {
            data = { title: 'Nova Mensagem', body: event.data.text() };
          }
        }
        
        const options = {
          body: data.body,
          icon: data.icon || 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=100&h=100&fit=crop',
          badge: data.icon || 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=100&h=100&fit=crop',
          tag: 'vibecheck-message',
          renotify: true,
          data: {
            url: data.url || '/'
          },
          vibrate: [200, 100, 200],
        };
        
        event.waitUntil(
          self.registration.showNotification(data.title, options)
        );
      });

      self.addEventListener('notificationclick', (event) => {
        event.notification.close();
        event.waitUntil(
          clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
              if (client.url && 'focus' in client) {
                return client.focus();
              }
            }
            if (clients.openWindow) {
              return clients.openWindow('/');
            }
          })
        );
      });
    `);
  });


  // --- TRATAMENTO DE ERROS GLOBAL DA API ---
  app.use("/api", (err: any, req: any, res: any, next: any) => {
    console.error("[SERVER API ERROR]", err);
    res.status(500).json({ error: "Erro na API do servidor: " + err.message });
  });


  // --- INICIAR SERVIDOR ---

  // Integração com Vite Helper Middleware
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Encontro Simples] Servidor rodando em http://localhost:${PORT}`);
  });
}

startServer();
