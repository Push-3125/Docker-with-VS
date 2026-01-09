const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});

app.use(limiter);
app.use(cors());
app.use(express.json());

// Environment variables
const MONGO_URI = process.env.MONGO_URI || "mongodb://mongodb:27017/todolist";
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";
const PORT = process.env.PORT || 3000;

// MongoDB connection
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

// Todo Schema (Updated)
const todoSchema = new mongoose.Schema({
  text: { type: String, required: true },
  completed: { type: Boolean, default: false },
  category: {
    type: String,
    enum: ["work", "personal", "urgent", "shopping"],
    default: "personal",
  },
  deadline: { type: Date, default: null },
  order: { type: Number, default: 0 },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Todo = mongoose.model("Todo", todoSchema);

// Middleware: Verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
}

// ==================== AUTH ROUTES ====================

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get current user
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== TODO ROUTES ====================

// Get all todos for user
app.get("/api/todos", authenticateToken, async (req, res) => {
  try {
    const todos = await Todo.find({ userId: req.user.userId }).sort({
      order: 1,
      createdAt: -1,
    });
    res.json(todos);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create todo
app.post("/api/todos", authenticateToken, async (req, res) => {
  try {
    const { text, category, deadline } = req.body;

    const todo = new Todo({
      text,
      category: category || "personal",
      deadline: deadline || null,
      userId: req.user.userId,
      completed: false,
    });

    await todo.save();
    res.status(201).json(todo);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Update todo
app.put("/api/todos/:id", authenticateToken, async (req, res) => {
  try {
    const { text, completed, category, deadline } = req.body;

    const todo = await Todo.findOne({
      _id: req.params.id,
      userId: req.user.userId,
    });

    if (!todo) {
      return res.status(404).json({ error: "Todo not found" });
    }

    if (text !== undefined) todo.text = text;
    if (completed !== undefined) todo.completed = completed;
    if (category !== undefined) todo.category = category;
    if (deadline !== undefined) todo.deadline = deadline;

    todo.updatedAt = Date.now();
    await todo.save();

    res.json(todo);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reorder todos
app.put("/api/todos/reorder", authenticateToken, async (req, res) => {
  try {
    const { order } = req.body;

    const bulkOps = order.map((item) => ({
      updateOne: {
        filter: { _id: item.id, userId: req.user.userId },
        update: { $set: { order: item.order } },
      },
    }));

    await Todo.bulkWrite(bulkOps);
    res.json({ message: "Order updated" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Delete todo
app.delete("/api/todos/:id", authenticateToken, async (req, res) => {
  try {
    const todo = await Todo.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId,
    });

    if (!todo) {
      return res.status(404).json({ error: "Todo not found" });
    }

    res.json({ message: "Todo deleted" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    database: mongoose.connection.readyState === 1,
    timestamp: new Date(),
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || "development"}`);
});
