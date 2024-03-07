const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("Connected to MongoDB");
    app.listen(process.env.API_PORT || 4001, () => {
      console.log(`Server running on port ${process.env.API_PORT || 4001}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

const User = mongoose.model('User', {
  username: String,
  password: String,
});

const Task = mongoose.model('Task', {
  user_id: mongoose.Schema.Types.ObjectId,
  task: String,
  isChecked: { type: Boolean, default: false },
});

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    return response.status(401).json({ error: "Invalid JWT Token" });
  }
  jwt.verify(jwtToken, process.env.JWT_SECRET, async (error, payload) => {
    if (error) {
      return response.status(401).json({ error: "Invalid JWT Token" });
    }
    request.username = payload.username;
    next();
  });
};

app.post("/register", async (request, response) => {
  const { username, password } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const existingUser = await User.findOne({ username: username });
    if (existingUser) {
      return response.status(400).json({ error: "Username already exists" });
    }

    await User.create({ username: username, password: hashedPassword });
    response.json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Registration Error:", error);
    response.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const dbUser = await User.findOne({ username: username });
  if (!dbUser) {
    return response.status(400).json({ error: "Invalid User" });
  }
  const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
  if (isPasswordMatched) {
    const payload = {
      username: username,
    };
    const jwtToken = jwt.sign(payload, process.env.JWT_SECRET);
    response.json({ message: "Login Success!", user_id: dbUser._id, jwtToken });
  } else {
    response.status(400).json({ error: "Invalid Password" });
  }
});

app.post("/tasks", authenticateToken, async (request, response) => {
  const { user_id, task } = request.body;
  try {
    const newTask = await Task.create({ user_id: user_id, task: task });
    response.json({ message: "Task created successfully", task_id: newTask._id });
  } catch (error) {
    console.error("Task creation failed:", error.message);
    response.status(500).json({ error: "Task creation failed" });
  }
});

app.get("/tasks/:userId", async (request, response) => {
  const { userId } = request.params;
  try {
    const taskArray = await Task.find({ user_id: userId });
    response.json(taskArray);
  } catch (error) {
    console.error("Error fetching tasks:", error.message);
    response.status(500).json({ error: "Failed to fetch tasks" });
  }
});

app.get("/users/", async (request, response) => {
  try {
    const usersArray = await User.find();
    response.json(usersArray);
  } catch (error) {
    console.error("Error fetching users:", error.message);
    response.status(500).json({ error: "Failed to fetch users" });
  }
});

app.delete('/tasks/:taskId', authenticateToken, async (req, res) => {
  const { taskId } = req.params;
  try {
    const result = await Task.deleteOne({ _id: taskId });
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

app.patch('/tasks/:taskId', authenticateToken, async (req, res) => {
  const { taskId } = req.params;
  const { isChecked } = req.body;

  try {
    await Task.updateOne(
      { _id: taskId },
      { $set: { isChecked: isChecked } }
    );
    console.log(`Task ${taskId} isChecked status updated to ${isChecked}`);
    res.json({ message: 'Task isChecked status updated successfully' });
  } catch (error) {
    console.error('Error updating task isChecked status:', error.message);
    res.status(500).json({ error: 'Failed to update task isChecked status' });
  }
});
