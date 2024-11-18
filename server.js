const express = require("express")

const path = require("path")

const {open} = require("sqlite")

const sqlite3 = require("sqlite3")

const jwt = require("jsonwebtoken")

const bcrypt = require("bcrypt")

const multer = require("multer")

const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, "filesharing.db")

let db = null
const initializeDBAndserver = async () =>{
    try{
        const db = await open({
        filename: dbPath,
        driver: sqlite3.Database,
    })
        app.listen(3000, ()=>{
            console.log("server running at http://localhost:3000/")
        })
    }
    catch(e){
        console.log(e.message)
    }
}

initializeDBAndserver()

const authenticateToken = (role) => (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).send("Authorization header missing");
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "secret_key", (err, payload) => {
        if (err) return res.status(401).send("Invalid Token");
        if (payload.role !== role) return res.status(403).send("Forbidden");

        req.user = payload;
        next();
    });
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, "uploads"),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.presentationml.presentation"];
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Invalid file type"));
};

const upload = multer({ storage, fileFilter });

app.post("/ops/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await db.get("SELECT * FROM users WHERE email = ? AND role = 'OpsUser'", [email]);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).send("Invalid credentials");
    }

    const token = jwt.sign({ id: user.id, role: user.role }, "secret_key", { expiresIn: "1h" });
    res.send({ token });
});

app.post("/ops/upload", authenticateToken("OpsUser"), upload.single("file"), async (req, res) => {
    const { file } = req;
    if (!file) return res.status(400).send("File upload failed");

    const insertQuery = "INSERT INTO files (file_name, uploaded_by, file_path) VALUES (?, ?, ?)";
    await db.run(insertQuery, [file.originalname, req.user.id, file.path]);
    res.send("File uploaded successfully");
});

app.post("/client/signup", async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const insertQuery = "INSERT INTO users (email, password, role) VALUES (?, ?, 'ClientUser')";
    await db.run(insertQuery, [email, hashedPassword]);

    const verificationToken = jwt.sign({ email }, "email_secret", { expiresIn: "1d" });

    // Send verification email
    const transporter = nodemailer.createTransport({ service: "gmail", auth: { user: "your_email", pass: "your_password" } });
    const verificationUrl = `http://localhost:3000/verify-email/${verificationToken}`;
    await transporter.sendMail({
        from: "your_email",
        to: email,
        subject: "Verify your email",
        text: `Click this link to verify your email: ${verificationUrl}`,
    });

    res.send("Verification email sent");
});

app.get("/verify-email/:token", async (req, res) => {
    try {
        const { email } = jwt.verify(req.params.token, "email_secret");
        await db.run("UPDATE users SET is_verified = 1 WHERE email = ?", [email]);
        res.send("Email verified");
    } catch {
        res.status(400).send("Invalid token");
    }
});

app.post("/client/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await db.get("SELECT * FROM users WHERE email = ? AND role = 'ClientUser'", [email]);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).send("Invalid credentials");
    }

    const token = jwt.sign({ id: user.id, role: user.role }, "secret_key", { expiresIn: "1h" });
    res.send({ token });
});

app.get("/client/files", authenticateToken("ClientUser"), async (req, res) => {
    const files = await db.all("SELECT * FROM files");
    res.send(files);
});

app.get("/client/download/:fileId", authenticateToken("ClientUser"), async (req, res) => {
    const file = await db.get("SELECT * FROM files WHERE id = ?", [req.params.fileId]);
    if (!file) return res.status(404).send("File not found");

    const encryptedUrl = crypto.createHash("sha256").update(`${file.id}-${Date.now()}`).digest("hex");
    res.send({ "download-link": `http://localhost:3000/download/${encryptedUrl}` });
});

app.get("/download/:encryptedUrl", authenticateToken("ClientUser"), (req, res) => {
    // Validate URL and serve file
    // Implementation here depends on how you generate the encrypted URL
});
