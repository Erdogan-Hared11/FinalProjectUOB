require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();

app.use(helmet());
app.disable('x-powered-by');
app.use(morgan('dev'));
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json({limit:'20mb'}));
app.use(bodyParser.urlencoded({ extended: true , limit:'20mb' }));

const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || 'Ufeyn__12345',
    database: process.env.DB_NAME || 'dalag_com',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) return cb(null, true);
        cb(new Error('Only image files are allowed!'));
    }
}).single('image');

app.use('/uploads', express.static(uploadsDir));

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        req.user = { id: 1 }; 
        next();
    } else {
        return res.status(401).json({ error: 'Authentication required' });
    }
};

app.post('/upload', authenticate, (req, res) => {
    upload(req, res, err => {
        if (err) return res.status(400).json({ error: err.message });
        const imageUrl = `http://localhost:${PORT}/uploads/${req.file.filename}`;
        res.json({ message: 'Image uploaded successfully', url: imageUrl });
    });
});

app.get('/uploads/:filename', (req, res) => {
    const filepath = path.join(uploadsDir, req.params.filename);
    if (fs.existsSync(filepath)) {
        res.sendFile(filepath);
    } else {
        res.status(404).json({ error: 'Image not found' });
    }
});

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        res.status(201).json({
            message: 'User registered successfully',
            userId: result.insertId
        });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email already exists' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

        if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/users', async (req, res) => {
    try {
        const [users] = await db.execute('SELECT id, username, email FROM users');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/users/:id', async (req, res) => {
    try {
        const [result] = await db.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/users/:id', async (req, res) => {
    try {
        const { username, email } = req.body;
        const [result] = await db.execute(
            'UPDATE users SET username = ?, email = ? WHERE id = ?',
            [username, email, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/products', async (req, res) => {
    try {
        const [products] = await db.execute('SELECT id, name, address, status, weight, image_url FROM products');
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/products', authenticate, (req, res) => {
    upload(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });

        try {
            const { name, address, status, weight } = req.body;
            if (!name || !req.file) return res.status(400).json({ error: 'Name and image are required' });

            const [result] = await db.execute(
                'INSERT INTO products (name, address, status, weight, image_url) VALUES (?, ?, ?, ?, ?)',
                [name, address, status || 'active', weight || 0, req.file.filename]
            );

            res.status(201).json({
                message: 'Product added successfully',
                productId: result.insertId
            });
        } catch (err) {
            if (req.file) fs.unlinkSync(path.join(uploadsDir, req.file.filename));
            res.status(500).json({ error: err.message });
        }
    });
});

app.delete('/products/:id', authenticate, async (req, res) => {
    try {
        // 1. Hel image_url si aan u tirtirno file-ka image-ka
        const [rows] = await db.execute('SELECT image_url FROM products WHERE id = ?', [req.params.id]);
        if (rows.length === 0) return res.status(404).json({ error: 'Product not found' });

        const imageUrl = rows[0].image_url;

        // 2. Tirtir product-ka
        const [result] = await db.execute('DELETE FROM products WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Product not found' });

        // 3. Tirtir image file
        if (imageUrl && fs.existsSync(path.join(uploadsDir, imageUrl))) {
            fs.unlinkSync(path.join(uploadsDir, imageUrl));
        }

        res.json({ message: 'Product deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.put('/products/:id', authenticate, (req, res) => {
    upload(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });

        try {
            const { name, address, status, weight } = req.body;
            if (!name || !address) return res.status(400).json({ error: 'Name and address are required' });

            // 1. Hel xogta product-ka hadda jira si aan u helno image_url
            const [rows] = await db.execute('SELECT image_url FROM products WHERE id = ?', [req.params.id]);
            if (rows.length === 0) {
                // Haddii file cusub la upload gareeyay laakiin product ma jiro, tirtir file-ka
                if (req.file) fs.unlinkSync(path.join(uploadsDir, req.file.filename));
                return res.status(404).json({ error: 'Product not found' });
            }

            const oldImage = rows[0].image_url;

            // 2. Haddii file cusub la helay, update image_url, haddii kale hayso image-kii hore
            let imageUrl = oldImage;
            if (req.file) {
                imageUrl = req.file.filename;

                // Tirtir image hore
                if (oldImage && fs.existsSync(path.join(uploadsDir, oldImage))) {
                    fs.unlinkSync(path.join(uploadsDir, oldImage));
                }
            }

            // 3. Update product
            const [result] = await db.execute(
                'UPDATE products SET name = ?, address = ?, status = ?, weight = ?, image_url = ? WHERE id = ?',
                [name, address, status || 'active', weight || 0, imageUrl, req.params.id]
            );

            if (result.affectedRows === 0) {
                if (req.file) fs.unlinkSync(path.join(uploadsDir, req.file.filename));
                return res.status(404).json({ error: 'Product not found' });
            }

            res.json({ message: 'Product updated successfully' });

        } catch (err) {
            if (req.file) fs.unlinkSync(path.join(uploadsDir, req.file.filename));
            res.status(500).json({ error: err.message });
        }
    });
});

app.post('/orders', async (req, res) => {
  try {
    const { user_id, items, total_price, status = 'pending' } = req.body;

    if (!user_id || !items || !total_price) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const [result] = await db.execute(
      `INSERT INTO orders (user_id, items, total_price, status) VALUES (?, ?, ?, ?)`,
      [user_id, JSON.stringify(items), total_price, status]
    );

    res.status(201).json({ message: 'Order created', order_id: result.insertId });
  } catch (error) {
    console.error('Error in /orders:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
app.get('/orders/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    const [orders] = await db.execute(
      'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    res.json({ orders });
  } catch (error) {
    console.error('Error in GET /orders/:userId:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin route: soo hel dhammaan orders-ka
app.get('/admin/orders', async (req, res) => {
  try {
    const [orders] = await db.execute('SELECT * FROM orders');
    res.json(orders);
  } catch (error) {
    console.error('Error fetching all orders:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
// Update order status
app.post('/orders/update-status', async (req, res) => {
  try {
    const { orderId, status } = req.body;

    // Hubi in status uu yahay mid sax ah
    const validStatuses = ['pending', 'confirmed', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status value' });
    }

    // Hubi in orderId la siiyay
    if (!orderId) {
      return res.status(400).json({ message: 'Missing orderId' });
    }

    // Update status in database
    const [result] = await db.execute(
      `UPDATE orders SET status = ? WHERE order_id = ?`,
      [status, orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }

    res.json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});






const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server wuxuu ku shaqeynayaa http://localhost:${PORT}`);
});