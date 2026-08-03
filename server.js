const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: '*' }));
app.use(express.json());

app.get('/', (req, res) => {
    res.send('🚀 Enterprise Inventory System API is Running!');
});

// -------------------------------------------------------------
// 🔐 AUTHENTICATION & APPROVAL ROUTES
// -------------------------------------------------------------

// 🟢 REGISTER WITH CURRENCY & ADMIN PASSCODE
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role, currency, adminCode } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Name, email, and password required' });

    try {
        const userExists = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) return res.status(400).json({ message: 'Email is already registered' });

        const requestedRole = role ? role.toUpperCase() : 'CUSTOMER';
        
        // 🛡️ Secret Admin Passcode Check
        if (requestedRole === 'ADMIN') {
            const SECRET_ADMIN_PASS = process.env.ADMIN_SECRET || 'ADMIN123'; // Passcode
            if (adminCode !== SECRET_ADMIN_PASS) {
                return res.status(403).json({ message: 'Invalid Admin Secret Code!' });
            }
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const userCurrency = currency || 'USD';
        
        // Admins are auto-approved, Customers require Admin Approval
        const isApproved = requestedRole === 'ADMIN' ? true : false;

        const newUser = await db.query(
            'INSERT INTO users (name, email, password, role, currency, is_approved) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role, currency, is_approved',
            [name, email, hashedPassword, requestedRole, userCurrency, isApproved]
        );

        const msg = isApproved 
            ? 'Account created successfully!' 
            : 'Registration successful! Please wait for Admin approval before logging in.';

        res.status(201).json({ message: msg, user: newUser.rows[0] });
    } catch (err) {
        console.error('Registration Error:', err.message);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// 🟢 LOGIN (WITH APPROVAL CHECK)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(400).json({ message: 'Invalid credentials' });

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        // ⛔ Check Admin Approval for Customer
        if (!user.is_approved && user.role !== 'ADMIN') {
            return res.status(403).json({ message: 'Your account is pending Admin approval. Please contact support.' });
        }

        const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1d' });
        res.json({ 
            message: 'Login successful!', 
            token, 
            user: { id: user.id, name: user.name, email: user.email, role: user.role, currency: user.currency } 
        });
    } catch (err) {
        console.error('Login Error:', err.message);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// 🟢 ADMIN: GET PENDING CUSTOMERS
app.get('/api/admin/pending-users', async (req, res) => {
    try {
        const result = await db.query('SELECT id, name, email, currency, role, created_at FROM users WHERE is_approved = FALSE ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch pending users' });
    }
});

// 🟢 ADMIN: APPROVE CUSTOMER
app.put('/api/admin/approve-user/:id', async (req, res) => {
    try {
        await db.query('UPDATE users SET is_approved = TRUE WHERE id = $1', [req.params.id]);
        res.json({ message: 'Customer account approved successfully!' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to approve customer' });
    }
});

// -------------------------------------------------------------
// 📦 PRODUCT ROUTES
// -------------------------------------------------------------

app.get('/api/products', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM products ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/products', async (req, res) => {
    let { name, sku, quantity, price } = req.body;
    if (!name || !price) return res.status(400).json({ message: 'Name and Price required!' });
    if (!sku || sku.trim() === '') sku = 'SKU-' + Math.floor(100000 + Math.random() * 900000);

    try {
        const newProduct = await db.query(
            'INSERT INTO products (name, sku, quantity, price, alert_quantity) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [name, sku, quantity || 0, price, 5]
        );
        res.status(201).json({ message: 'Product added successfully', product: newProduct.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Database query error' });
    }
});

app.put('/api/products/:id', async (req, res) => {
    const { name, sku, price, quantity } = req.body;
    try {
        const result = await db.query(
            'UPDATE products SET name = $1, sku = $2, price = $3, quantity = $4 WHERE id = $5 RETURNING *',
            [name, sku, price, quantity || 0, req.params.id]
        );
        res.json({ message: 'Product updated successfully!', product: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update product' });
    }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM products WHERE id = $1', [req.params.id]);
        res.json({ message: 'Product deleted successfully!' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// -------------------------------------------------------------
// 🛒 SALES & REPORTS
// -------------------------------------------------------------

app.post('/api/sales', async (req, res) => {
    const { customer_id, product_id, quantity } = req.body;
    try {
        const productRes = await db.query('SELECT * FROM products WHERE id = $1', [product_id]);
        if (productRes.rows.length === 0) return res.status(404).json({ message: 'Product not found' });

        const product = productRes.rows[0];
        if (product.quantity < quantity) return res.status(400).json({ message: `Only ${product.quantity} items available!` });

        const totalAmount = product.price * quantity;
        const newStock = product.quantity - quantity;

        const saleRes = await db.query('INSERT INTO sales (customer_id, total_amount, payment_status) VALUES ($1, $2, $3) RETURNING id', [customer_id, totalAmount, 'PAID']);
        await db.query('INSERT INTO sale_items (sale_id, product_id, quantity, unit_price) VALUES ($1, $2, $3, $4)', [saleRes.rows[0].id, product_id, quantity, product.price]);
        await db.query('UPDATE products SET quantity = $1 WHERE id = $2', [newStock, product_id]);

        res.status(201).json({ message: 'Purchase completed successfully!', saleId: saleRes.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: 'Purchase failed' });
    }
});

app.get('/api/sales/customer/:id', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT s.id as sale_id, s.total_amount, s.created_at, p.name as product_name, si.quantity, si.unit_price 
            FROM sales s
            JOIN sale_items si ON s.id = si.sale_id
            JOIN products p ON si.product_id = p.id
            WHERE s.customer_id = $1 ORDER BY s.id DESC
        `, [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch customer orders' });
    }
});

app.get('/api/admin/analytics', async (req, res) => {
    try {
        const revenueRes = await db.query('SELECT COALESCE(SUM(total_amount), 0) as total_revenue FROM sales');
        const itemsSoldRes = await db.query('SELECT COALESCE(SUM(quantity), 0) as total_items_sold FROM sale_items');
        const lowStockRes = await db.query('SELECT * FROM products WHERE quantity <= 5 ORDER BY quantity ASC');
        const pendingUsersRes = await db.query('SELECT COUNT(*) as pending_count FROM users WHERE is_approved = FALSE');

        res.json({
            totalRevenue: Number(revenueRes.rows[0].total_revenue),
            totalItemsSold: Number(itemsSoldRes.rows[0].total_items_sold),
            lowStockCount: lowStockRes.rows.length,
            pendingUsersCount: Number(pendingUsersRes.rows[0].pending_count)
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

app.get('/api/admin/sales-report', async (req, res) => {
    const { startDate, endDate } = req.query;
    try {
        let query = `
            SELECT s.id as sale_id, COALESCE(u.name, 'Customer') as customer_name, COALESCE(p.name, 'Product') as product_name, 
                   si.quantity, si.unit_price, s.total_amount, s.created_at
            FROM sales s
            LEFT JOIN users u ON s.customer_id = u.id
            LEFT JOIN sale_items si ON s.id = si.sale_id
            LEFT JOIN products p ON s.product_id = p.id
        `;
        const params = [];
        if (startDate && endDate) {
            query += ` WHERE s.created_at >= $1 AND s.created_at <= $2`;
            params.push(startDate, endDate + ' 23:59:59');
        }
        query += ` ORDER BY s.id DESC`;

        const result = await db.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to generate report' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`📡 Server running on http://localhost:${PORT}`);
});