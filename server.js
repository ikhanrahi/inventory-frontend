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

// ১. টেস্ট রুট
app.get('/', (req, res) => {
    res.send('🚀 Enterprise Inventory System API is Running!');
});

// -------------------------------------------------------------
// 🔐 AUTHENTICATION ROUTES
// -------------------------------------------------------------

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Name, email, and password required' });

    try {
        const userExists = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) return res.status(400).json({ message: 'Email is already registered' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const userRole = role ? role.toUpperCase() : 'CUSTOMER';

        const newUser = await db.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
            [name, email, hashedPassword, userRole]
        );

        res.status(201).json({ message: 'User registered successfully!', user: newUser.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Server error during registration' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(400).json({ message: 'Invalid credentials' });

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1d' });
        res.json({ message: 'Login successful!', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: 'Server error during login' });
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

// 🟢 SKU is Optional! Auto-generates unique SKU if left empty.
app.post('/api/products', async (req, res) => {
    let { name, sku, quantity, price } = req.body;

    if (!name || !price) {
        return res.status(400).json({ message: 'Name and Price are required!' });
    }

    if (!sku || sku.trim() === '') {
        sku = 'SKU-' + Math.floor(100000 + Math.random() * 900000);
    }

    try {
        const newProduct = await db.query(
            'INSERT INTO products (name, sku, quantity, price, alert_quantity) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [name, sku, quantity || 0, price, 5]
        );

        res.status(201).json({
            message: 'Product added successfully',
            product: newProduct.rows[0]
        });
    } catch (err) {
        console.error('Add Product Error:', err.message);
        res.status(500).json({ error: 'Database query error' });
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
// 🛒 SALES & PURCHASE ROUTES
// -------------------------------------------------------------

app.post('/api/sales', async (req, res) => {
    const { customer_id, product_id, quantity } = req.body;
    if (!customer_id || !product_id || !quantity || quantity <= 0) return res.status(400).json({ message: 'Invalid order details' });

    try {
        const productRes = await db.query('SELECT * FROM products WHERE id = $1', [product_id]);
        if (productRes.rows.length === 0) return res.status(404).json({ message: 'Product not found' });

        const product = productRes.rows[0];
        if (product.quantity < quantity) return res.status(400).json({ message: `Only ${product.quantity} items available!` });

        const totalAmount = product.price * quantity;
        const newStock = product.quantity - quantity;

        const saleRes = await db.query(
            'INSERT INTO sales (customer_id, total_amount, payment_status) VALUES ($1, $2, $3) RETURNING id',
            [customer_id, totalAmount, 'PAID']
        );

        await db.query(
            'INSERT INTO sale_items (sale_id, product_id, quantity, unit_price) VALUES ($1, $2, $3, $4)',
            [saleRes.rows[0].id, product_id, quantity, product.price]
        );

        // Update Stock
        await db.query('UPDATE products SET quantity = $1 WHERE id = $2', [newStock, product_id]);

        res.status(201).json({ message: 'Purchase completed successfully!', saleId: saleRes.rows[0].id, totalAmount });
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
            WHERE s.customer_id = $1
            ORDER BY s.id DESC
        `, [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch customer orders' });
    }
});

// -------------------------------------------------------------
// 📊 REPORTS & ANALYTICS
// -------------------------------------------------------------

app.get('/api/admin/analytics', async (req, res) => {
    try {
        const revenueRes = await db.query('SELECT COALESCE(SUM(total_amount), 0) as total_revenue FROM sales');
        const itemsSoldRes = await db.query('SELECT COALESCE(SUM(quantity), 0) as total_items_sold FROM sale_items');
        const lowStockRes = await db.query('SELECT * FROM products WHERE quantity <= 5 ORDER BY quantity ASC');

        res.json({
            totalRevenue: Number(revenueRes.rows[0].total_revenue),
            totalItemsSold: Number(itemsSoldRes.rows[0].total_items_sold),
            lowStockCount: lowStockRes.rows.length,
            lowStockProducts: lowStockRes.rows
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

app.get('/api/admin/sales-report', async (req, res) => {
    const { startDate, endDate } = req.query;
    try {
        let query = `
            SELECT s.id as sale_id, u.name as customer_name, p.name as product_name, 
                   si.quantity, si.unit_price, s.total_amount, s.created_at
            FROM sales s
            JOIN users u ON s.customer_id = u.id
            JOIN sale_items si ON s.id = si.sale_id
            JOIN products p ON si.product_id = p.id
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