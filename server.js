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
// 🔐 AUTHENTICATION ROUTES (Register & Login)
// -------------------------------------------------------------

// ২. ইউজার রেজিস্ট্রেশন API (Register)
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email, and password are required' });
    }

    try {
        // ইমেইল আগে থেকে আছে কিনা চেক করা
        const userExists = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ message: 'Email is already registered' });
        }

        // পাসওয়ার্ড এনক্রিপ্ট / হ্যাশ করা
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // রোল সেট করা (ডিফল্ট CUSTOMER, তবে ADMIN ও দেওয়া যাবে)
        const userRole = role ? role.toUpperCase() : 'CUSTOMER';

        // ডাটাবেজে ইউজার সেভ করা
        const newUser = await db.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
            [name, email, hashedPassword, userRole]
        );

        res.status(201).json({
            message: 'User registered successfully!',
            user: newUser.rows[0]
        });

    } catch (err) {
        console.error('Registration Error:', err.message);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// ৩. ইউজার লগইন API (Login)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        // ইমেইল দিয়ে ইউজার খোঁজা
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const user = result.rows[0];

        // পাসওয়ার্ড ম্যাচ করে কিনা চেক করা
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // সিকিউর JWT টোকেন জেনারেট করা
        const token = jwt.sign(
            { id: user.id, name: user.name, role: user.role },
            process.env.JWT_SECRET || 'secretkey',
            { expiresIn: '1d' } // টোকেনটির মেয়াদ ১ দিন থাকবে
        );

        res.json({
            message: 'Login successful!',
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (err) {
        console.error('Login Error:', err.message);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// -------------------------------------------------------------
// 📦 PRODUCT ROUTES
// -------------------------------------------------------------

// ৪. সব প্রোডাক্ট লিস্ট
app.get('/api/products', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM products ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database server error' });
    }
});

// ৫. নতুন প্রোডাক্ট অ্যাড
app.post('/api/products', async (req, res) => {
    const { name, sku, quantity, price, alert_quantity } = req.body;

    if (!name || !sku || !price) {
        return res.status(400).json({ message: 'Name, SKU, and Price are required!' });
    }

    try {
        const newProduct = await db.query(
            'INSERT INTO products (name, sku, quantity, price, alert_quantity) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [name, sku, quantity || 0, price, alert_quantity || 5]
        );

        res.status(201).json({
            message: 'Product added successfully',
            product: newProduct.rows[0]
        });
    } catch (err) {
        res.status(500).json({ error: 'Database query error' });
    }
});

// -------------------------------------------------------------
// 🛒 SALES & PURCHASE ROUTES
// -------------------------------------------------------------

// ১. কাস্টমারের কেনাকাটা/অর্ডার নেওয়ার API
app.post('/api/sales', async (req, res) => {
    const { customer_id, product_id, quantity } = req.body;

    if (!customer_id || !product_id || !quantity || quantity <= 0) {
        return res.status(400).json({ message: 'Invalid order details!' });
    }

    try {
        // ১. প্রোডাক্টের স্টক ও দাম ডাটাবেজ থেকে চেক করা
        const productRes = await db.query('SELECT * FROM products WHERE id = $1', [product_id]);
        
        if (productRes.rows.length === 0) {
            return res.status(404).json({ message: 'Product not found!' });
        }

        const product = productRes.rows[0];

        // ২. স্টকে পর্যাপ্ত মালামাল আছে কিনা চেক করা
        if (product.quantity < quantity) {
            return res.status(400).json({ message: `Only ${product.quantity} items available in stock!` });
        }

        const totalAmount = product.price * quantity;

        // ৩. sales টেবিলে বিক্রির হিসাব যোগ করা
        const saleRes = await db.query(
            'INSERT INTO sales (customer_id, total_amount, payment_status) VALUES ($1, $2, $3) RETURNING id',
            [customer_id, totalAmount, 'PAID']
        );

        const saleId = saleRes.rows[0].id;

        // ৪. sale_items টেবিলে কোন প্রোডাক্ট কত পিস কেনা হলো তা সেভ করা
        await db.query(
            'INSERT INTO sale_items (sale_id, product_id, quantity, unit_price) VALUES ($1, $2, $3, $4)',
            [saleId, product_id, quantity, product.price]
        );

        // ৫. প্রোডাক্টের স্টক থেকে বিক্রি হওয়া পরিমাণ বিয়োগ করা (Stock Auto-Deduct)
        await db.query(
            'UPDATE products SET quantity = quantity - $1 WHERE id = $2',
            [quantity, product_id]
        );

        res.status(201).json({
            message: 'Purchase completed successfully!',
            saleId: saleId,
            totalAmount: totalAmount
        });

    } catch (err) {
        console.error('Purchase Error:', err.message);
        res.status(500).json({ error: 'Server error during purchase process' });
    }
});

// ২. কাস্টমারের নিজস্ব অর্ডারের ইতিহাস (Order History) দেখার API
app.get('/api/sales/customer/:id', async (req, res) => {
    const customerId = req.params.id;

    try {
        const result = await db.query(`
            SELECT s.id as sale_id, s.total_amount, s.created_at, p.name as product_name, si.quantity, si.unit_price 
            FROM sales s
            JOIN sale_items si ON s.id = si.sale_id
            JOIN products p ON si.product_id = p.id
            WHERE s.customer_id = $1
            ORDER BY s.id DESC
        `, [customerId]);

        res.json(result.rows);
    } catch (err) {
        console.error('Fetch Orders Error:', err.message);
        res.status(500).json({ error: 'Failed to fetch customer orders' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`📡 Server running on http://localhost:${PORT}`);
});