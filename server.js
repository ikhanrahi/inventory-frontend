const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dns = require('dns');
require('dotenv').config();
const db = require('./db');

dns.setDefaultResultOrder('ipv4first');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: '*' }));
app.use(express.json());

let currentAdminPasscode = process.env.ADMIN_SECRET || 'ADMIN123';

// 📧 FIXED NODEMAILER TRANSPORTER WITH STRICT IPv4 DNS LOOKUP FOR RENDER
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // SSL for Port 465
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    // STRICTLY FORCES IPv4 DNS LOOKUP & COMPLETELY FIXES ENETUNREACH ON RENDER
    lookup: (hostname, options, callback) => {
        dns.lookup(hostname, { family: 4 }, callback);
    },
    tls: {
        rejectUnauthorized: false
    },
    connectionTimeout: 15000,
    socketTimeout: 15000
});

// Helper function to send low stock alert emails
async function checkAndSendLowStockAlert(productId) {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.log("ℹ️ Email Notification Skipped: EMAIL_USER or EMAIL_PASS not set on Render.");
        return;
    }

    try {
        const res = await db.query('SELECT * FROM products WHERE id = $1', [productId]);
        if (res.rows.length === 0) return;

        const product = res.rows[0];
        if (product.quantity <= 5) {
            console.log(`📧 Triggering Low Stock Email to ${process.env.EMAIL_USER} for product: ${product.name}...`);
            
            const mailOptions = {
                from: `"StockFlow ERP" <${process.env.EMAIL_USER}>`,
                to: process.env.EMAIL_USER,
                subject: `⚠️ LOW STOCK ALERT: ${product.name} (${product.quantity} Pcs Left)`,
                html: `
                    <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0f172a; color: #f8fafc; border-radius: 10px;">
                        <h2 style="color: #f43f5e;">⚠️ Low Stock Inventory Alert</h2>
                        <p>The following item in your inventory has reached a critical stock level:</p>
                        <table style="width: 100%; border-collapse: collapse; margin-top: 15px; color: #f8fafc;">
                            <tr style="background-color: #1e293b;"><td style="padding: 8px;"><strong>Product Name:</strong></td><td style="padding: 8px;">${product.name}</td></tr>
                            <tr style="background-color: #0f172a;"><td style="padding: 8px;"><strong>SKU:</strong></td><td style="padding: 8px;">${product.sku}</td></tr>
                            <tr style="background-color: #1e293b;"><td style="padding: 8px;"><strong>Remaining Stock:</strong></td><td style="padding: 8px; font-weight: bold; color: #f43f5e;">${product.quantity} Pcs</td></tr>
                        </table>
                    </div>
                `
            };

            const info = await transporter.sendMail(mailOptions);
            console.log(`🎉 Low Stock Email Sent Successfully! Message ID: ${info.messageId}`);
        }
    } catch (err) {
        console.error('❌ Email Dispatch Failed with Error:', err.message);
    }
}

app.get('/', (req, res) => {
    res.send('🚀 Enterprise Inventory System API is Running!');
});

// 🔐 AUTHENTICATION & APPROVAL ROUTES
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role, currency, adminCode } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Name, email, and password required' });

    try {
        const userExists = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) return res.status(400).json({ message: 'Email is already registered' });

        const requestedRole = role ? role.toUpperCase() : 'CUSTOMER';
        if (requestedRole === 'ADMIN' && adminCode !== currentAdminPasscode) {
            return res.status(403).json({ message: 'Invalid Admin Secret Code!' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const userCurrency = currency || 'USD';
        const isApproved = requestedRole === 'ADMIN' ? true : false;

        const newUser = await db.query(
            'INSERT INTO users (name, email, password, role, currency, is_approved) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role, currency, is_approved',
            [name, email, hashedPassword, requestedRole, userCurrency, isApproved]
        );

        const msg = isApproved ? 'Account created successfully!' : 'Registration successful! Please wait for Admin approval.';
        res.status(201).json({ message: msg, user: newUser.rows[0] });
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

        if (!user.is_approved && user.role !== 'ADMIN') {
            return res.status(403).json({ message: 'Your account is pending Admin approval.' });
        }

        const loginTime = new Date().toISOString();
        try { await db.query('UPDATE users SET updated_at = $1 WHERE id = $2', [loginTime, user.id]); } catch (e) {}

        const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1d' });
        res.json({ 
            message: 'Login successful!', 
            token, 
            user: { id: user.id, name: user.name, email: user.email, role: user.role, currency: user.currency || 'USD', lastLogin: loginTime } 
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error during login' });
    }
});

// 🔑 ADMIN PASSCODE MANAGEMENT
app.get('/api/admin/get-passcode', (req, res) => res.json({ passcode: currentAdminPasscode }));
app.put('/api/admin/update-passcode', (req, res) => {
    const { newPasscode } = req.body;
    if (!newPasscode || newPasscode.trim().length < 4) return res.status(400).json({ message: 'Passcode must be at least 4 characters long!' });
    currentAdminPasscode = newPasscode.trim();
    res.json({ message: 'Admin passcode updated successfully!', passcode: currentAdminPasscode });
});

// 👥 ADMIN USER MANAGEMENT
app.get('/api/admin/users-stats', async (req, res) => {
    try {
        const totalAdmins = await db.query("SELECT COUNT(*) FROM users WHERE role = 'ADMIN'");
        const totalCustomers = await db.query("SELECT COUNT(*) FROM users WHERE role = 'CUSTOMER' AND is_approved = TRUE");
        const pendingApprovals = await db.query("SELECT COUNT(*) FROM users WHERE is_approved = FALSE");
        res.json({
            totalAdmins: parseInt(totalAdmins.rows[0].count),
            totalCustomers: parseInt(totalCustomers.rows[0].count),
            pendingApprovals: parseInt(pendingApprovals.rows[0].count)
        });
    } catch (err) { res.status(500).json({ error: 'Failed to fetch user stats' }); }
});

app.get('/api/admin/all-users', async (req, res) => {
    try {
        const result = await db.query('SELECT id, name, email, role, currency, is_approved, created_at, updated_at FROM users ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch users' }); }
});

app.put('/api/admin/manage-user/:id', async (req, res) => {
    const { role, is_approved, currency } = req.body;
    try {
        await db.query('UPDATE users SET role = $1, is_approved = $2, currency = $3 WHERE id = $4', [role, is_approved, currency, req.params.id]);
        res.json({ message: 'User updated successfully!' });
    } catch (err) { res.status(500).json({ error: 'Failed to update user' }); }
});

app.put('/api/admin/change-password/:id', async (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters long!' });
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await db.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.params.id]);
        res.json({ message: 'Password updated successfully!' });
    } catch (err) { res.status(500).json({ error: 'Failed to update password' }); }
});

app.delete('/api/admin/delete-user/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ message: 'User deleted successfully!' });
    } catch (err) { res.status(500).json({ error: 'Failed to delete user' }); }
});

// 📦 PRODUCT ROUTES
app.get('/api/products', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM products ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/products', async (req, res) => {
    let { name, sku, quantity, price, cost_price, category, brand, supplier, location, expiry_date } = req.body;
    if (!name || !price) return res.status(400).json({ message: 'Name and Price required!' });
    if (!sku || sku.trim() === '') sku = 'SKU-' + Math.floor(100000 + Math.random() * 900000);

    try {
        const newProduct = await db.query(
            `INSERT INTO products (name, sku, quantity, price, cost_price, category, brand, supplier, location, expiry_date, alert_quantity) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
            [name, sku, quantity || 0, price, cost_price || 0, category || 'General', brand || 'Generic', supplier || 'N/A', location || 'Main Stock', expiry_date || null, 5]
        );
        res.status(201).json({ message: 'Product added successfully', product: newProduct.rows[0] });
    } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// 📦 BULK PRODUCT IMPORT API
app.post('/api/products/bulk', async (req, res) => {
    const { products } = req.body;
    if (!products || !Array.isArray(products) || products.length === 0) {
        return res.status(400).json({ message: 'No valid products provided for import!' });
    }

    try {
        let insertedCount = 0;
        for (const item of products) {
            let { name, sku, quantity, price, cost_price, category, brand, supplier, location, expiry_date } = item;
            if (!name || !price) continue;

            if (!sku || sku.trim() === '') {
                sku = 'SKU-' + Math.floor(100000 + Math.random() * 900000);
            }

            await db.query(
                `INSERT INTO products (name, sku, quantity, price, cost_price, category, brand, supplier, location, expiry_date, alert_quantity) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                [
                    name,
                    sku,
                    parseInt(quantity) || 0,
                    parseFloat(price) || 0,
                    parseFloat(cost_price) || 0,
                    category || 'General',
                    brand || 'Generic',
                    supplier || 'N/A',
                    location || 'Main Stock',
                    expiry_date || null,
                    5
                ]
            );
            insertedCount++;
        }

        res.status(201).json({ message: `Successfully imported ${insertedCount} products!`, count: insertedCount });
    } catch (err) {
        console.error('Bulk Import Error:', err.message);
        res.status(500).json({ error: 'Failed to process bulk product import.' });
    }
});

app.put('/api/products/:id', async (req, res) => {
    const { name, sku, price, cost_price, category, brand, supplier, location, expiry_date, quantity } = req.body;
    try {
        const result = await db.query(
            `UPDATE products SET name = $1, sku = $2, price = $3, cost_price = $4, category = $5, brand = $6, supplier = $7, location = $8, expiry_date = $9, quantity = $10 WHERE id = $11 RETURNING *`,
            [name, sku, price, cost_price || 0, category || 'General', brand || 'Generic', supplier || 'N/A', location || 'Main Stock', expiry_date || null, quantity || 0, req.params.id]
        );
        checkAndSendLowStockAlert(req.params.id);
        res.json({ message: 'Product updated successfully!', product: result.rows[0] });
    } catch (err) { res.status(500).json({ error: 'Failed to update product' }); }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        await db.query('DELETE FROM products WHERE id = $1', [req.params.id]);
        res.json({ message: 'Product deleted successfully!' });
    } catch (err) { res.status(500).json({ error: 'Failed to delete product' }); }
});

// 🛒 POS & CHECKOUT
app.post('/api/pos/checkout', async (req, res) => {
    const { customer_id, cart_items, payment_method, paid_amount } = req.body;
    if (!cart_items || cart_items.length === 0) return res.status(400).json({ message: 'Cart is empty!' });

    try {
        let grandTotal = 0;
        for (const item of cart_items) {
            const prodRes = await db.query('SELECT * FROM products WHERE id = $1', [item.product_id]);
            const prod = prodRes.rows[0];
            if (prod.quantity < item.quantity) return res.status(400).json({ message: `Insufficient stock for ${prod.name}` });
            grandTotal += prod.price * item.quantity;
        }

        const paid = paid_amount !== undefined ? parseFloat(paid_amount) : grandTotal;
        const due = Math.max(0, grandTotal - paid);
        const payStatus = due > 0 ? (paid > 0 ? 'PARTIAL' : 'DUE') : 'PAID';

        const saleRes = await db.query(
            'INSERT INTO sales (customer_id, total_amount, paid_amount, due_amount, payment_status, payment_method) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [customer_id || null, grandTotal, paid, due, payStatus, payment_method || 'Cash']
        );
        const saleId = saleRes.rows[0].id;

        for (const item of cart_items) {
            const prodRes = await db.query('SELECT * FROM products WHERE id = $1', [item.product_id]);
            const prod = prodRes.rows[0];
            await db.query('INSERT INTO sale_items (sale_id, product_id, quantity, unit_price) VALUES ($1, $2, $3, $4)', [saleId, item.product_id, item.quantity, prod.price]);
            await db.query('UPDATE products SET quantity = $1 WHERE id = $2', [prod.quantity - item.quantity, item.product_id]);
            checkAndSendLowStockAlert(item.product_id);
        }

        res.status(201).json({ message: 'POS Checkout completed successfully!', saleId, totalAmount: grandTotal, paidAmount: paid, dueAmount: due });
    } catch (err) { res.status(500).json({ error: 'POS Transaction failed' }); }
});

app.post('/api/sales', async (req, res) => {
    const { customer_id, product_id, quantity, payment_method, paid_amount } = req.body;
    try {
        const productRes = await db.query('SELECT * FROM products WHERE id = $1', [product_id]);
        const product = productRes.rows[0];
        if (product.quantity < quantity) return res.status(400).json({ message: 'Stock not available' });

        const totalAmount = product.price * quantity;
        const paid = paid_amount !== undefined ? parseFloat(paid_amount) : totalAmount;
        const due = Math.max(0, totalAmount - paid);
        const payStatus = due > 0 ? (paid > 0 ? 'PARTIAL' : 'DUE') : 'PAID';

        const saleRes = await db.query(
            'INSERT INTO sales (customer_id, total_amount, paid_amount, due_amount, payment_status, payment_method) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [customer_id, totalAmount, paid, due, payStatus, payment_method || 'Cash']
        );

        await db.query('INSERT INTO sale_items (sale_id, product_id, quantity, unit_price) VALUES ($1, $2, $3, $4)', [saleRes.rows[0].id, product_id, quantity, product.price]);
        await db.query('UPDATE products SET quantity = $1 WHERE id = $2', [product.quantity - quantity, product_id]);
        checkAndSendLowStockAlert(product_id);

        res.status(201).json({ message: 'Purchase successful!', saleId: saleRes.rows[0].id });
    } catch (err) { res.status(500).json({ error: 'Purchase failed' }); }
});

// 💳 CUSTOMER DUE LEDGER & PAYMENTS
app.get('/api/admin/dues-ledger', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT u.id as customer_id, u.name as customer_name, u.email, u.currency,
                   COALESCE(SUM(s.due_amount), 0) as total_due,
                   COALESCE(SUM(s.total_amount), 0) as total_purchased,
                   COALESCE(SUM(s.paid_amount), 0) as total_paid
            FROM users u
            LEFT JOIN sales s ON u.id = s.customer_id
            WHERE u.role = 'CUSTOMER'
            GROUP BY u.id, u.name, u.email, u.currency
            HAVING SUM(s.due_amount) > 0
            ORDER BY total_due DESC
        `);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch dues ledger' }); }
});

app.post('/api/admin/pay-due', async (req, res) => {
    const { customer_id, amount_paid } = req.body;
    if (!customer_id || !amount_paid || parseFloat(amount_paid) <= 0) {
        return res.status(400).json({ message: 'Valid Customer ID and Payment Amount required!' });
    }

    try {
        let remainingPayment = parseFloat(amount_paid);
        const salesRes = await db.query(
            'SELECT * FROM sales WHERE customer_id = $1 AND due_amount > 0 ORDER BY id ASC',
            [customer_id]
        );

        for (const sale of salesRes.rows) {
            if (remainingPayment <= 0) break;

            const currentDue = parseFloat(sale.due_amount);
            const currentPaid = parseFloat(sale.paid_amount);

            if (remainingPayment >= currentDue) {
                const newPaid = currentPaid + currentDue;
                await db.query(
                    'UPDATE sales SET paid_amount = $1, due_amount = 0, payment_status = $2 WHERE id = $3',
                    [newPaid, 'PAID', sale.id]
                );
                remainingPayment -= currentDue;
            } else {
                const newPaid = currentPaid + remainingPayment;
                const newDue = currentDue - remainingPayment;
                await db.query(
                    'UPDATE sales SET paid_amount = $1, due_amount = $2, payment_status = $3 WHERE id = $4',
                    [newPaid, newDue, 'PARTIAL', sale.id]
                );
                remainingPayment = 0;
            }
        }

        await db.query('INSERT INTO due_payments (customer_id, amount_paid) VALUES ($1, $2)', [customer_id, amount_paid]);
        res.json({ message: `Successfully collected due payment of ${amount_paid}!` });
    } catch (err) {
        res.status(500).json({ error: 'Failed to process due payment' });
    }
});

app.get('/api/sales/customer/:id', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT s.id as sale_id, s.total_amount, COALESCE(s.paid_amount, s.total_amount) as paid_amount, COALESCE(s.due_amount, 0) as due_amount, s.payment_status, s.created_at, p.name as product_name, si.quantity, si.unit_price 
            FROM sales s JOIN sale_items si ON s.id = si.sale_id JOIN products p ON si.product_id = p.id
            WHERE s.customer_id = $1 ORDER BY s.id DESC
        `, [req.params.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Failed to fetch customer orders' }); }
});

app.get('/api/admin/analytics', async (req, res) => {
    try {
        const revenueRes = await db.query('SELECT COALESCE(SUM(total_amount), 0) as total_revenue, COALESCE(SUM(due_amount), 0) as total_due FROM sales');
        const itemsSoldRes = await db.query('SELECT COALESCE(SUM(quantity), 0) as total_items_sold FROM sale_items');
        const lowStockRes = await db.query('SELECT COUNT(*) as low_stock_count FROM products WHERE quantity <= 5');
        res.json({
            totalRevenue: Number(revenueRes.rows[0].total_revenue),
            totalDue: Number(revenueRes.rows[0].total_due),
            totalItemsSold: Number(itemsSoldRes.rows[0].total_items_sold),
            lowStockCount: Number(lowStockRes.rows[0].low_stock_count)
        });
    } catch (err) { res.status(500).json({ error: 'Failed to fetch analytics' }); }
});

// 📊 REPORTS API WITH ALL TYPES INCLUDING PAYMENTS & BESTSELLERS
app.get('/api/admin/reports/:type', async (req, res) => {
    const { type } = req.params;
    const { startDate, endDate } = req.query;
    try {
        let query = '', params = [];
        if (type === 'sales') {
            query = `SELECT s.id as sale_id, COALESCE(u.name, 'Customer') as customer_name, COALESCE(p.name, 'Product') as product_name, si.quantity, si.unit_price, s.total_amount, COALESCE(s.paid_amount, s.total_amount) as paid_amount, COALESCE(s.due_amount, 0) as due_amount, COALESCE(s.payment_method, 'Cash') as payment_method, s.created_at FROM sales s LEFT JOIN users u ON s.customer_id = u.id LEFT JOIN sale_items si ON s.id = si.sale_id LEFT JOIN products p ON si.product_id = p.id`;
            if (startDate && endDate) { query += ` WHERE s.created_at >= $1 AND s.created_at <= $2`; params.push(startDate, endDate + ' 23:59:59'); }
            query += ` ORDER BY s.id DESC`;
        } else if (type === 'dues') {
            query = `SELECT s.id as sale_id, COALESCE(u.name, 'Customer') as customer_name, COALESCE(p.name, 'Product') as product_name, si.quantity, si.unit_price, s.total_amount, s.paid_amount, s.due_amount, s.created_at 
                     FROM sales s JOIN users u ON s.customer_id = u.id JOIN sale_items si ON s.id = si.sale_id JOIN products p ON si.product_id = p.id 
                     WHERE s.due_amount > 0 ORDER BY s.id DESC`;
        } else if (type === 'payments' || type === 'paymentmethods') {
            query = `SELECT COALESCE(payment_method, 'Cash') as payment_method, COUNT(id) as total_transactions, SUM(total_amount) as total_revenue, SUM(paid_amount) as total_collected, SUM(due_amount) as total_due 
                     FROM sales GROUP BY payment_method ORDER BY total_revenue DESC`;
        } else if (type === 'bestsellers') {
            query = `SELECT p.name as product_name, p.sku, p.category, SUM(si.quantity) as total_sold, SUM(si.quantity * si.unit_price) as total_revenue 
                     FROM sale_items si JOIN products p ON si.product_id = p.id 
                     GROUP BY p.id, p.name, p.sku, p.category ORDER BY total_sold DESC LIMIT 10`;
        } else if (type === 'stocks') {
            query = `SELECT id, name, sku, category, brand, supplier, location, expiry_date, price, cost_price, quantity FROM products ORDER BY quantity ASC`;
        } else if (type === 'lowstock') {
            query = `SELECT id, name, sku, category, brand, supplier, location, price, quantity FROM products WHERE quantity <= 5 ORDER BY quantity ASC`;
        } else if (type === 'supplier') {
            query = `SELECT COALESCE(supplier, 'N/A') as supplier, COALESCE(brand, 'Generic') as brand, COUNT(*) as total_products, SUM(quantity) as total_stock, SUM(cost_price * quantity) as total_cost_value FROM products GROUP BY supplier, brand ORDER BY total_stock DESC`;
        } else if (type === 'profit') {
            query = `SELECT p.name as product_name, SUM(si.quantity) as total_sold, SUM(si.quantity * si.unit_price) as gross_revenue, SUM(si.quantity * COALESCE(p.cost_price, 0)) as total_cost, SUM(si.quantity * (si.unit_price - COALESCE(p.cost_price, 0))) as net_profit FROM sale_items si JOIN products p ON si.product_id = p.id GROUP BY p.name ORDER BY net_profit DESC`;
        } else if (type === 'category') {
            query = `SELECT category, COUNT(*) as total_items, SUM(quantity) as total_stock, SUM(price * quantity) as inventory_value FROM products GROUP BY category`;
        } else if (type === 'customer') {
            query = `SELECT u.name, u.email, u.currency, COUNT(s.id) as total_orders, COALESCE(SUM(s.total_amount), 0) as total_spent, COALESCE(SUM(s.due_amount), 0) as total_due FROM users u LEFT JOIN sales s ON u.id = s.customer_id WHERE u.role = 'CUSTOMER' GROUP BY u.id, u.name, u.email, u.currency ORDER BY total_spent DESC`;
        }
        const result = await db.query(query, params);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Failed to generate report' }); }
});

app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));