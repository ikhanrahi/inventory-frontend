const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 5000;

// ১. সকল অরিজিন সাপোর্ট করার জন্য CORS অপশন
app.use(cors({ origin: '*' }));
app.use(express.json());

// ডাটাবেজের বিকল্প মেমোরি
let inventory = [
    { id: 1, name: 'Laptop', quantity: 5, price: 1200 },
    { id: 2, name: 'Mouse', quantity: 20, price: 25 }
];

// Home Route
app.get('/', (req, res) => {
    res.send('Inventory API is running!');
});

// Route 1: Get all products
app.get('/api/products', (req, res) => {
    res.json(inventory);
});

// Route 2: Add product
app.post('/api/products', (req, res) => {
    const { name, quantity, price } = req.body;

    if (!name || !quantity || !price) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    const newProduct = {
        id: inventory.length + 1,
        name,
        quantity: Number(quantity),
        price: Number(price)
    };

    inventory.push(newProduct);
    res.status(201).json({ message: 'Product added successfully', product: newProduct });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});