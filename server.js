const express = require('express');
const cors = require('cors');

const app = express();

// Render Dynamic Port ব্যবহার করে, তাই process.env.PORT দেওয়া বাধ্যতামূলক
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: '*' }));
app.use(express.json());

let inventory = [
    { id: 1, name: 'Laptop', quantity: 5, price: 1200 },
    { id: 2, name: 'Mouse', quantity: 20, price: 25 }
];

app.get('/', (req, res) => {
    res.send('Inventory API is running!');
});

app.get('/api/products', (req, res) => {
    res.json(inventory);
});

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

// 0.0.0.0 যোগ করা হয়েছে যাতে Render ব্যাকএন্ড সার্ভারকে চিনতে পারে
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});