const express = require('express')
const sql = require("mysql2/promise")
const bcrypt = require("bcrypt")
const cors = require("cors")
const jwt = require('jsonwebtoken')

// ✅ USE ENVIRONMENT PORT (Render provides this)
const port = process.env.PORT || 5000

require('dotenv').config()

const dbConfig ={
    host:process.env.DB_HOST,
    user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    database:process.env.DB_NAME,
    port:process.env.DB_PORT,
    waitForConnection:true,
    connectionLimit:100,
    queueLimit:0
}

const app = express()
app.use(express.json())
const secret = process.env.JWT

// ✅ CORS - ALLOW YOUR NETLIFY URL
app.use(cors({
    origin: [
        'http://localhost:3000',                       // Local development
        'https://educationreminder.netlify.app'        // Your Netlify URL
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}))

app.listen(port,()=>{
    console.log(`Server is running on port ${port}!`)
})

// Rest of your code (authenticator, routes, etc.) stays the same...