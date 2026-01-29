const express = require('express')
const sql = require("mysql2/promise")
const bcrypt = require("bcrypt")
const cors = require("cors")
const jwt = require('jsonwebtoken')

// Use PORT from environment variable (Render provides this)
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

// ===== FIXED CORS CONFIGURATION =====
app.use(cors({
    origin: [
        'http://localhost:3000',                       // Local development
        'https://educationreminder.netlify.app'        // Your Netlify frontend
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}))

app.listen(port,()=>{
    console.log(`Server is running on port ${port}!`)
})

function authenticator(req,res,next){
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(' ')[1]

    if(!token){
       return  res.status(401).json("Authentication failed")
    }

    jwt.verify(token,secret,(err,decoded)=>{
        if(err){
         return   res.status(403).json("Authorization failed")
        }
        req.user = decoded
        next()

    })
}

app.get("/allactivities",authenticator,async(req,res)=>{

    const {userSchool} = req.user
    let connection
   

    try{
        connection = await sql.createConnection(dbConfig)
        const [rows] = await connection.execute('SELECT * FROM Information WHERE school=?',[userSchool])
        res.status(200).json(rows)
    }catch(error){
        console.error(error)
        res.status(500).json({message:"error retrieveing all activities."})
    }finally{
       connection ?   await connection.end() :''
    }
})

app.post("/add",authenticator,async(req,res)=>{
    let connection

    const {type,time,name,description} = req.body
    const {userId,userSchool} = req.user
    
    

    try{
        connection = await sql.createConnection(dbConfig)
        
        await connection.execute('INSERT INTO defaultdb.Information (time,name,createdBy_id,school,description,type) VALUES(?,?,?,?,?,?)',[time,name,userId,userSchool,description,type])
        res.status(201).json({message:"successfully created"})
    }catch(err){
        console.error(err)
        res.status(500).json({message:'Error creating new item'})
    }finally{
        if(connection) await connection.end()
    }
})

app.put("/edit/:id",authenticator,async(req,res)=>{
    let connection  
    const id = req.params.id
    const {time,name,description,type} = req.body
    try{
        connection = await sql.createConnection(dbConfig)
        await connection.execute('UPDATE  Information SET  time=?, name=?, description=?, type=? WHERE id=?',[time,name,description,type,id])
        res.status(200).json({message:'update success'})
    }catch(err){
        console.error(err)
        res.status(500).json({message:'Updating fail!'})
    }finally{
        connection ?   await connection.end() :''
    }
})

app.delete("/delete/:id",authenticator,async(req,res)=>{
    let connection  
    const id = req.params.id
    
    try{
        connection = await sql.createConnection(dbConfig)
        await connection.execute('DELETE FROM Information WHERE id=?',[id])
        res.status(200).json({message:'delete success'})
    }catch(err){
        console.error(err)
        res.status(500).json({message:'Deleting fail!'})
    }finally{
        connection ?   await connection.end() :''
    }
})




app.post("/register",async(req,res)=>{
    const {name,email,password,role,school} = req.body
    
    
    let connection 
    try{
        
        connection = await sql.createConnection(dbConfig)
        const [rows] =  await connection.execute('SELECT * FROM Registeration WHERE email=?',[email])
        if(rows.length>0){
            return res.status(409).json({message:'email already registered'})
        }

        const hashedPassword =await bcrypt.hash(password,10)
        
        await connection.execute('INSERT INTO Registeration (name,email,password,role,school) VALUES (?,?,?,?,?)',[name,email,hashedPassword,role,school])
        res.status(201).json('successfully registered')
    }catch(err){
        console.error(err)
        res.status(500).json({message:'error registeration'})
    }finally{
     connection ?   await connection.end() :''
    }
})

app.post("/login",async(req,res)=>{
    const {email,password} = req.body
    
    let connection
    try{
        connection = await sql.createConnection(dbConfig)
        const [rows] =await connection.execute('SELECT * from Registeration WHERE email =?' ,[email])
        
        if(rows.length<=0){
         return   res.status(404).json({message:'user not found'})
        }
        
        const valid = await bcrypt.compare(password,rows[0].password)

        if(!valid){
            return res.status(401).json({message:"invalid password"})
        }
        else{
            const token = jwt.sign(
                {userId : rows[0].id,userName:rows[0].name,userRole:rows[0].role,userSchool: rows[0].school},secret, {expiresIn:"1h"}
            )
            return res.json({token})
        }
        
    }catch(err){
        console.error(err)
        res.status(500).json({message:'Login fail'})
    }finally{
      connection ?  await connection.end() : ''
    }
})
