import express from "express"
import sqlite3 from "sqlite3"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"

import cors from "cors"


const sqlite=sqlite3.verbose()

app.use(express.json())


const app = express()

app.use(cors(
{
origin: ["https://deploy-mern-1whq.vercel.app"],
methods: ["POST", "GET"],
credentials: true
}
));


const dbName="myLoginData.db"

let db

const initializeDB=()=>{
db=new sqlite.Database(dbName, async (err)=>{
    if(err){
        console.log(`database connection error ${err.message}`)
    }else{
        console.log("database is connected")
        const createTable=`CREATE TABLE IF NOT EXISTS Logindata (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, password TEXT)`
        db.run(createTable, async(err)=>{
            if(err){
                console.log(`create query error ${err.message}`)
            }else{
                console.log(`table created or existed`)
            }
        })
    }
})
}

initializeDB()


app.post("/adduser", async (request, response) => {
    const { name, password } = request.body;
    const hashedpassword=await bcrypt.hash(password, 15)
   

   const selectQuery=`SELECT * FROM Logindata WHERE name=?`
   db.get(selectQuery, [name], async(err, dbuser)=>{
    if(err){
        console.log(`select query error ${err.message}`)
    }
    if(!dbuser){
    const insertQuery=`INSERT INTO Logindata (name, password) VALUES(?, ?)`
    db.run(insertQuery, [name, hashedpassword], function(err){
        if(err){
            console.log(`inser query error ${err.message}`)
        }
            const lastId=`the user id :${this.lastID}`
            response.send(lastId)
        
        })
    }else{
        console.log("user already exists")
    }
   })
   })



   
   app.post("/login", async(req, res)=>{

    const {name, password}=req.body
    const selectQuery=`SELECT * FROM Logindata WHERE name=?`
    db.get(selectQuery, [name], async(err, dbuser)=>{
        if(err){
            console.log(`select query error:${err.message}`)
            res.send(err.message)
        }
        if(dbuser===undefined){
            res.status(400);
            res.send(`"Invalid user"`) 
        }
        else
        {
            const comparepassword=await bcrypt.compare(password, dbuser.password)
           
            if(comparepassword===true){
                const payload={
                    name:name
                }
                const jwtToken=  jwt.sign(payload, "my_secret_token")
                
                res.send({jwtToken})
               
            }else{
                res.status(400)
                res.send(`"Incorrect password"`)
               
            }
        }
    })
   })





   app.get("/", async(req, res)=>{
    db.all(`SELECT * FROM Logindata`, async (err, data)=>{
        if(err){
            console.log(`error at select ${err.message}`)
        }else{
            res.send(data)
        }
    })
   })

   app.get("/user/:id", async(req, res)=>{
    const userid=req.params.id
   
    const updateQuery=`SELECT * FROM Logindata WHERE id=?`
    db.all(updateQuery, [userid], async(err, data)=>{
        if(err){
            console.log(`delete query error ${err.message}`)
        }else{
            res.send(data)
        }
    })
   })


   app.put("/user/:id", async(req, res)=>{
    const userid=req.params.id
    const {name, password}=req.body
    const updateQuery=`UPDATE Logindata SET name=?, password=? WHERE id=?`
    db.run(updateQuery, [name, password, userid], (err)=>{
        if(err){
            console.log(`update query error ${err.message}`)
        }else{
            res.send("updated")
        }
    })
   })

   app.delete("/user/:id", async(req, res)=>{
    const userid=req.params.id
   
    const updateQuery=`DELETE FROM Logindata WHERE id=?`
    db.run(updateQuery, [userid], (err)=>{
        if(err){
            console.log(`delete query error ${err.message}`)
        }else{
            res.send("deleted")
        }
    })
   })




app.listen(1000, ()=>{
    console.log("server is started in 1000")
})