// server.js
const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')

const server = jsonServer.create()
const router = jsonServer.router('db.json')
const usersdb = JSON.parse(fs.readFileSync('./users.json').toString())

const middlewares = jsonServer.defaults()
server.use(middlewares)

server.use(bodyParser.urlencoded({extended:true}))
server.use(bodyParser.json())

const SECRET_KEY = "AURORACOWORKING"
const expiresIn = "30d"

const createToken = (payload) => {
    return jwt.sign(payload,SECRET_KEY,{expiresIn})
}

const verifyToken = (token) => {
    const out = jwt.verify(token, SECRET_KEY, (err,decode) => decode !== undefined ? decode : err )
    if(out.name==="JsonWebTokenError") throw(out)
    return out
}

const isAuthenticated = ({username,password}) => {
    return usersdb.users.findIndex(user => user.username === username && user.password === password ) !== -1
}

server.post('/auth/login', (req,res)=>{
    const {username, password} = req.body
    if(isAuthenticated({username,password})===false){
        const status = 401
        const message = 'incorrect username or password'
        res.status(status).json({status,message})
        return
    }
    const access_token = createToken({username,password})
    res.status(200).json({access_token})
})

server.use(/^(?!\/auth).*$/,(req,res,next)=>{
    if(req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer'){
        const status = 401
        const message = 'Error in authorization format'
        res.status(status).json({status,message})
        return
    }
    try{
        verifyToken((req.headers.authorization.split(' ')[1]))
        next()
    }catch(err){
        const status = 401
        const message = 'invalid token'
        res.status(status).json({status,message,err})
    }
})

server.use(router)

server.listen(3001, () => {
    console.log('JSON Server is running')
})

