const express = require('express')
const createError = require('http-errors')
const morgan = require('morgan')
require('dotenv').config()
require('./helpers/init_mongodb')
// require('./helpers/init_redis')
const {verifyAccessToken } = require('./helpers/jwt_helper')


const AuthRoute = require('./Routes/Auth.route')

const app = express()
app.use(morgan('dev'))
app.use(express.json())
app.use(express.urlencoded({extended:true}))



app.get('/',verifyAccessToken ,async (req, res, next) => {
    res.send("Hello from express")
})

app.use('/auth',AuthRoute)


app.use(async (req, res, next) => {
    next(createError.NotFound("This route does not exist"))
})

app.use((err, req, res, next) => {
    res.status(err.status || 500) 
    res.send({
        error: {
            status: err.status || 500,
            message : err.message,
        }
    })
})

const PORT = process.env.PORT || 3000


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})